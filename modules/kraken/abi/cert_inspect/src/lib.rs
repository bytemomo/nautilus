use openssl::asn1::Asn1TimeRef;
use openssl::nid::Nid;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use openssl::x509::X509;
use serde_json::Value;
use std::ffi::{c_void, CStr, CString};
use std::mem;
use std::net::TcpStream;
use std::os::raw::{c_char, c_int, c_uint};
use std::ptr;
use std::time::{SystemTime, UNIX_EPOCH};

/* ================================================================ */
/* C ABI Structures Replicated in Rust                              */
/* ================================================================ */
#[repr(C)]
pub struct KrakenHostPort {
    pub host: *const c_char,
    pub port: u16,
}

#[repr(C)]
pub struct KrakenStringList {
    pub strings: *mut *const c_char,
    pub count: usize,
}

#[repr(C)]
pub struct KrakenKeyValue {
    pub key: *const c_char,
    pub value: *const c_char,
}

#[repr(C)]
pub struct KrakenEvidence {
    pub items: *mut KrakenKeyValue,
    pub count: usize,
}

#[repr(C)]
pub struct KrakenFinding {
    pub id: *const c_char,
    pub module_id: *const c_char,
    pub success: bool,
    pub title: *const c_char,
    pub severity: *const c_char,
    pub description: *const c_char,
    pub evidence: KrakenEvidence,
    pub tags: KrakenStringList,
    pub timestamp: i64,
    pub target: KrakenHostPort,
}

#[repr(C)]
pub struct KrakenRunResult {
    pub target: KrakenHostPort,
    pub findings: *mut KrakenFinding,
    pub findings_count: usize,
    pub logs: KrakenStringList,
}

/* ================================================================ */
/* ABI Version and Entry Points                                     */
/* ================================================================ */

#[no_mangle]
pub static KRAKEN_MODULE_ABI_VERSION: u32 = 1;

#[no_mangle]
pub extern "C" fn kraken_free(p: *mut c_void) {
    if p.is_null() {
        return;
    }
    unsafe {
        let result = Box::from_raw(p as *mut KrakenRunResult);
        let _ = CString::from_raw(result.target.host as *mut c_char);

        let findings = Vec::from_raw_parts(
            result.findings,
            result.findings_count,
            result.findings_count,
        );
        for f in findings {
            let _ = CString::from_raw(f.id as *mut c_char);
            let _ = CString::from_raw(f.module_id as *mut c_char);
            let _ = CString::from_raw(f.title as *mut c_char);
            let _ = CString::from_raw(f.severity as *mut c_char);
            let _ = CString::from_raw(f.description as *mut c_char);
            let _ = CString::from_raw(f.target.host as *mut c_char);

            let evidence =
                Vec::from_raw_parts(f.evidence.items, f.evidence.count, f.evidence.count);
            for kv in evidence {
                let _ = CString::from_raw(kv.key as *mut c_char);
                let _ = CString::from_raw(kv.value as *mut c_char);
            }

            let tags = Vec::from_raw_parts(
                f.tags.strings as *mut *mut c_char,
                f.tags.count,
                f.tags.count,
            );
            for tag in tags {
                let _ = CString::from_raw(tag);
            }
        }

        let logs = Vec::from_raw_parts(
            result.logs.strings as *mut *mut c_char,
            result.logs.count,
            result.logs.count,
        );
        for log in logs {
            let _ = CString::from_raw(log);
        }
    }
}

#[no_mangle]
pub extern "C" fn kraken_run(
    host: *const c_char,
    port: c_uint,
    _timeout_ms: c_uint,
    params_json: *const c_char,
    out_result: *mut *mut KrakenRunResult,
) -> c_int {
    if host.is_null() || out_result.is_null() {
        return 1;
    }

    let ts = now_ts();
    let host_str = unsafe { CStr::from_ptr(host) }
        .to_string_lossy()
        .into_owned();
    let target = format!("{}:{}", host_str, port);

    // Define all parameters with their defaults
    let mut tls_insecure = true;
    let mut warn_days: i64 = 21;
    let mut min_rsa_bits: u32 = 2048;
    let mut allow_sha1 = false;
    let mut disallow_self_signed = true;
    let mut match_hostname = true;
    let mut require_san = true;
    let mut require_server_auth = false;

    // Parse all parameters from the provided JSON string
    if !params_json.is_null() {
        if let Ok(pj) = unsafe { CStr::from_ptr(params_json) }.to_str() {
            if let Ok(v) = serde_json::from_str::<Value>(pj) {
                tls_insecure = v
                    .get("tls_insecure")
                    .and_then(|x| x.as_bool())
                    .unwrap_or(tls_insecure);
                warn_days = v
                    .get("warn_days")
                    .and_then(|x| x.as_i64())
                    .unwrap_or(warn_days);
                min_rsa_bits = v
                    .get("min_rsa_bits")
                    .and_then(|x| x.as_u64())
                    .unwrap_or(min_rsa_bits as u64) as u32;
                allow_sha1 = v
                    .get("allow_sha1")
                    .and_then(|x| x.as_bool())
                    .unwrap_or(allow_sha1);
                disallow_self_signed = v
                    .get("disallow_self_signed")
                    .and_then(|x| x.as_bool())
                    .unwrap_or(disallow_self_signed);
                match_hostname = v
                    .get("match_hostname")
                    .and_then(|x| x.as_bool())
                    .unwrap_or(match_hostname);
                require_san = v
                    .get("require_san")
                    .and_then(|x| x.as_bool())
                    .unwrap_or(require_san);
                require_server_auth = v
                    .get("require_server_auth")
                    .and_then(|x| x.as_bool())
                    .unwrap_or(require_server_auth);
            }
        }
    }

    let mut findings = Vec::new();
    let mut logs = vec![CString::new(format!("Cert inspect started for {}", target)).unwrap()];

    // Connect and retrieve the certificate
    let cert = match connect_and_get_cert(&target, &host_str, tls_insecure) {
        Ok(c) => c,
        Err(e) => return finish_with_error(&e, &host_str, port, out_result),
    };
    logs.push(CString::new("Successfully retrieved peer certificate.").unwrap());

    // --- Execute All Certificate Checks ---

    if let Some(days_left) = days_from_now(cert.not_after()) {
        if days_left < 0 {
            add_finding(
                &mut findings,
                "CERT-EXPIRED",
                "Certificate expired",
                "high",
                "The certificate's 'notAfter' date is in the past.",
                vec![("days_expired", &(-days_left).to_string())],
                ts,
                &host_str,
                port,
            );
        } else if days_left <= warn_days {
            add_finding(
                &mut findings,
                "CERT-EXPIRING",
                "Certificate expiring soon",
                "medium",
                "The certificate will expire in the configured warning period.",
                vec![("days_left", &days_left.to_string())],
                ts,
                &host_str,
                port,
            );
        }
    }

    if disallow_self_signed && is_self_signed(&cert) {
        add_finding(
            &mut findings,
            "CERT-SELFSIGNED",
            "Self-signed certificate",
            "medium",
            "The certificate's issuer is the same as its subject, indicating it is self-signed.",
            vec![],
            ts,
            &host_str,
            port,
        );
    }

    if !allow_sha1 && is_sigalg_sha1(&cert) {
        add_finding(
            &mut findings,
            "CERT-SHA1",
            "Weak signature algorithm (SHA-1)",
            "medium",
            "The certificate is signed with the deprecated SHA-1 algorithm.",
            vec![],
            ts,
            &host_str,
            port,
        );
    }

    if let Ok(pk) = cert.public_key() {
        if pk.bits() < min_rsa_bits {
            add_finding(
                &mut findings,
                "CERT-WEAKKEY",
                "Weak public key",
                "medium",
                "The public key size is below the configured threshold.",
                vec![
                    ("bits", &pk.bits().to_string()),
                    ("minimum", &min_rsa_bits.to_string()),
                ],
                ts,
                &host_str,
                port,
            );
        }
    }

    if match_hostname && !hostname_matches(&cert, &host_str) {
        add_finding(&mut findings, "CERT-HOSTNAME", "Hostname mismatch", "high", "The certificate's Common Name or Subject Alternative Names do not match the target host.", vec![("target_host", &host_str)], ts, &host_str, port);
    }

    if require_san && cert.subject_alt_names().is_none() {
        add_finding(&mut findings, "CERT-NOSAN", "Missing Subject Alternative Name", "medium", "The certificate lacks a SAN extension, which is required by modern browsers and clients.", vec![], ts, &host_str, port);
    }

    if require_server_auth {
        println!("[ERROR] cert_inspect module: require_server_auth flag not yet supported!");
    }

    // --- Finalize and Return Result Struct ---
    let findings_count = findings.len();
    let logs_count = logs.len();
    let result = Box::new(KrakenRunResult {
        target: KrakenHostPort {
            host: CString::new(host_str).unwrap().into_raw(),
            port: port as u16,
        },
        findings: vec_to_raw_parts(findings),
        findings_count,
        logs: KrakenStringList {
            strings: vec_to_raw_parts(
                logs.into_iter()
                    .map(|s| s.into_raw() as *const c_char)
                    .collect(),
            ),
            count: logs_count,
        },
    });

    unsafe {
        *out_result = Box::into_raw(result);
    }
    0
}

/* ================================================================ */
/* Helper Functions                                                 */
/* ================================================================ */

fn connect_and_get_cert(target: &str, host: &str, tls_insecure: bool) -> Result<X509, String> {
    let mut builder =
        SslConnector::builder(SslMethod::tls()).map_err(|e| format!("SSL init failed: {}", e))?;
    if tls_insecure {
        builder.set_verify(SslVerifyMode::NONE);
    }
    let connector = builder.build();
    let stream = TcpStream::connect(target).map_err(|e| format!("TCP connect failed: {}", e))?;
    let ssl_stream = connector
        .connect(host, stream)
        .map_err(|e| format!("TLS handshake failed: {}", e))?;
    ssl_stream
        .ssl()
        .peer_certificate()
        .ok_or_else(|| "No peer certificate found".to_string())
}

fn add_finding(
    findings: &mut Vec<KrakenFinding>,
    id: &str,
    title: &str,
    severity: &str,
    description: &str,
    evidence_pairs: Vec<(&str, &str)>,
    ts: i64,
    host: &str,
    port: c_uint,
) {
    let evidence_vec: Vec<KrakenKeyValue> = evidence_pairs
        .into_iter()
        .map(|(k, v)| KrakenKeyValue {
            key: CString::new(k).unwrap().into_raw(),
            value: CString::new(v).unwrap().into_raw(),
        })
        .collect();
    let tags_vec: Vec<*const c_char> = vec!["tls", "cert"]
        .iter()
        .map(|t| CString::new(*t).unwrap().into_raw() as *const c_char)
        .collect();
    let evidence_count = evidence_vec.len();
    let tags_count = tags_vec.len();

    findings.push(KrakenFinding {
        id: CString::new(id).unwrap().into_raw(),
        module_id: CString::new("cert_inspect_rust").unwrap().into_raw(),
        success: true,
        title: CString::new(title).unwrap().into_raw(),
        severity: CString::new(severity).unwrap().into_raw(),
        description: CString::new(description).unwrap().into_raw(),
        evidence: KrakenEvidence {
            items: vec_to_raw_parts(evidence_vec),
            count: evidence_count,
        },
        tags: KrakenStringList {
            strings: vec_to_raw_parts(tags_vec),
            count: tags_count,
        },
        timestamp: ts,
        target: KrakenHostPort {
            host: CString::new(host).unwrap().into_raw(),
            port: port as u16,
        },
    });
}

fn finish_with_error(
    msg: &str,
    host: &str,
    port: c_uint,
    out_result: *mut *mut KrakenRunResult,
) -> c_int {
    let logs_vec = vec![CString::new(msg).unwrap().into_raw() as *const c_char];
    let logs_count = logs_vec.len();
    let result = Box::new(KrakenRunResult {
        target: KrakenHostPort {
            host: CString::new(host).unwrap().into_raw(),
            port: port as u16,
        },
        findings: ptr::null_mut(),
        findings_count: 0,
        logs: KrakenStringList {
            strings: vec_to_raw_parts(logs_vec),
            count: logs_count,
        },
    });
    unsafe {
        *out_result = Box::into_raw(result);
    }
    0
}

fn vec_to_raw_parts<T>(mut v: Vec<T>) -> *mut T {
    let ptr = v.as_mut_ptr();
    mem::forget(v);
    ptr
}

fn now_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn days_from_now(t: &Asn1TimeRef) -> Option<i64> {
    let now = openssl::asn1::Asn1Time::days_from_now(0).ok()?;
    t.diff(&now).ok().map(|d| d.days as i64)
}

fn is_self_signed(cert: &X509) -> bool {
    cert.verify(&cert.public_key().unwrap()).unwrap_or(false)
}

fn is_sigalg_sha1(cert: &X509) -> bool {
    let nid = cert.signature_algorithm().object().nid();
    nid == Nid::SHA1WITHRSAENCRYPTION || nid == Nid::DSAWITHSHA1
}
fn hostname_matches(cert: &X509, host: &str) -> bool {
    if let Some(sans) = cert.subject_alt_names() {
        for san in sans {
            if let Some(dns) = san.dnsname() {
                if dns.eq_ignore_ascii_case(host) {
                    return true;
                }
            }
        }
    }
    if let Some(cn) = cert.subject_name().entries_by_nid(Nid::COMMONNAME).next() {
        if cn.data().as_slice().eq_ignore_ascii_case(host.as_bytes()) {
            return true;
        }
    }
    false
}
