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
pub struct ORCA_HostPort {
    pub host: *const c_char,
    pub port: u16,
}

#[repr(C)]
pub struct ORCA_StringList {
    pub strings: *mut *const c_char,
    pub count: usize,
}

#[repr(C)]
pub struct ORCA_KeyValue {
    pub key: *const c_char,
    pub value: *const c_char,
}

#[repr(C)]
pub struct ORCA_Evidence {
    pub items: *mut ORCA_KeyValue,
    pub count: usize,
}

#[repr(C)]
pub struct ORCA_Finding {
    pub id: *const c_char,
    pub plugin_id: *const c_char,
    pub success: bool,
    pub title: *const c_char,
    pub severity: *const c_char,
    pub description: *const c_char,
    pub evidence: ORCA_Evidence,
    pub tags: ORCA_StringList,
    pub timestamp: i64,
    pub target: ORCA_HostPort,
}

#[repr(C)]
pub struct ORCA_RunResult {
    pub target: ORCA_HostPort,
    pub findings: *mut ORCA_Finding,
    pub findings_count: usize,
    pub logs: ORCA_StringList,
}

/* ================================================================ */
/* ABI Version and Entry Points                                     */
/* ================================================================ */

#[no_mangle]
pub static ORCA_PLUGIN_ABI_VERSION: u32 = 2;

#[no_mangle]
pub extern "C" fn ORCA_Free(p: *mut c_void) {
    if p.is_null() {
        return;
    }
    unsafe {
        let result = Box::from_raw(p as *mut ORCA_RunResult);

        // Free strings and arrays within the main struct
        let _ = CString::from_raw(result.target.host as *mut c_char);

        // Free findings
        let findings = Vec::from_raw_parts(
            result.findings,
            result.findings_count,
            result.findings_count,
        );
        for f in findings {
            let _ = CString::from_raw(f.id as *mut c_char);
            let _ = CString::from_raw(f.plugin_id as *mut c_char);
            let _ = CString::from_raw(f.title as *mut c_char);
            let _ = CString::from_raw(f.severity as *mut c_char);
            let _ = CString::from_raw(f.description as *mut c_char);
            let _ = CString::from_raw(f.target.host as *mut c_char);

            // Free evidence
            let evidence =
                Vec::from_raw_parts(f.evidence.items, f.evidence.count, f.evidence.count);
            for kv in evidence {
                let _ = CString::from_raw(kv.key as *mut c_char);
                let _ = CString::from_raw(kv.value as *mut c_char);
            }

            // Free tags
            let tags = Vec::from_raw_parts(
                f.tags.strings as *mut *mut c_char,
                f.tags.count,
                f.tags.count,
            );
            for tag in tags {
                let _ = CString::from_raw(tag);
            }
        }

        // Free logs
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
pub extern "C" fn ORCA_Run(
    host: *const c_char,
    port: c_uint,
    _timeout_ms: c_uint,
    params_json: *const c_char,
    out_result: *mut *mut ORCA_RunResult,
) -> c_int {
    if host.is_null() || out_result.is_null() {
        return 1;
    }

    let ts = now_ts();
    let host_str = unsafe { CStr::from_ptr(host) }
        .to_string_lossy()
        .into_owned();
    let target = format!("{}:{}", host_str, port);

    // Default parameters
    let mut tls_insecure = true;
    let mut warn_days: i64 = 21;
    let mut min_rsa_bits: u32 = 2048;
    let mut allow_sha1 = false;
    let mut disallow_self_signed = true;

    // Parse JSON params if provided
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
            }
        }
    }

    let mut findings = Vec::new();
    let mut logs = vec![
        CString::new(format!("Connecting to {}", target)).unwrap(),
        CString::new(format!("tls_insecure={}", tls_insecure)).unwrap(),
    ];

    let mut builder = match SslConnector::builder(SslMethod::tls()) {
        Ok(b) => b,
        Err(e) => {
            return finish_with_error(
                &format!("SSL init failed: {}", e),
                host_str.as_str(),
                port,
                out_result,
            )
        }
    };

    if tls_insecure {
        builder.set_verify(SslVerifyMode::NONE);
    } else {
        builder.set_verify(SslVerifyMode::PEER);
    }
    let connector = builder.build();

    let stream = match TcpStream::connect(&target) {
        Ok(s) => s,
        Err(e) => {
            return finish_with_error(
                &format!("TCP connect failed: {}", e),
                host_str.as_str(),
                port,
                out_result,
            )
        }
    };

    let ssl_stream = match connector.connect(&host_str, stream) {
        Ok(s) => s,
        Err(e) => {
            return finish_with_error(
                &format!("TLS handshake failed: {}", e),
                host_str.as_str(),
                port,
                out_result,
            )
        }
    };

    let cert = match ssl_stream.ssl().peer_certificate() {
        Some(c) => c,
        None => {
            return finish_with_error(
                "No peer certificate found",
                host_str.as_str(),
                port,
                out_result,
            )
        }
    };

    // ========= Certificate Checks =========

    if let Some(days_left) = days_from_now(cert.not_after()) {
        if days_left < 0 {
            add_finding(
                &mut findings,
                "CERT-EXPIRED",
                "Certificate expired",
                "high",
                "Leaf certificate is expired",
                vec![("days_left", &days_left.to_string())],
                &["tls", "cert"],
                ts,
                &host_str,
                port as u16,
            );
        } else if days_left <= warn_days {
            add_finding(
                &mut findings,
                "CERT-EXPIRING",
                "Certificate expiring soon",
                "medium",
                "Leaf certificate expires soon",
                vec![("days_left", &days_left.to_string())],
                &["tls", "cert"],
                ts,
                &host_str,
                port as u16,
            );
        }
    }

    if disallow_self_signed && is_self_signed(&cert) {
        add_finding(
            &mut findings,
            "CERT-SELFSIGNED",
            "Self-signed certificate",
            "medium",
            "Certificate appears to be self-signed",
            vec![],
            &["tls", "cert"],
            ts,
            &host_str,
            port as u16,
        );
    }

    if !allow_sha1 && is_sigalg_sha1(&cert) {
        add_finding(
            &mut findings,
            "CERT-SHA1",
            "Weak signature algorithm (SHA-1)",
            "medium",
            "Certificate is signed with the insecure SHA-1 algorithm",
            vec![],
            &["tls", "cert"],
            ts,
            &host_str,
            port as u16,
        );
    }

    if let Ok(pk) = cert.public_key() {
        if pk.bits() < min_rsa_bits {
            add_finding(
                &mut findings,
                "CERT-WEAKKEY",
                "Weak public key",
                "medium",
                "Public key size is below the recommended threshold",
                vec![
                    ("bits", &pk.bits().to_string()),
                    ("minimum", &min_rsa_bits.to_string()),
                ],
                &["tls", "cert"],
                ts,
                &host_str,
                port as u16,
            );
        }
    }

    if !hostname_matches(&cert, &host_str) {
        add_finding(
            &mut findings,
            "CERT-HOSTNAME",
            "Hostname mismatch",
            "high",
            "Certificate is not valid for the target hostname",
            vec![("hostname", &host_str)],
            &["tls", "cert"],
            ts,
            &host_str,
            port as u16,
        );
    }

    logs.push(CString::new("Successfully analyzed peer certificate.").unwrap());

    // ======== Finalize and Return Struct ========
    let findings_count = findings.len();
    let logs_count = logs.len();

    let result = Box::new(ORCA_RunResult {
        target: ORCA_HostPort {
            host: CString::new(host_str).unwrap().into_raw(),
            port: port as u16,
        },
        findings: vec_to_raw_parts(findings),
        findings_count,
        logs: ORCA_StringList {
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

fn add_finding(
    findings: &mut Vec<ORCA_Finding>,
    id: &str,
    title: &str,
    severity: &str,
    description: &str,
    evidence_pairs: Vec<(&str, &str)>,
    tags_slice: &[&str],
    ts: i64,
    host: &str,
    port: u16,
) {
    let evidence_vec: Vec<ORCA_KeyValue> = evidence_pairs
        .into_iter()
        .map(|(k, v)| ORCA_KeyValue {
            key: CString::new(k).unwrap().into_raw(),
            value: CString::new(v).unwrap().into_raw(),
        })
        .collect();

    let tags_vec: Vec<*const c_char> = tags_slice
        .iter()
        .map(|t| CString::new(*t).unwrap().into_raw() as *const c_char)
        .collect();

    let evidence_count = evidence_vec.len();
    let tags_count = tags_vec.len();

    findings.push(ORCA_Finding {
        id: CString::new(id).unwrap().into_raw(),
        plugin_id: CString::new("cert_inspect_rust").unwrap().into_raw(),
        success: true,
        title: CString::new(title).unwrap().into_raw(),
        severity: CString::new(severity).unwrap().into_raw(),
        description: CString::new(description).unwrap().into_raw(),
        evidence: ORCA_Evidence {
            items: vec_to_raw_parts(evidence_vec),
            count: evidence_count,
        },
        tags: ORCA_StringList {
            strings: vec_to_raw_parts(tags_vec),
            count: tags_count,
        },
        timestamp: ts,
        target: ORCA_HostPort {
            host: CString::new(host).unwrap().into_raw(),
            port,
        },
    });
}

fn finish_with_error(
    msg: &str,
    host: &str,
    port: c_uint,
    out_result: *mut *mut ORCA_RunResult,
) -> c_int {
    let log = CString::new(msg).unwrap().into_raw() as *const c_char;
    let logs_vec = vec![log];
    let logs_count = logs_vec.len();

    let result = Box::new(ORCA_RunResult {
        target: ORCA_HostPort {
            host: CString::new(host).unwrap().into_raw(),
            port: port as u16,
        },
        findings: ptr::null_mut(),
        findings_count: 0,
        logs: ORCA_StringList {
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

// Certificate analysis helpers (unchanged from original logic)
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
    nid == Nid::SHA1WITHRSAENCRYPTION || nid == Nid::DSAWITHSHA1 || nid == Nid::ECDSA_WITH_SHA1
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
