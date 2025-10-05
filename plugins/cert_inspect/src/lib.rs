use openssl::asn1::Asn1TimeRef;
use openssl::nid::Nid;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use openssl::x509::X509;
use serde::Serialize;
use serde_json::{json, Value};
use std::ffi::{CStr, CString};
use std::net::TcpStream;
use std::os::raw::{c_char, c_int, c_uint, c_void};
use std::ptr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[no_mangle]
pub static ORCA_PLUGIN_ABI_VERSION: u32 = 1;

#[derive(Serialize)]
struct Finding {
    id: String,
    plugin_id: String,
    title: String,
    severity: String,
    description: String,
    evidence: Value,
    tags: Vec<String>,
    timestamp: i64,
}

#[derive(Serialize)]
struct Log {
    ts: i64,
    line: String,
}

#[derive(Serialize)]
struct RunResult {
    findings: Vec<Finding>,
    logs: Vec<Log>,
}

#[no_mangle]
pub extern "C" fn ORCA_Free(p: *mut c_void) {
    if !p.is_null() {
        unsafe { libc::free(p) };
    }
}

#[no_mangle]
pub extern "C" fn ORCA_Run(
    host: *const c_char,
    port: c_uint,
    timeout_ms: c_uint,
    params_json: *const c_char,
    out_json: *mut *mut c_char,
    out_len: *mut usize,
) -> c_int {
    if host.is_null() || out_json.is_null() || out_len.is_null() {
        return 1;
    }

    let ts = now_ts();
    let host_str = unsafe { CStr::from_ptr(host) }
        .to_string_lossy()
        .into_owned();
    let target = format!("{}:{}", host_str, port);
    let timeout = Duration::from_millis(timeout_ms as u64);

    // ---- defaults (the params you asked to support)
    let mut tls_insecure: bool = true;
    let mut warn_days: i64 = 21;
    let mut min_rsa_bits: u32 = 2048;
    let mut allow_sha1: bool = false;
    let mut disallow_self_signed: bool = true;

    // Parse JSON params (all optional)
    if !params_json.is_null() {
        if let Ok(pj) = unsafe { CStr::from_ptr(params_json) }.to_str() {
            if let Ok(v) = serde_json::from_str::<Value>(pj) {
                if let Some(b) = v.get("tls_insecure").and_then(|x| x.as_bool()) {
                    tls_insecure = b;
                }
                if let Some(n) = v.get("warn_days").and_then(|x| x.as_i64()) {
                    warn_days = n;
                }
                if let Some(n) = v.get("min_rsa_bits").and_then(|x| x.as_u64()) {
                    min_rsa_bits = n as u32;
                }
                if let Some(b) = v.get("allow_sha1").and_then(|x| x.as_bool()) {
                    allow_sha1 = b;
                }
                if let Some(b) = v.get("disallow_self_signed").and_then(|x| x.as_bool()) {
                    disallow_self_signed = b;
                }
            }
        }
    }

    let mut findings = Vec::new();
    let mut logs = vec![
        Log {
            ts,
            line: format!("Connecting to {}", target),
        },
        Log {
            ts,
            line: format!("tls_insecure={}", tls_insecure),
        },
    ];

    // ---- TLS connector
    let mut builder = match SslConnector::builder(SslMethod::tls()) {
        Ok(b) => b,
        Err(e) => {
            return finish_with_log(&format!("SSL init failed: {}", e), ts, out_json, out_len)
        }
    };

    if tls_insecure {
        builder.set_verify(SslVerifyMode::NONE);
    } else {
        builder.set_verify(SslVerifyMode::PEER);
        let _ = builder.set_default_verify_paths();
    }
    let connector = builder.build();

    let stream = match TcpStream::connect(&target) {
        Ok(s) => s,
        Err(e) => {
            return finish_with_log(&format!("TCP connect failed: {}", e), ts, out_json, out_len)
        }
    };
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let mut cfg = match connector.configure() {
        Ok(c) => c,
        Err(e) => {
            return finish_with_log(
                &format!("SSL configure failed: {}", e),
                ts,
                out_json,
                out_len,
            )
        }
    };
    cfg.set_use_server_name_indication(true);
    // We do our own hostname checks below; don't let OpenSSL fail the handshake on hostname
    cfg.set_verify_hostname(false);

    let ssl_stream = match cfg.connect(&host_str, stream) {
        Ok(s) => s,
        Err(e) => {
            return finish_with_log(
                &format!("TLS handshake failed: {}", e),
                ts,
                out_json,
                out_len,
            )
        }
    };

    let cert = match ssl_stream.ssl().peer_certificate() {
        Some(c) => c,
        None => return finish_with_log("No peer certificate", ts, out_json, out_len),
    };

    // ========= Checks =========

    // Expiry
    if let Some(days_left) = days_from_now(cert.not_after()) {
        if days_left < 0 {
            // stringify evidence values
            add_finding(
                &mut findings,
                "CERT-EXPIRED",
                "Certificate expired",
                "high",
                "Leaf certificate is expired",
                json!({ "days_left": format!("{}", days_left) }),
                &["tls:cert"],
                ts,
            );
        } else if days_left <= warn_days {
            add_finding(
                &mut findings,
                "CERT-EXPIRING",
                "Certificate expiring soon",
                "medium",
                "Leaf certificate expires soon",
                json!({ "days_left": format!("{}", days_left) }),
                &["tls:cert"],
                ts,
            );
        }
    }

    // NotBefore (future validity)
    if let Some(nb_days) = diff_days(cert.not_before()) {
        if nb_days > 0 {
            add_finding(
                &mut findings,
                "CERT-NOTYETVALID",
                "Certificate not yet valid",
                "high",
                "Leaf certificate NotBefore is in the future",
                json!({ "days_to_valid": format!("{}", nb_days) }),
                &["tls:cert"],
                ts,
            );
        }
    }

    // Self-signed check: verify with its own public key
    if disallow_self_signed && is_self_signed(&cert) {
        add_finding(
            &mut findings,
            "CERT-SELFSIGNED",
            "Self-signed certificate",
            "medium",
            "Certificate appears self-signed",
            json!({}),
            &["tls:cert"],
            ts,
        );
    }

    // SHA-1 signature
    if !allow_sha1 && is_sigalg_sha1(&cert) {
        add_finding(
            &mut findings,
            "CERT-SHA1",
            "Weak signature algorithm (SHA-1)",
            "medium",
            "Certificate is signed with SHA-1",
            json!({}),
            &["tls:cert"],
            ts,
        );
    }

    // Key strength (RSA threshold)
    if let Ok(pk) = cert.public_key() {
        let bits_u32 = pk.bits() as u32; // pk.bits() is usize
        if bits_u32 < min_rsa_bits {
            add_finding(
                &mut findings,
                "CERT-WEAKKEY",
                "Weak public key",
                "medium",
                "Public key type/size is weak",
                json!({ "bits": format!("{}", bits_u32), "min_rsa_bits": format!("{}", min_rsa_bits) }),
                &["tls:cert"],
                ts,
            );
        }
    }

    // SAN presence and basic hostname match (optional; no params exposed here)
    let san_dns = subject_alt_dns(&cert);
    if san_dns.is_empty() {
        add_finding(
            &mut findings,
            "CERT-NOSAN",
            "No Subject Alternative Name",
            "medium",
            "Certificate lacks SAN DNS entries",
            json!({}),
            &["tls:cert"],
            ts,
        );
    }
    if !hostname_matches(&cert, &host_str, &san_dns) {
        add_finding(
            &mut findings,
            "CERT-HOSTNAME",
            "Hostname mismatch",
            "high",
            "Certificate does not match target hostname",
            json!({ "host": host_str.clone() }),
            &["tls:cert"],
            ts,
        );
    }

    logs.push(Log {
        ts,
        line: format!("Checked TLS certificate (SANs: {})", san_dns.join(",")),
    });

    // ---- Serialize
    let result = RunResult { findings, logs };
    let json_str = match serde_json::to_string(&result) {
        Ok(s) => s,
        Err(_) => return 2,
    };

    unsafe {
        let c_str = match CString::new(json_str) {
            Ok(s) => s,
            Err(_) => return 3,
        };
        let len = c_str.as_bytes().len();
        let buf = libc::malloc(len + 1) as *mut c_char;
        if buf.is_null() {
            return 3;
        }
        ptr::copy_nonoverlapping(c_str.as_ptr(), buf, len + 1);
        *out_json = buf;
        *out_len = len;
    }
    0
}

/* ================= Helpers ================= */

fn now_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

// Convert OpenSSL time difference to i64 days
fn days_from_now(t: &Asn1TimeRef) -> Option<i64> {
    let now = openssl::asn1::Asn1Time::days_from_now(0).ok()?;
    t.diff(&now).ok().map(|d| d.days as i64)
}

fn diff_days(t: &Asn1TimeRef) -> Option<i64> {
    let now = openssl::asn1::Asn1Time::days_from_now(0).ok()?;
    t.diff(&now).ok().map(|d| d.days as i64)
}

fn is_self_signed(cert: &X509) -> bool {
    if let Ok(pub_key) = cert.public_key() {
        cert.verify(&pub_key).unwrap_or(false)
    } else {
        false
    }
}

fn is_sigalg_sha1(cert: &X509) -> bool {
    let nid = cert.signature_algorithm().object().nid();
    nid == Nid::SHA1WITHRSAENCRYPTION || nid == Nid::DSAWITHSHA1 || nid == Nid::ECDSA_WITH_SHA1
}

fn subject_alt_dns(cert: &X509) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(stack) = cert.subject_alt_names() {
        for gn in stack {
            if let Some(d) = gn.dnsname() {
                out.push(d.to_string());
            }
        }
    }
    out
}

fn subject_cn(cert: &X509) -> Option<String> {
    let subj = cert.subject_name();
    let mut last_cn: Option<String> = None;
    for e in subj.entries() {
        if e.object().nid() == Nid::COMMONNAME {
            if let Ok(utf8) = e.data().as_utf8() {
                last_cn = Some(utf8.to_string());
            }
        }
    }
    last_cn
}

fn hostname_matches(cert: &X509, host: &str, sans: &[String]) -> bool {
    if sans.iter().any(|d| d.eq_ignore_ascii_case(host)) {
        return true;
    }
    if let Some(cn) = subject_cn(cert) {
        if cn.eq_ignore_ascii_case(host) {
            return true;
        }
    }
    false
}

fn add_finding(
    findings: &mut Vec<Finding>,
    id: &str,
    title: &str,
    severity: &str,
    description: &str,
    evidence: Value,
    tags: &[&str],
    ts: i64,
) {
    findings.push(Finding {
        id: id.into(),
        plugin_id: "cert_inspect".into(),
        title: title.into(),
        severity: severity.into(),
        description: description.into(),
        evidence,
        tags: tags.iter().map(|s| s.to_string()).collect(),
        timestamp: ts,
    });
}

fn finish_with_log(msg: &str, ts: i64, out_json: *mut *mut c_char, out_len: *mut usize) -> c_int {
    let obj = json!({
        "findings": [],
        "logs": [ { "ts": ts, "line": msg } ]
    });
    let s = match serde_json::to_string(&obj) {
        Ok(x) => x,
        Err(_) => return 3,
    };
    unsafe {
        let cs = match CString::new(s) {
            Ok(x) => x,
            Err(_) => return 3,
        };
        let len = cs.as_bytes().len();
        let buf = libc::malloc(len + 1) as *mut c_char;
        if buf.is_null() {
            return 3;
        }
        ptr::copy_nonoverlapping(cs.as_ptr(), buf, len + 1);
        *out_json = buf;
        *out_len = len;
    }
    0
}
