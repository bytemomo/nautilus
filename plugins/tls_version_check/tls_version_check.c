#ifdef __cplusplus
extern "C" {
#endif
__declspec(dllexport) int ORCA_Run(const char *host, unsigned int port,
                                   unsigned int timeout_ms, char **out_json,
                                   size_t *out_len);
__declspec(dllexport) void ORCA_Free(void *p);
#ifdef __cplusplus
}
#endif

// ----- Implementation (C or C++) -----
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#endif

#include <openssl/err.h>
#include <openssl/ssl.h>

static char *dup_json(const char *s) {
  size_t n = strlen(s);
  char *p = (char *)malloc(n + 1);
  if (p)
    memcpy(p, s, n + 1);
  return p;
}

static int try_tls_version(const char *host, unsigned short port, int version,
                           unsigned int timeout_ms) {
  char portstr[16];
  snprintf(portstr, sizeof(portstr), "%hu", port);

  SSL_CTX *ctx = SSL_CTX_new(TLS_method());
  if (!ctx)
    return 0;

  SSL_CTX_set_min_proto_version(ctx, version);
  SSL_CTX_set_max_proto_version(ctx, version);

  BIO *bio = BIO_new_ssl_connect(ctx);
  if (!bio) {
    SSL_CTX_free(ctx);
    return 0;
  }

  char target[256];
  snprintf(target, sizeof(target), "%s:%s", host, portstr);
  BIO_set_conn_hostname(bio, target);

  SSL *ssl = NULL;
  BIO_get_ssl(bio, &ssl);
  if (ssl) {
    // SNI: only if host looks like a hostname (not strict; OpenSSL accepts it)
    SSL_set_tlsext_host_name(ssl, host);
  }

  // Optional TCP connect timeout (OpenSSL BIO has knobs, but simplest is to set
  // socket opts).
#ifdef _WIN32
  // Let’s rely on OS defaults; keep code simple/cross-OpenSSL.
  (void)timeout_ms;
#endif

  int ok = (BIO_do_connect(bio) == 1) && (SSL_do_handshake(ssl) == 1);

  BIO_free_all(bio);
  SSL_CTX_free(ctx);
  return ok;
}

// --- Exported ABI ---
__declspec(dllexport) int ORCA_Run(const char *host, unsigned int port,
                                   unsigned int timeout_ms, char **out_json,
                                   size_t *out_len) {
#ifdef _WIN32
  // Ensure winsock is initialized (safe if already done).
  WSADATA wsa;
  WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

  (void)timeout_ms; // keep simple; handshake is typically quick

  // Ensure OpenSSL is initialized (OpenSSL 1.1+ auto-inits, but harmless):
  SSL_library_init();
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();

  int vers[4] = {TLS1_VERSION, TLS1_1_VERSION, TLS1_2_VERSION, TLS1_3_VERSION};
  int ok[4] = {0, 0, 0, 0};

  for (int i = 0; i < 4; i++) {
    ok[i] = try_tls_version(host, (unsigned short)port, vers[i], timeout_ms);
  }

  time_t now = time(NULL);
  char buf[2048];

  // Emit a single finding + logs (compact and ORCA-friendly)
  // evidence fields advertise which versions were OK.
  // You can expand this later with ciphers, ALPN, etc.
  int n = snprintf(
      buf, sizeof(buf),
      "{"
      "\"findings\":[{"
      "\"id\":\"TLS-VERSIONS\","
      "\"plugin_id\":\"tls_version_check\","
      "\"title\":\"TLS versions supported\","
      "\"severity\":\"info\","
      "\"description\":\"Versions the server accepted.\","
      "\"evidence\":{"
      "\"host\":\"%s\",\"port\":\"%u\","
      "\"tls10\":\"%s\",\"tls11\":\"%s\",\"tls12\":\"%s\",\"tls13\":\"%s\""
      "},"
      "\"tags\":[\"supports:tls\"],"
      "\"timestamp\":%lld"
      "}],"
      "\"logs\":["
      "{\"ts\":%lld,\"line\":\"TLS 1.0 %s\"},"
      "{\"ts\":%lld,\"line\":\"TLS 1.1 %s\"},"
      "{\"ts\":%lld,\"line\":\"TLS 1.2 %s\"},"
      "{\"ts\":%lld,\"line\":\"TLS 1.3 %s\"}"
      "]"
      "}",
      host, port, ok[0] ? "ok" : "fail", ok[1] ? "ok" : "fail",
      ok[2] ? "ok" : "fail", ok[3] ? "ok" : "fail", (long long)now,
      (long long)now, ok[0] ? "ok" : "fail", (long long)now,
      ok[1] ? "ok" : "fail", (long long)now, ok[2] ? "ok" : "fail",
      (long long)now, ok[3] ? "ok" : "fail");
  if (n <= 0)
    return 1;

  char *json = dup_json(buf);
  if (!json)
    return 2;
  *out_json = json;
  *out_len = strlen(json);

#ifdef _WIN32
  WSACleanup();
#endif
  return 0;
}

__declspec(dllexport) void ORCA_Free(void *p) {
  if (p)
    free(p);
}
