// ----- Public ABI -----
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ORCA_API: visibility/export across compilers
#if defined(_WIN32)
  #if defined(BUILDING_TLS_VERSION_CHECK)
    #define ORCA_API __declspec(dllexport)
  #else
    #define ORCA_API __declspec(dllimport)
  #endif
#elif defined(__GNUC__) && __GNUC__ >= 4
  #define ORCA_API __attribute__((visibility("default")))
#else
  #define ORCA_API
#endif

ORCA_API int ORCA_Run(const char *host, unsigned int port,
                      unsigned int timeout_ms, char **out_json,
                      size_t *out_len);
ORCA_API void ORCA_Free(void *p);

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

#include <openssl/ssl.h>
#include <openssl/err.h>

// Some environments may lack TLS1_3_VERSION; make it optional
#ifndef TLS1_VERSION
  #define TLS1_VERSION 0
#endif
#ifndef TLS1_1_VERSION
  #define TLS1_1_VERSION 0
#endif
#ifndef TLS1_2_VERSION
  #define TLS1_2_VERSION 0
#endif
#ifndef TLS1_3_VERSION
  #define TLS1_3_VERSION 0
#endif

static char *dup_json(const char *s) {
  size_t n = strlen(s);
  char *p = (char *)malloc(n + 1);
  if (p) memcpy(p, s, n + 1);
  return p;
}

static int try_tls_version(const char *host, unsigned short port, int version,
                           unsigned int timeout_ms) {
  if (version == 0) return -1; // “not available” on this OpenSSL

  char portstr[16];
  snprintf(portstr, sizeof(portstr), "%hu", port);

  SSL_CTX *ctx = SSL_CTX_new(TLS_method());
  if (!ctx) return 0;

  // lock min/max to a single protocol
  SSL_CTX_set_min_proto_version(ctx, (uint16_t)version);
  SSL_CTX_set_max_proto_version(ctx, (uint16_t)version);

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
    // SNI (harmless if host is an IP)
    SSL_set_tlsext_host_name(ssl, host);
  }

  (void)timeout_ms; // left as future work if you want a strict connect timeout

  int ok = (BIO_do_connect(bio) == 1) && ssl && (SSL_do_handshake(ssl) == 1);

  BIO_free_all(bio);
  SSL_CTX_free(ctx);
  return ok ? 1 : 0;
}

static const char *status_str(int v) {
  return v < 0 ? "n/a" : (v ? "ok" : "fail");
}

// --- Exported ABI ---
ORCA_API int ORCA_Run(const char *host, unsigned int port,
                      unsigned int timeout_ms, char **out_json,
                      size_t *out_len) {
#ifdef _WIN32
  WSADATA wsa;
  WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

  (void)timeout_ms;

  // OpenSSL 1.1.0+ auto-initializes; older versions use legacy init safely.
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  SSL_library_init();
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();
#endif

  const int vers[4] = { TLS1_VERSION, TLS1_1_VERSION, TLS1_2_VERSION, TLS1_3_VERSION };
  int ok[4];

  for (int i = 0; i < 4; ++i) {
    ok[i] = try_tls_version(host, (unsigned short)port, vers[i], timeout_ms);
  }

  time_t now = time(NULL);
  char buf[2048];

  // Emit compact JSON, marking “n/a” where a protocol macro wasn’t available
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
      host, port,
      status_str(ok[0]), status_str(ok[1]), status_str(ok[2]), status_str(ok[3]),
      (long long)now,
      (long long)now, status_str(ok[0]),
      (long long)now, status_str(ok[1]),
      (long long)now, status_str(ok[2]),
      (long long)now, status_str(ok[3]));
  if (n <= 0) {
#ifdef _WIN32
    WSACleanup();
#endif
    return 1;
  }

  char *json = dup_json(buf);
  if (!json) {
#ifdef _WIN32
    WSACleanup();
#endif
    return 2;
  }
  *out_json = json;
  *out_len = strlen(json);

#ifdef _WIN32
  WSACleanup();
#endif
  return 0;
}

ORCA_API void ORCA_Free(void *p) {
  if (p) free(p);
}

