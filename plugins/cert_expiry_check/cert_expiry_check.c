#include <stddef.h> // for size_t
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#define EXPORT __declspec(dllexport)
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#define EXPORT
#endif

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

static char *dup_json(const char *s) {
  size_t n = strlen(s);
  char *p = (char *)malloc(n + 1);
  if (p)
    memcpy(p, s, n + 1);
  return p;
}

EXPORT int ORCA_Run(const char *host, unsigned int port,
                    unsigned int timeout_ms, const char *params_json,
                    char **out_json, size_t *out_len) {
#ifdef _WIN32
  WSADATA wsa;
  WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

  /* OpenSSL 1.1+ auto-inits, but these calls are harmless on newer versions */
  SSL_library_init();
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();

  SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
  if (!ctx)
    return 1;

  char portstr[16];
  snprintf(portstr, sizeof(portstr), "%u", port);

  BIO *bio = BIO_new_ssl_connect(ctx);
  if (!bio) {
    SSL_CTX_free(ctx);
    return 2;
  }

  char target[256];
  snprintf(target, sizeof(target), "%s:%s", host, portstr);
  BIO_set_conn_hostname(bio, target);

  SSL *ssl = NULL;
  BIO_get_ssl(bio, &ssl);
  if (!ssl) {
    BIO_free_all(bio);
    SSL_CTX_free(ctx);
    return 3;
  }
  SSL_set_tlsext_host_name(ssl, host);

  (void)timeout_ms; /* TODO: wire up a real timeout if you need it */

  if (BIO_do_connect(bio) != 1) {
    BIO_free_all(bio);
    SSL_CTX_free(ctx);
    return 4;
  }
  if (SSL_do_handshake(ssl) != 1) {
    BIO_free_all(bio);
    SSL_CTX_free(ctx);
    return 5;
  }

  X509 *cert = SSL_get_peer_certificate(ssl);
  if (!cert) {
    BIO_free_all(bio);
    SSL_CTX_free(ctx);
    return 6;
  }

  const ASN1_TIME *notAfter = X509_get0_notAfter(cert);

  /* Render notAfter for human-readable report */
  char datebuf[128] = {0};
  {
    BIO *mem = BIO_new(BIO_s_mem());
    if (mem) {
      ASN1_TIME_print(mem, notAfter);
      BIO_read(mem, datebuf, sizeof(datebuf) - 1);
      BIO_free(mem);
    }
  }

  /* Compute days_left using ASN1_TIME_diff (difference from now to notAfter) */
  int pday = 0, psec = 0;
  int days_left = 0; /* positive -> days until expiry; negative -> expired */

  if (ASN1_TIME_diff(&pday, &psec, NULL, notAfter) == 1) {
    /* Total seconds (can be negative if already expired) */
    long long total = (long long)pday * 86400 + (long long)psec;
    if (total >= 0) {
      days_left = (int)((total + 86399) / 86400); /* ceil to whole days */
    } else {
      long long neg = -total;
      days_left =
          -(int)((neg + 86399) / 86400); /* ceil toward zero, keep sign */
    }
  } else {
    /* If diff fails, mark unknown conservatively */
    days_left = 0;
  }

  const char *severity = "info";
  if (days_left < 0)
    severity = "high";
  else if (days_left < 30)
    severity = "medium";

  time_t now = time(NULL);
  char report[1024];
  snprintf(report, sizeof(report),
           "{ \"findings\":[{"
           "\"id\":\"CERT-EXPIRY\","
           "\"plugin_id\":\"cert_expiry_check\","
           "\"title\":\"Certificate expiry check\","
           "\"severity\":\"%s\","
           "\"description\":\"Leaf certificate expiry\","
           "\"evidence\":{\"notAfter\":\"%s\",\"days_left\":\"%d\"},"
           "\"tags\":[\"tls:cert\"],"
           "\"timestamp\":%lld"
           "}],"
           "\"logs\":[{\"ts\":%lld,\"line\":\"Checked certificate expiry\"}] }",
           severity, datebuf, days_left, (long long)now, (long long)now);

  *out_json = dup_json(report);
  *out_len = strlen(report);

  X509_free(cert);
  BIO_free_all(bio);
  SSL_CTX_free(ctx);
#ifdef _WIN32
  WSACleanup();
#endif
  return 0;
}

EXPORT void ORCA_Free(void *p) {
  if (p)
    free(p);
}
