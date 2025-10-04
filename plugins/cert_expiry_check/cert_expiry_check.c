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
                    unsigned int timeout_ms, char **out_json, size_t *out_len) {
#ifdef _WIN32
  WSADATA wsa;
  WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

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

  int ok = BIO_do_connect(bio);
  if (ok != 1) {
    BIO_free_all(bio);
    SSL_CTX_free(ctx);
    return 4;
  }

  ok = SSL_do_handshake(ssl);
  if (ok != 1) {
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

  ASN1_TIME *notAfter = X509_get_notAfter(cert);
  BIO *mem = BIO_new(BIO_s_mem());
  ASN1_TIME_print(mem, notAfter);
  char datebuf[128];
  memset(datebuf, 0, sizeof(datebuf));
  BIO_read(mem, datebuf, sizeof(datebuf) - 1);
  BIO_free(mem);

  // Convert ASN1_TIME to time_t
  int days, secs;
  if (X509_cmp_time(notAfter, &days) == 0) {
    // fallback: manual conversion if needed
  }

  // Safer: convert ASN1_TIME into struct tm
  struct tm t;
  memset(&t, 0, sizeof(t));
  const char *str = (const char *)notAfter->data;
  if (notAfter->type == V_ASN1_UTCTIME) {
    sscanf(str, "%2d%2d%2d%2d%2dZ", &t.tm_year, &t.tm_mon, &t.tm_mday,
           &t.tm_hour, &t.tm_min);
    t.tm_year += (t.tm_year < 70) ? 2000 - 1900 : 1900 - 1900;
    t.tm_mon -= 1;
  } else if (notAfter->type == V_ASN1_GENERALIZEDTIME) {
    sscanf(str, "%4d%2d%2d%2d%2dZ", &t.tm_year, &t.tm_mon, &t.tm_mday,
           &t.tm_hour, &t.tm_min);
    t.tm_year -= 1900;
    t.tm_mon -= 1;
  }
  time_t expiry = mktime(&t);
  time_t now = time(NULL);
  int days_left = (int)((expiry - now) / 86400);

  char report[1024];
  const char *severity = "info";
  if (days_left < 0)
    severity = "high";
  else if (days_left < 30)
    severity = "medium";

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
