#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

static const char *default_users[] = {"admin", "root", "user", "guest"};
static const char *default_passwords[] = {"admin", "root", "1234", "password",
                                          "guest"};

static char *dup_json(const char *s) {
  size_t n = strlen(s);
  char *p = (char *)malloc(n + 1);
  if (p)
    memcpy(p, s, n + 1);
  return p;
}

static int connect_socket(const char *host, uint16_t port) {
  char portstr[16];
  snprintf(portstr, sizeof(portstr), "%u", port);
  struct addrinfo hints, *res = NULL;
  memset(&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_family = AF_UNSPEC;
  if (getaddrinfo(host, portstr, &hints, &res) != 0)
    return -1;

  int sock = -1;
  for (struct addrinfo *p = res; p; p = p->ai_next) {
    sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (sock < 0)
      continue;
    if (connect(sock, p->ai_addr, (int)p->ai_addrlen) == 0)
      break;
#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif
    sock = -1;
  }
  freeaddrinfo(res);
  return sock;
}

// Minimal Telnet login attempt (very naive)
static int try_telnet_login(const char *host, uint16_t port, const char *user,
                            const char *pass) {
  int s = connect_socket(host, port);
  if (s < 0)
    return 0;

  char buf[1024];
  int n = recv(s, buf, sizeof(buf) - 1, 0);
  if (n <= 0) {
#ifdef _WIN32
    closesocket(s);
#else
    close(s);
#endif
    return 0;
  }
  buf[n] = 0;

  // send username
  send(s, user, (int)strlen(user), 0);
  send(s, "\n", 1, 0);

  n = recv(s, buf, sizeof(buf) - 1, 0);
  if (n <= 0) {
#ifdef _WIN32
    closesocket(s);
#else
    close(s);
#endif
    return 0;
  }
  buf[n] = 0;

  // send password
  send(s, pass, (int)strlen(pass), 0);
  send(s, "\n", 1, 0);

  n = recv(s, buf, sizeof(buf) - 1, 0);
  if (n <= 0) {
#ifdef _WIN32
    closesocket(s);
#else
    close(s);
#endif
    return 0;
  }
  buf[n] = 0;

  // heuristic: if prompt contains "$" or "#" → success
  int success = (strchr(buf, '$') || strchr(buf, '#')) ? 1 : 0;

#ifdef _WIN32
  closesocket(s);
#else
  close(s);
#endif
  return success;
}

EXPORT int ORCA_Run(const char *host, unsigned int port,
                    unsigned int timeout_ms, const char *params_json,
                    char **out_json, size_t *out_len) {
#ifdef _WIN32
  WSADATA wsa;
  WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

  time_t now = time(NULL);
  char report[2048];
  snprintf(report, sizeof(report),
           "{ \"findings\":[], \"logs\":[{\"ts\":%lld, \"line\":\"Default "
           "Password Audit started\"}] }",
           (long long)now);

  // Try telnet default creds if port==23
  if (port == 23) {
    for (size_t i = 0; i < sizeof(default_users) / sizeof(default_users[0]);
         i++) {
      for (size_t j = 0;
           j < sizeof(default_passwords) / sizeof(default_passwords[0]); j++) {
        if (try_telnet_login(host, (uint16_t)port, default_users[i],
                             default_passwords[j])) {
          snprintf(report, sizeof(report),
                   "{ \"findings\":[{"
                   "\"id\":\"DEFAULT-CREDS\","
                   "\"plugin_id\":\"default_password_audit\","
                   "\"title\":\"Default credentials accepted\","
                   "\"severity\":\"high\","
                   "\"description\":\"Service allowed login with default "
                   "credentials\","
                   "\"evidence\":{\"user\":\"%s\",\"pass\":\"%s\"},"
                   "\"tags\":[\"default:creds\"],"
                   "\"timestamp\":%lld"
                   "}],"
                   "\"logs\":[{\"ts\":%lld,\"line\":\"Login success with "
                   "%s/%s\"}] }",
                   default_users[i], default_passwords[j], (long long)now,
                   (long long)now, default_users[i], default_passwords[j]);
          goto done;
        }
      }
    }
  }

done:
  *out_json = dup_json(report);
  *out_len = strlen(report);

#ifdef _WIN32
  WSACleanup();
#endif
  return 0;
}

EXPORT void ORCA_Free(void *p) {
  if (p)
    free(p);
}
