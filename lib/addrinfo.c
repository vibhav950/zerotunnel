#include "conn_defs.h"

#include <arpa/inet.h>
#include <assert.h>

void my_addrinfo_free(struct my_addrinfo *ai) {
  struct my_addrinfo *ai_cur, *ai_next;

  for (ai_cur = ai; ai_cur; ai_cur = ai_next) {
    ai_next = ai_cur->ai_next;
    free(ai_cur);
  }
}

void my_addrinfo_set_port(struct my_addrinfo *ai, int port) {
  struct my_addrinfo *ai_cur;
  struct sockaddr_in *addr;
#ifdef USE_IPV6
  struct sockaddr_in6 *addr6;
#endif

  assert(ai);
  assert(port > 0);

  for (ai_cur = ai; ai_cur; ai_cur = ai_cur->ai_next) {
    switch (ai_cur->ai_family) {
    case AF_INET:
      addr = (struct sockaddr_in *)ai_cur->ai_addr;
      addr->sin_port = htons((unsigned short)port);
      break;
#ifdef USE_IPV6
    case AF_INET6:
      addr6 = (struct sockaddr_in6 *)ai_cur->ai_addr;
      addr6->sin6_port = htons((unsigned short)port);
      break;
#endif
    }
  }
}
