#ifdef WIN32

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define INET6_ADDRSTRLEN 46
typedef int socklen_t;

const char * inet_ntop(int af, const void *src, char *dst, socklen_t size);
int inet_pton(int af, const char *src, void *dst);

#endif

