
#include <sys/types.h>
#ifdef WIN32
#include <windows.h>
#include <winsock.h>
#include <winsock2.h>
#include <Ws2tcpip.h>
#else 
#include <sys/socket.h>
#endif

#define IP45_ADDR_LEN 70

extern const char *inet_ntop45 (const char *src, char *dst, socklen_t size);

