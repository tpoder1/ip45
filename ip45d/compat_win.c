/*

  IP45 Project - http://ip45.org

  Copyright (C) 2012 - 2014,  Tomas Podermanski

  This code can be redistributed and/or modified under the terms of 
  the GNU General Public License as published by the Free Software 
  Foundation, either version 3 of the License, or (at your option) 
  any later version, see <http://www.gnu.org/licenses/>.

*/
#ifdef WIN32

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <winioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "tap-windows.h"
#include "ip6.h"
#include "compat_win.h"


/*
 * inet_ntop() and inet_pton() wrap-implementations using
 * WSAAddressToString() and WSAStringToAddress() functions
 *
 * this is needed as long as we support running OpenVPN on WinXP
 */

const char *
inet_ntop(int af, const void *src, char *dst, socklen_t size)
{
  struct sockaddr_storage ss;
  unsigned long s = size;

  ZeroMemory(&ss, sizeof(ss));
  ss.ss_family = af;

  switch(af) {
    case AF_INET:
      ((struct sockaddr_in *)&ss)->sin_addr = *(struct in_addr *)src;
      break;
    case AF_INET6:
      ((struct sockaddr_in6 *)&ss)->sin6_addr = *(struct in6_addr *)src;
      break;
    default:
      return NULL;
  }
  /* cannot direclty use &size because of strict aliasing rules */
  return (WSAAddressToString((struct sockaddr *)&ss, sizeof(ss), NULL, dst, &s) == 0)?
          dst : NULL;
}

int
inet_pton(int af, const char *src, void *dst)
{
  struct sockaddr_storage ss;
  int size = sizeof(ss);
  char src_copy[INET6_ADDRSTRLEN+1];

  ZeroMemory(&ss, sizeof(ss));
  /* stupid non-const API */
  strncpy (src_copy, src, INET6_ADDRSTRLEN+1);
  src_copy[INET6_ADDRSTRLEN] = 0;

  if (WSAStringToAddress(src_copy, af, NULL, (struct sockaddr *)&ss, &size) == 0) {
    switch(af) {
      case AF_INET:
	*(struct in_addr *)dst = ((struct sockaddr_in *)&ss)->sin_addr;
	return 1;
      case AF_INET6:
	*(struct in6_addr *)dst = ((struct sockaddr_in6 *)&ss)->sin6_addr;
	return 1;
    }
  }
  return 0;
}

#endif

