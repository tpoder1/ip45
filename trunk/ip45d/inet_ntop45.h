/*

  IP45 Project - http://ip45.org

  Copyright (C) 2012 - 2014,  Tomas Podermanski

  This code can be redistributed and/or modfied under the terms of 
  the GNU General Public License as published by the Free Software 
  Foundation, either version 3 of the License, or (at your option) 
  any later version, see <http://www.gnu.org/licenses/>.

*/

#include <sys/types.h>
#ifdef WIN32
#include <windows.h>
#include <winsock.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else 
#include <sys/socket.h>
#endif

#define IP45_ADDR_LEN 70

extern const char *inet_ntop45 (const char *src, char *dst, socklen_t size);

