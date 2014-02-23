/*

  IP45 Project - http://ip45.org

  Copyright (C) 2012 - 2014,  Tomas Podermanski

  This code can be redistributed and/or modified under the terms of 
  the GNU General Public License as published by the Free Software 
  Foundation, either version 3 of the License, or (at your option) 
  any later version, see <http://www.gnu.org/licenses/>.

*/



/* initialize output socket */
int init_sock_win();

void GetDeviceGuid(char* szDeviceGuid);

void GetHumanName(char* szDeviceGuid, char* szHumanName);

int TAP_CONTROL_CODE(int request, int method);

/* WINDOWS only: read Neighbor Solicitation message and prepare 
 * a packet with Neighbor Advertisement */
int build_nd_adv_pkt(char *virt_mac, char *buf_sol, int len, char *buf_adv);

/* WINDOWS only: reads data from tap and sends via socket (IPv6 -> IP45) */
DWORD WINAPI tun_to_sock_loop(  LPVOID lpParam );

/* WINDOWS only: reads data from socket and sends to tap (IP45 -> IPv6) */
DWORD WINAPI sock_to_tun_loop(  LPVOID lpParam );

/* WINDOWS only: main loop */
int main_loop_win(int verbose_opt);


