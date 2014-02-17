


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


