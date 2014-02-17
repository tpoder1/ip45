

#include "ip45d.h"
#include "ip45d_common.h"
#include "ip45d_win.h"
#include "session_table.h"
#include "inet_ntop45.h"

/* temporary until the code will be cleaned up */
HANDLE ptr;
int sock;

OVERLAPPED olReading, olWriting;

char virt_mac[ETH_ALEN] = { 0x00, 0x00, 0x93, 0x92, 0xD7, 0x8F };
char host_mac[ETH_ALEN] = { 0x00, 0xFF, 0x93, 0x92, 0xD7, 0x8F };



/* initialize output socket */
int init_sock_win() {

	int sock;
	struct sockaddr_in ls; 

	if (( sock = WSASocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, WSA_FLAG_OVERLAPPED)) == INVALID_SOCKET) {
		LOG("WSASocket failed with error: %d\n", WSAGetLastError());
		closesocket(sock);	
		return -1;
	}

	memset(&ls, 0, sizeof(struct sockaddr_in));
	ls.sin_family = AF_INET;
	ls.sin_addr.s_addr = INADDR_ANY;
	ls.sin_port = htons(IP45_COMPAT_UDP_PORT);
	//ls.sin_port = IP45_COMPAT_UDP_PORT;
	if (bind(sock, (struct sockaddr *)&ls, sizeof(struct sockaddr_in)) < 0 ) {
		LOG("WSASocket failed with error: %d\n", WSAGetLastError());
		closesocket(sock);	
	}
	
	return sock;
}


void GetDeviceGuid(char* szDeviceGuid) {	
	HKEY hKey = NULL;
	//if (ERROR_SUCCESS==RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}", 0, KEY_READ, &hKey))
	if (ERROR_SUCCESS==RegOpenKeyEx(HKEY_LOCAL_MACHINE, ADAPTER_KEY, 0, KEY_READ, &hKey))
	{
		TCHAR    achKey[MAX_KEY_LENGTH];   // buffer for subkey name
		DWORD    cbName;                   // size of name string 
		TCHAR    achClass[MAX_PATH] = TEXT("");  // buffer for class name 
		DWORD    cchClassName = MAX_PATH;  // size of class string 
		DWORD    cSubKeys=0;               // number of subkeys 
		DWORD    cbMaxSubKey;              // longest subkey size 
		DWORD    cchMaxClass;              // longest class string 
		DWORD    cValues;              // number of values for key 
		DWORD    cchMaxValue;          // longest value name 
		DWORD    cbMaxValueData;       // longest value data 
		DWORD    cbSecurityDescriptor; // size of security descriptor 
		FILETIME ftLastWriteTime;      // last write time 

		DWORD i, retCode; 

		//TCHAR  achValue[MAX_VALUE_NAME]; 
		//DWORD cchValue = MAX_VALUE_NAME; 
	
		retCode = RegQueryInfoKey(
			hKey,                    // key handle 
			achClass,                // buffer for class name 
			&cchClassName,           // size of class string 
			NULL,                    // reserved 
			&cSubKeys,               // number of subkeys 
			&cbMaxSubKey,            // longest subkey size 
			&cchMaxClass,            // longest class string 
			&cValues,                // number of values for this key 
			&cchMaxValue,            // longest value name 
			&cbMaxValueData,         // longest value data 
			&cbSecurityDescriptor,   // security descriptor 
			&ftLastWriteTime);       // last write time 

		for (i=0; i<cSubKeys; i++) 
        { 
            cbName = MAX_KEY_LENGTH;
            retCode = RegEnumKeyEx(hKey, i,
                     achKey, 
                     &cbName, 
                     NULL, 
                     NULL, 
                     NULL, 
                     &ftLastWriteTime); 
            if (retCode == ERROR_SUCCESS) 
            {    
				HKEY hSubKey = NULL;
				if (ERROR_SUCCESS==RegOpenKeyEx(hKey, achKey, 0, KEY_READ, &hSubKey))
				{
					BYTE szComponent[1000];
					DWORD cbData = 1000;
					DWORD dwType = REG_SZ;

					memset(szComponent, 0, 1000);
					RegQueryValueEx(hSubKey, "ComponentId", NULL, &dwType, szComponent, (void *)&cbData);
					//DEBUG("Found interface: %s\n", szComponent);
					//if (!strcmp((char *)szComponent, "tap0801"))
					if (!strcmp((char *)szComponent, "tap0901"))
					{
						cbData = 1000;
						dwType = REG_SZ;
						RegQueryValueEx(hSubKey, "NetCfgInstanceId", NULL, &dwType, (void *)szDeviceGuid, (void *)&cbData);
						break;
					}
					RegCloseKey(hSubKey);
				}
            }
        }
		RegCloseKey(hKey);
	}

}

void GetHumanName(char* szDeviceGuid, char* szHumanName)
{
	HKEY hKey = NULL;
	char szKeyName[1999];
	strcpy(szKeyName, NETWORK_CONNECTIONS_KEY);
	strcat(szKeyName, "\\");
//	strcpy(szKeyName, "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\");
	if (strlen(szDeviceGuid) > 0)
	{
		strcat(szKeyName, szDeviceGuid);
		strcat(szKeyName, "\\Connection");
		DEBUG("KEY: %s\n", szKeyName);
		if (ERROR_SUCCESS==RegOpenKeyEx(HKEY_LOCAL_MACHINE, szKeyName, 0, KEY_READ, &hKey))
		{			
			DWORD cbData = 1000;
			DWORD dwType = REG_SZ;

			memset(szHumanName, 0, 1000);
			RegQueryValueEx(hKey, "Name", NULL, &dwType, (void *)szHumanName, (void *)&cbData);

			RegCloseKey(hKey);
		}
	}
}

int TAP_CONTROL_CODE(int request, int method)
{
	return CTL_CODE(FILE_DEVICE_UNKNOWN, request, method, FILE_ANY_ACCESS);
}


/* WINDOWS only: read Neighbor Solicitation message and prepare 
 * a packet with Neighbor Advertisement */
int build_nd_adv_pkt(char *virt_mac, char *buf_sol, int len, char *buf_adv) {

	struct ethhdr *eth_sol = (void *)buf_sol;
	struct ethhdr *eth_adv = (void *)buf_adv;
	struct ip6_hdr *ip6h_sol = (void *)buf_sol + sizeof(struct ethhdr);
	struct ip6_hdr *ip6h_adv = (void *)buf_adv + sizeof(struct ethhdr);
	struct nd_neighbor_solicit *icmp6h_sol = (void *)ip6h_sol + sizeof(struct ip6_hdr);
	struct nd_neighbor_advert *icmp6h_adv = (void *)ip6h_adv + sizeof(struct ip6_hdr);
	char *nd_mac_opts = (void *)icmp6h_adv + sizeof(struct nd_neighbor_advert);


	if (ip6h_sol->ip6_nxt != IPPROTO_ICMPV6) {
		return 0;
	}

	if (icmp6h_sol->nd_ns_type != ND_NEIGHBOR_SOLICIT) {
		return 0;
	}

	/* copy original packet into new one */
	memcpy(buf_adv, buf_sol, len);

	icmp6h_adv->nd_na_type = ND_NEIGHBOR_ADVERT;

	/* copy source address from the orriginal packet to the destination */
	memcpy(&ip6h_adv->ip6_dst, &ip6h_sol->ip6_src, sizeof(struct in6_addr));
	/* requested target */
	memcpy(&ip6h_adv->ip6_src, &icmp6h_sol->nd_ns_target, sizeof(struct in6_addr));

	/* set sollicited and override flag */
	icmp6h_adv->nd_na_flags_reserved = htonl(ND_NA_FLAG_SOLICITED | ND_NA_FLAG_OVERRIDE);

	/* set MAC address */
	/* 0 - address type, 1 - addr length, 2 - 7 address */
	nd_mac_opts[0] = ND_OPT_TARGET_LINKADDR; /* 0x1 - source link address, 0x2 - target link address */
	memcpy(nd_mac_opts + 2, virt_mac, ETH_ALEN);


	{
	uint32_t ip6nxt = htonl(ip6h_adv->ip6_nxt);
	uint32_t icmp_len = htonl(len - sizeof(struct ip6_hdr) - sizeof(struct ethhdr));
	char xbuf[PKT_BUF_SIZE];
	int xptr = 0; 
	
	/* an ugly way to cumpute TCP checksum - to be repaired */
	icmp6h_adv->nd_na_cksum = 0x0;
	memcpy(xbuf + xptr, (char *)&(ip6h_adv->ip6_src), sizeof(struct in6_addr));
	xptr += sizeof(ip6h_adv->ip6_src);
	memcpy(xbuf + xptr, &ip6h_adv->ip6_dst, sizeof(ip6h_adv->ip6_dst));
	xptr += sizeof(ip6h_adv->ip6_dst);
	memcpy(xbuf + xptr, &icmp_len, sizeof(uint32_t));
	xptr += sizeof(uint32_t);
	memcpy(xbuf + xptr, &ip6nxt, sizeof(ip6nxt));
	xptr += sizeof(ip6nxt);
	memcpy(xbuf + xptr, icmp6h_adv, ntohl(icmp_len));
	xptr += ntohl(icmp_len);
	icmp6h_adv->nd_na_cksum = inet_cksum(xbuf, xptr);

	}

	/* fill ethernet header */
	eth_adv->h_proto = htons(ETH_P_IPV6);
	memcpy(eth_adv->h_dest, eth_sol->h_source, ETH_ALEN);
	memcpy(eth_adv->h_source, virt_mac, ETH_ALEN);
	return len;
}

/* WINDOWS only: reads data from tap and sends via socket (IPv6 -> IP45) */
DWORD WINAPI tun_to_sock_loop(  LPVOID lpParam ) {

	//HANDLE ptr;
	//int sock; 

	char rcv_ebuf6[PKT_BUF_SIZE];
	struct ethhdr *rcv_eth6 = (struct ethhdr *)rcv_ebuf6;
	char *rcv_buf6 = rcv_ebuf6 + sizeof(struct ethhdr);
	struct ip6_hdr *rcv_ip6h = (struct ip6_hdr *)rcv_buf6;

	char snd_buf45[PKT_BUF_SIZE];
//	struct ip45hdr_p3 *snd_ip45h = (struct ip45hdr_p3 *)snd_buf45;


	char saddr[IP45_ADDR_LEN];
	char daddr[IP45_ADDR_LEN];

	
//	struct in45_addr s45addr;
	struct sockaddr_in peer45_addr;
//	int client_len = sizeof(struct sockaddr);
	WSABUF SndBuf;
	DWORD Flags;

	while(1) {
//		DWORD sock_len;
		DWORD tun_len;
		DWORD snd_len;
//		DWORD dwEvent;
//		int addrlen;
//		WSANETWORKEVENTS myNetEvents;
		int rc;
		//DWORD write_len;


		ReadFile(ptr, rcv_ebuf6, PKT_BUF_SIZE, NULL, &olReading);

		WaitForSingleObject(olReading.hEvent, INFINITE);

		if (!GetOverlappedResult(ptr, &olReading, &tun_len, FALSE) || tun_len <= 0) {
			LOG("Cannot read data GetOverlappedResult\n");
			continue;
		}


		if (ntohs(rcv_eth6->h_proto) != ETH_P_IPV6) {
			continue;
		}

		/* check NS packets and inject the response */
		if (rcv_ip6h->ip6_nxt == IPPROTO_ICMPV6) {
			struct icmp6_hdr *icmp6h = (void *)rcv_ip6h + sizeof(struct ip6_hdr);
			char buf_adv[PKT_BUF_SIZE];

			if (icmp6h->icmp6_type == ND_NEIGHBOR_SOLICIT)  {
				snd_len = build_nd_adv_pkt(virt_mac, rcv_ebuf6, tun_len, buf_adv);
				LOG("ICMP solic v6 %d\n", (int)snd_len);

				/* inject ICMPv6 packet with response */
	     			if (!WriteFile(ptr, buf_adv, snd_len, NULL, &olWriting)) {
					LOG("Cannot write ICMPv6 data.  Error: %d \n", (int)GetLastError());
					exit(2);
				}
				continue;
			}
		}

		tun_len -= sizeof(struct ethhdr);
		snd_len = ipv6_to_ip45(rcv_buf6, tun_len, snd_buf45, &peer45_addr);

		if ((int)snd_len <= 0 ) {
			if ((int)snd_len < 0) {
				LOG("Invalid IPv6 packet\n");
			}
			continue;
		}

//		if (verbose_opt) {
			inet_ntop(AF_INET6, (char *)&rcv_ip6h->ip6_src, saddr, IP45_ADDR_LEN);
			inet_ntop(AF_INET6, (char *)&rcv_ip6h->ip6_dst, daddr, IP45_ADDR_LEN);
			DEBUG("Received IPv6 packet %s -> %s, proto=%d bytes=%d\n",
					saddr, daddr, rcv_ip6h->ip6_nxt, (int)tun_len);
//		}

		SndBuf.len = snd_len;
		SndBuf.buf = snd_buf45;
		Flags = 0;

		rc = WSASendTo(sock, &SndBuf, 1, &snd_len, Flags, 
			(struct sockaddr*)&peer45_addr, sizeof(struct sockaddr_in),
			NULL, NULL );

		if (rc == SOCKET_ERROR) {
			LOG("WSASendTo failed with error: %d\n",  (int)GetLastError());
		}
	} /* while */

}

/* WINDOWS only: reads data from socket and sends to tap (IP45 -> IPv6) */
DWORD WINAPI sock_to_tun_loop(  LPVOID lpParam ) {

	//HANDLE ptr;
	//int sock; 

	char snd_ebuf6[PKT_BUF_SIZE];
	struct ethhdr *snd_eth6 = (struct ethhdr *)snd_ebuf6;
	char *snd_buf6 = snd_ebuf6 + sizeof(struct ethhdr);
	struct ip6_hdr *snd_ip6h = (struct ip6_hdr *)snd_buf6;

	char rcv_buf45[PKT_BUF_SIZE];
	struct ip45hdr_p3 *rcv_ip45h = (struct ip45hdr_p3 *)rcv_buf45;

	char saddr[IP45_ADDR_LEN];
//	char daddr[IP45_ADDR_LEN];

//	char virt_mac[ETH_ALEN] = { 0x00, 0x00, 0x93, 0x92, 0xD7, 0x8F };
//	char host_mac[ETH_ALEN] = { 0x00, 0xFF, 0x93, 0x92, 0xD7, 0x8F };
	
	struct in45_addr s45addr;
	struct sockaddr_in peer45_addr;
	int client_len = sizeof(struct sockaddr);
//	int x = 0;

//	DWORD Flags;

	while(1) {
		DWORD sock_len;
//		DWORD tun_len;
		DWORD snd_len;
// write_len;
//		DWORD dwEvent;
//		int addrlen;
//		WSANETWORKEVENTS myNetEvents;
//		int rc, err;

		sock_len = recvfrom(sock, (void *)rcv_buf45, PKT_BUF_SIZE, 0, (struct sockaddr *)&peer45_addr, &client_len);
/*		if (WSAEnumNetworkEvents(sock, sockEvent, &myNetEvents)) {
			LOG("ERROR: WSAEnumNetworkEvents\n");
			exit(2);
		}
		*/

		if ( (int)sock_len <= 0 ) {
			if (WSAGetLastError() == WSAECONNRESET) {
				LOG("Connection reseted by peer\n");
			} else {
			 	LOG("Recv socket error: %d\n", WSAGetLastError());
			}
			continue;
		}

		if ( (int)sock_len < (int)sizeof(struct ip45hdr_p3) ) {
			LOG("Received too short IP45 packet\n");
			continue;
		}

		snd_len = ip45_to_ipv6(&peer45_addr, rcv_buf45, sock_len, (char *)snd_ip6h);

		if (snd_len < 0 || snd_len == 0) {
			if (snd_len < 0) {
				LOG("Invalid IP45 packet\n");
			}
			continue;
		}

		/* valid IP45 packet */
		rcv_ip45h = (struct ip45hdr_p3 *)rcv_buf45;

		stck45_to_in45(&s45addr, (void *)&peer45_addr.sin_addr, &rcv_ip45h->s45stck, rcv_ip45h->s45mark);

//		if (verbose_opt) {
			inet_ntop45((char *)&s45addr, saddr, IP45_ADDR_LEN);
			DEBUG("Received IP45 packet %s->{me}, sid %08x.%08x.%08x.%08x, proto %d, bytes %d\n", 
				saddr,  
				(unsigned int)ntohl((unsigned int)rcv_ip45h->sid.s45_sid32[0]), 
				(unsigned int)ntohl((unsigned int)rcv_ip45h->sid.s45_sid32[1]), 
				(unsigned int)ntohl((unsigned int)rcv_ip45h->sid.s45_sid32[2]), 
				(unsigned int)ntohl((unsigned int)rcv_ip45h->sid.s45_sid32[3]),
				rcv_ip45h->nexthdr, (int)sock_len);
//		}

		snd_eth6->h_proto = htons(ETH_P_IPV6);
		memcpy(snd_eth6->h_dest, host_mac, ETH_ALEN);
		memcpy(snd_eth6->h_source, virt_mac, ETH_ALEN);
		snd_len += sizeof(struct ethhdr);

	     	if (!WriteFile(ptr, snd_ebuf6, snd_len, NULL, &olWriting)) {
			LOG("Cannot write data to ip45/tun interface. Error: %d \n", (int)GetLastError());
			exit(2);
		}
	} /* while */

	return 0;
}


/* WINDOWS only: main loop */
int main_loop_win(int verbose_opt) {
//	int ptun[3] = {0x0100030a, 0x0000030a, 0x00ffffff};

	DWORD pstatus;
	DWORD pstatus_len;


	char devGuid[1000];
	char devHuman[1000];
	char fileName[1000];

//	WSABUF RcvBuf, SndBuf;
//	DWORD Flags;

	HANDLE Thread1 = 0;
//	HANDLE Thread2 = 0;

	/* prepare filehandle - TUN device */
	memset(devGuid, 0, 1000);
	GetDeviceGuid(devGuid);
	LOG("Devie GUID: %s\n", devGuid);

	GetHumanName(devGuid, devHuman);
	LOG("Humman name: %s\n", devHuman);
	sprintf(fileName, "%s%s%s", USERMODEDEVICEDIR, devGuid, TAP_WIN_SUFFIX);

	LOG("File Name: %s\n", fileName);


//	ptr = CreateFile(fileName, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE, 0, 
//						OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, NULL);

	ptr = CreateFile(fileName, GENERIC_READ | GENERIC_WRITE, 0, 0, 
						OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,  0);

	pstatus = 1;	
	DeviceIoControl(ptr, TAP_WIN_IOCTL_SET_MEDIA_STATUS, &pstatus, 4, &pstatus, 4, &pstatus_len, NULL);
	/* set device to TUN mode (without Ethernet frame) */
//	DeviceIoControl(ptr, TAP_WIN_IOCTL_CONFIG_TUN, ptun, 12, ptun, 12, &len, NULL);

	olReading.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	olWriting.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	
	if ((sock = init_sock_win()) < 0) {
		LOG("Cant initialize ip45 socket\n");
		exit(2);
	}


	//Thread1 = CreateThread( NULL, 0, sock_to_tun_loop, NULL, 0, NULL);  
	
	Thread1 = CreateThread( NULL, 0, tun_to_sock_loop, NULL, 0, NULL);  
	if ( Thread1 == NULL) {
		LOG("Cannot create thread\n");
	}
	
//	tun_to_sock_loop(NULL);
	
	sock_to_tun_loop(NULL);
	while (1) {
	}
	
	

	return 0;
}
