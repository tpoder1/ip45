/*

  IP45 Project - http://ip45.org

  Copyright (C) 2012 - 2014,  Tomas Podermanski

  This code can be redistributed and/or modfied under the terms of 
  the GNU General Public License as published by the Free Software 
  Foundation, either version 3 of the License, or (at your option) 
  any later version, see <http://www.gnu.org/licenses/>.

*/


//#include "ip45d.h"

struct session_entry_t  {
	uint64_t init_s45addr[2];
	uint64_t init_d45addr[2];
	uint64_t last_s45addr[2];
	uint64_t last_d45addr[2];
	uint16_t last_45port;
	uint8_t proto;
	uint16_t sport;
	uint16_t dport;
	struct in45_sid sid;
	struct session_entry_t *next;
} sesion_entry; 

struct session_table_t {
	struct session_entry_t *head;
	int items;
} session_table;

void session_table_init(struct session_table_t *table);
struct session_entry_t *session_table_add(struct session_table_t *table, struct session_entry_t *entry);
struct session_entry_t* session_table_lookup_sid(struct session_table_t *table, struct in45_sid *sid);
struct session_entry_t* session_table_lookup(struct session_table_t *table, 
	uint16_t sport, uint16_t dport, uint8_t proto);
	
