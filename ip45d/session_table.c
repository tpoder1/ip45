/*

  IP45 Project - http://ip45.org

  Copyright (C) 2012 - 2014,  Tomas Podermanski

  This code can be redistributed and/or modfied under the terms of 
  the GNU General Public License as published by the Free Software 
  Foundation, either version 3 of the License, or (at your option) 
  any later version, see <http://www.gnu.org/licenses/>.

*/


#include "ip45d.h"
#include "session_table.h"


/* init session table  */
void session_table_init(struct session_table_t *table) {

	table->items = 0;
	table->head = NULL;
}

/* add a new record into session table */
/* returns poiter to entry or null if memory is not available */
struct session_entry_t *session_table_add(struct session_table_t *table, struct session_entry_t *entry) {

	struct session_entry_t *new;

	new = malloc(sizeof(struct session_entry_t));

	if (new == NULL) {
		return NULL;
	}

	memcpy(new, entry, sizeof(struct session_entry_t));
	new->next = table->head;
	table->head = new;
	table->items += 1;
	
	return new;
}

/* lookup entry in the session_table */
/* returns pointer to foud recor or NULL if matching record does not exists */
struct session_entry_t* session_table_lookup_sid(struct session_table_t *table, struct in45_sid *sid) {
	
	struct session_entry_t *tmp; 
	tmp = table->head; 

	while (tmp != NULL) {
		if (tmp->sid.s45_sid64[0] == sid->s45_sid64[0] && tmp->sid.s45_sid64[1] == sid->s45_sid64[1]) {
			return tmp;	
		}
		tmp = tmp->next;
	}
	
	return NULL;
}
/* lookup entry in the session_table */
/* returns pointer to foud recor or NULL if matching record does not exists */
struct session_entry_t* session_table_lookup(struct session_table_t *table, 
	uint16_t sport, uint16_t dport, uint8_t proto) {
	
	struct session_entry_t *tmp; 
	tmp = table->head; 

	while (tmp != NULL) {
		if (tmp->sport == sport && tmp->dport == dport && tmp->proto == proto ) {
			return tmp;	
		}
		tmp = tmp->next;
	}
	
	return NULL;
}


