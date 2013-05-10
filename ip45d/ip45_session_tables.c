

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

struct session_entry_t  {
	uint64_t init_s45addr[2];
	uint64_t init_d45addr[2];
	uint64_t last_s45addr[2];
	uint64_t last_d45addr[2];
	uint8_t proto;
	uint16_t sport;
	uint16_t dport;
	uint64_t sid;
	struct session_entry_t *next;
} sesion_entry; 

struct session_table_t {
	struct session_entry_t *head;
	int items;
} session_table;

/* init session table  */
void session_table_init(struct session_table_t *table) {

	table->items = 0;
	table->head = NULL;
}

/* add a new record into session table */
/* returns poitern to entry or null if memory is not available */
struct session_entry_t *session_table_add(struct session_table_t *table, struct session_entry_t *entry) {

	struct session_entry_t *new;

	new = malloc(sizeof(struct session_entry_t));

	if (new == NULL) {
		return NULL;
	}

	memcpy(new, entry, sizeof(struct session_entry_t));
	new->next = table->head;
	table->head = new;
	
	return new;
}

/* lookup entry in the session_table */
/* returns pointer to foud recor or NULL if matching record does not exists */
struct session_entry_t* session_table_lookup_sid(struct session_table_t *table, uint16_t sid) {
	
	struct session_entry_t *tmp; 
	tmp = table->head; 

	while (tmp != NULL) {
		if (tmp->sid == sid) {
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


