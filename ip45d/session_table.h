

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

void session_table_init(struct session_table_t *table);
struct session_entry_t *session_table_add(struct session_table_t *table, struct session_entry_t *entry);
struct session_entry_t* session_table_lookup_sid(struct session_table_t *table, uint64_t sid);
struct session_entry_t* session_table_lookup(struct session_table_t *table, 
	uint16_t sport, uint16_t dport, uint8_t proto);
	
