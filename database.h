/**
 * database.h
 * the api for managing queries to sqlite3
 *
 */

#ifndef _DATABASE_H_
#define _DATABASE_H_

// these are the iana protocol numbers
#define DB_PROTO_TCP	6
#define DB_PROTO_UDP	17
#define DB_PROTO_ICMP	1
#define DB_PROTO_ICMP6	58

// these define the paylaod states
//  assessable, interesting, boring, submitted, done, error }

#define DB_PAYLOAD_STATE_ASSESSABLE 1
#define DB_PAYLOAD_STATE_INTERESTING 2
#define DB_PAYLOAD_STATE_BORING 3
#define DB_PAYLOAD_STATE_SUBMITTABLE 4
#define DB_PAYLOAD_STATE_SUBMITTED 5
#define DB_PAYLOAD_STATE_DONE 6
#define DB_PAYLOAD_STATE_ERROR 7

#define DB_STUPIDLY_TRIGGER_SLEEP_SECS 10

#include "config.h"
#include <dnet.h>
#include <sys/tree.h>
#include <sys/queue.h>
#include <event.h>

#include "honeyd.h"
#include "sqlite3.h"
#include "shellcode.h"

#include <netinet/icmp6.h>

#define USE_SQLITE3

TAILQ_HEAD(, shellcode) shellcode_assessment_queue;
TAILQ_HEAD(, shellcode) shellcode_submission_queue;
TAILQ_HEAD(, shellcode) shellcode_build_queue;

char* database_filename;
char* database_shellcodedir;

extern int database_usedb;
extern int database_shellcode_detection; 

void database_set_dbfile(char*);
void database_set_shellcodedir(char*);

void database_init(char* filename);
void database_fix_permissions();
void database_start_threads();

void database_create_tables();
int database_delete_database(char* filename);
int database_check_tables();

void database_query(char* sql, int (*callback)(void *, int, char**, char**) );

void database_close();

int log_transport_layer(struct tuple* conhdr, int payload_id);
int log_network_layer(struct tcp_con* tcp, struct udp_con* udp, int protocol_id);
int log_payload(char* buffer, int size);

void log_icmp4(struct ip_hdr*, struct icmp_hdr *);
void log_icmp6(struct ip6_hdr* ip6, struct icmp6_hdr * icmp6);

void database_assess_payloads();
void database_build_executables();
void database_submit_payloads();

void *database_stupidly_trigger_assessment();
void *database_stupidly_trigger_conversion();
void *database_stupidly_trigger_submission();
#endif

