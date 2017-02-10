#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/stat.h>       // for stat
#include "database.h"
#include "submission.h"
#include "util.h"
#include "pthread.h"

#include <sys/types.h>
#include <pwd.h>            // both for getuid and getpwuid 

#include <netinet/icmp6.h> 	// for struct icmp6_hdr
#define DB_WARN printf("Database warning: sqlite3 support is disabled. #define USE_SQLITE3 in database.h!\n");

//#define VERBOSE_PTHREADS

#ifdef USE_SQLITE3
sqlite3* sqlite_db;

// how to create the tables in the Database. 
// MAKE SURE TO ORDER THEM ALPHABETICALLY
char* tables[] = {"CREATE TABLE connection (af_inet_type NUMERIC, destination TEXT, end_time NUMERIC, id INTEGER PRIMARY KEY, protocol NUMERIC, protocol_id NUMERIC, source TEXT, start_time NUMERIC)", 
                  "CREATE TABLE icmp (code NUMERIC, id INTEGER PRIMARY KEY, type NUMERIC)",
                  "CREATE TABLE payload (id INTEGER PRIMARY KEY, payload BLOB, report_url TEXT, filename TEXT, state NUMERIC)", 
                  "CREATE TABLE tcp_udp (dport NUMERIC, id INTEGER PRIMARY KEY, payload_id NUMERIC, sport NUMERIC)"};
int ntables = 4;
#endif

int database_usedb;
int database_shellcode_detection;

pthread_t assessment_thread, conversion_thread, submission_thread;
pthread_mutex_t mutex;


// initializes the datbase and will report if an error should occur.
// also initializes the queues. 
void database_init(char* filename) {
#ifdef USE_SQLITE3
	if(database_usedb == 0)
        return;

	sqlite3_open(filename, &sqlite_db);
	if(!sqlite_db) {
		printf("Database error: The database %s didn't open.\n", filename);
		exit(EXIT_FAILURE);	
	} 

    TAILQ_INIT(&shellcode_assessment_queue);
    TAILQ_INIT(&shellcode_submission_queue);
    TAILQ_INIT(&shellcode_build_queue);

    database_fix_permissions();
#else
    DB_WARN
#endif
}

void database_fix_permissions() {
#ifdef USE_SQLITE3
    if(database_usedb == 0)
        return;

	if(database_shellcode_detection == 0)
		return;

    struct passwd* pw = getpwuid(getuid());
    
    struct stat st;
    int error = 0;
    int retval = stat(database_shellcodedir, &st);
    if(retval != 0) {
        perror("Database error: Couldn't access the shellcode directory");
        fprintf(stderr, "You configured %s as your shellcode directory. Please make sure it is accessible (honeyd was being run as user %s, uid: %d)\n", database_shellcodedir, pw->pw_name, pw->pw_uid );
        error = 1;
    }


    char* msfencode_logdir;
    asprintf(&msfencode_logdir, "%s/metasploit_logs", database_shellcodedir);
    if(asprintf == NULL) {
        printf("shellcode error while asprintf-ing msfencode_logdir");
        exit(EXIT_FAILURE);
    }
    
    retval = stat(msfencode_logdir, &st);
    if(retval != 0) {
        perror("Database error: Couldn't access msfencode's logging directory");
        fprintf(stderr, "You configured %s as the directory for msfencode to write it's logfiles to. Please make sure it is accessible (honeyd was being run as user %s, uid: %d)\n", msfencode_logdir, pw->pw_name, pw->pw_uid);
        error = 1;
    }
    
    // set environment variable for msfencode
    setenv("MSF_CFGROOT_CONFIG", msfencode_logdir, 1);
    free(msfencode_logdir);

    if(error > 0)
        exit(EXIT_FAILURE);

#else
    DB_WARN
#endif
}

void database_start_threads() {
#ifdef USE_SQLITE3
    if(database_usedb == 0)
        return;

    pthread_mutex_init(&mutex, NULL);
    pthread_mutex_lock(&mutex);

    
    int retval = pthread_create(&assessment_thread, NULL, database_stupidly_trigger_assessment, NULL);
    if(retval != 0) {
        perror("Error creating assessment thread");
        exit(EXIT_FAILURE);
    }

    retval = pthread_create(&conversion_thread, NULL, database_stupidly_trigger_conversion, NULL);
    if(retval != 0) {
        perror("Error creating conversion thread");
        exit(EXIT_FAILURE);
    }

    retval = pthread_create(&submission_thread, NULL, database_stupidly_trigger_submission, NULL);
    if(retval != 0) {
        perror("Error creating submission thread");
        exit(EXIT_FAILURE);
    }
    pthread_mutex_unlock(&mutex);
    

#else
    DB_WARN
#endif
}

// performs a database query and will report if an error should occur.
// requires an open database connection.
void database_query(char* sql, int (*callback)(void*, int, char**, char**)) {
#ifdef USE_SQLITE3
    if(database_usedb == 0)
        return;

	char *errorMsg = NULL;
	int retval = sqlite3_exec(sqlite_db, sql, callback, 0, &errorMsg);
    if(retval != SQLITE_OK) {
		printf("Database error: %s, retval: %d\n", errorMsg, retval);
		sqlite3_free(sqlite_db);
        free(errorMsg);
		exit(EXIT_FAILURE);
	}

#else
    DB_WARN
#endif

} 

// closes the database.
void database_close() {
#ifdef USE_SQLITE3 
    if(database_usedb == 0)
        return;
    
    pthread_cancel(assessment_thread);
    pthread_cancel(conversion_thread);
    pthread_cancel(submission_thread);

    printf("database info: waiting for threads to terminate...\n");
    /*
     *pthread_join(assessment_thread, NULL);
     *pthread_join(conversion_thread, NULL);
     *pthread_join(submission_thread, NULL);
     */

    int retval = sqlite3_close(sqlite_db);
    
	if(retval != SQLITE_OK) {
		printf("Database error: closing the database didn't work. (%d)\nTODO: Fix this!\n", retval);
        sqlite3_free(sqlite_db);
	}
	printf("Database info: Database successfully closed.\n");

#else
    DB_WARN
#endif

}

// writes transport layer information (source port and destination port) into the database.
// requires an open database connection
// returns the ID of the row that was inserted.
int log_transport_layer(struct tuple* conhdr, int payload_id) {
#ifdef USE_SQLITE3
    if(database_usedb == 0)
        return -1;

    printf("Im logging the transport layer!\n");

    sqlite3_stmt* statement; 
    
    int retval = sqlite3_prepare_v2(sqlite_db, "INSERT INTO tcp_udp (sport, dport, payload_id) VALUES (?, ?, ?);", -1, &statement, NULL);
    if(retval != SQLITE_OK) {
        sqlite3_finalize(statement);
        sqlite3_free(sqlite_db);
        printf("Error in sqlite3_prepare_v2 at line %d: %d\n", __LINE__, retval);
    }

    sqlite3_bind_int(statement, 1, conhdr->sport);
    sqlite3_bind_int(statement, 2, conhdr->dport);
    sqlite3_bind_int(statement, 3, payload_id);

    int step_type = sqlite3_step(statement);
    if(step_type != SQLITE_DONE) {
        printf("Didn't really step through the INSERT statement - strange!: %d\n", step_type);
        sqlite3_finalize(statement);
        sqlite3_free(sqlite_db);
        exit(EXIT_FAILURE);
    }


    sqlite3_finalize(statement);
    return sqlite3_last_insert_rowid(sqlite_db); 
#else
    DB_WARN
    return -1;
#endif
}

// writes icmpv4 information into the database.
// this breaks the convention of logging one layer only as it will also create an IPv6 entry
void log_icmp4(struct ip_hdr * ip, struct icmp_hdr * icmp) {
	
	if(database_usedb == 0)
	   return;	

	if(ip == NULL) {
		printf("Database warning: tried to log an icmp packet but couldn't read ipv6 header\n");
		return;
	}

	if(icmp == NULL) {
		printf("Database warning: tried to log an icmp packet but couldn't read icmpv6 header\n");
		return;
	}

	char* sql = "INSERT INTO icmp (type, code) VALUES (?, ?)";
	sqlite3_stmt* statement;
	int retval = sqlite3_prepare_v2(sqlite_db, sql, strlen(sql) + 1, &statement, NULL);

	if(retval != SQLITE_OK) {
		printf("Database error: There was an error with sqlite3_prepare_v2: %d\n", retval);
		sqlite3_finalize(statement);
		sqlite3_free(sqlite_db);
		exit(EXIT_FAILURE);
	}

	retval = sqlite3_bind_int(statement, 1, icmp->icmp_type);
	if(retval != SQLITE_OK) {
		printf("Database error: There was an error with sqlite3_bind_int: %d\n", retval);
		sqlite3_finalize(statement);
		sqlite3_free(sqlite_db);
		exit(EXIT_FAILURE);
	}
	
	retval = sqlite3_bind_int(statement, 2, icmp->icmp_code);
	if(retval != SQLITE_OK) {
		printf("Database error: There was an error with sqlite3_bind_int: %d\n", retval);
		sqlite3_finalize(statement);
		sqlite3_free(sqlite_db);
		exit(EXIT_FAILURE);
	}

	while(1) {
		retval = sqlite3_step(statement);
		if(retval == SQLITE_DONE)
			break;
		else
			printf("Database info: still stepping while INSERTING the icmp6 type\n");
	}

	sqlite3_finalize(statement);
	int icmp_id = sqlite3_last_insert_rowid(sqlite_db);

	sqlite3_stmt* stmt_ipv4;

	// we use constant values 4 for the af_inet_type and 1 for the protocol number for icmp
	// trying to use the preprocessor macro DB_PROTO_ICMP doesn't work here.. so we use
	// hard coded numbers to limit the number of calls to sqlite3_bind_int.
	char* ipv4_sql = "INSERT INTO connection (source, destination, af_inet_type, start_time, end_time, protocol, protocol_id) \
					  VALUES (?, ?, 4, ?, ?, 1, ?);";
	retval = sqlite3_prepare_v2(sqlite_db, ipv4_sql, strlen(ipv4_sql) + 1, &stmt_ipv4, NULL);
   if(retval != SQLITE_OK) {
		printf("Database error: There was an error with sqlite_prepare_v2: %d\n", retval);
        sqlite3_finalize(stmt_ipv4);
        sqlite3_free(sqlite_db);
        exit(EXIT_FAILURE);
   }
 
  	char* src = calloc(32, sizeof(char));
	if(src == NULL) {
		printf("Error: Couldn't alloc enough memory for buffer src in line %d\n", __LINE__);
 		exit(EXIT_FAILURE);
	}
	inet_ntop(AF_INET, &(ip->ip_src), src, 32 * sizeof(char));
	retval = sqlite3_bind_text(stmt_ipv4, 1, src, -1, NULL);
	if(retval != SQLITE_OK) {
        printf("Database error: There was an error with sqlite3_bind_blob: %d\n", retval);
        sqlite3_finalize(stmt_ipv4);
        sqlite3_free(sqlite_db);
		free(src);
        exit(EXIT_FAILURE);
	}

	char* dst = calloc(32, sizeof(char));
	if(dst == NULL) {
		printf("Error: Couldn't alloc enough memory for buffer dst in line %d\n", __LINE__);
		exit(EXIT_FAILURE);
	}
	inet_ntop(AF_INET, &(ip->ip_dst), dst, 32 * sizeof(char));
   retval = sqlite3_bind_text(stmt_ipv4, 2, dst, -1, NULL);
   if(retval != SQLITE_OK) {
        printf("Database error: There was an error with sqlite3_bind_blob: %d\n", retval);
        sqlite3_finalize(stmt_ipv4);
        sqlite3_free(sqlite_db);
		free(dst);
        exit(EXIT_FAILURE);
   } 

   time_t now = time(NULL);
   retval = sqlite3_bind_int(stmt_ipv4, 3, (int) now);
   if(retval != SQLITE_OK) {
        printf("Database error: There was an error with sqlite3_bind_blob: %d\n", retval);
        sqlite3_finalize(stmt_ipv4);
        sqlite3_free(sqlite_db);
        exit(EXIT_FAILURE);
   } 

   retval = sqlite3_bind_int(stmt_ipv4, 4, (int) now);
   if(retval != SQLITE_OK) {
        printf("Database error: There was an error with sqlite3_bind_blob: %d\n", retval);
        sqlite3_finalize(stmt_ipv4);
        sqlite3_free(sqlite_db);
        exit(EXIT_FAILURE);
   } 

   retval = sqlite3_bind_int(stmt_ipv4, 5, icmp_id);
   if(retval != SQLITE_OK) {
        printf("Database error: There was an error with sqlite3_bind_blob: %d\n", retval);
        sqlite3_finalize(stmt_ipv4);
        sqlite3_free(sqlite_db);
        exit(EXIT_FAILURE);
   } 

	while(1) {
		retval = sqlite3_step(stmt_ipv4);
		if(retval == SQLITE_DONE)
			break;
		else
			printf("Datbase info: still stepping while INSERTING\n");
	}

	free(src);
	free(dst);
	sqlite3_finalize(stmt_ipv4);

}



// writes icmpv6 information into the database.
// this breaks the convention of logging one layer only as it will also create an IPv6 entry
void log_icmp6(struct ip6_hdr * ip6, struct icmp6_hdr * icmp6) {
	
	if(database_usedb == 0)
	   return;	

	if(ip6 == NULL) {
		printf("Database warning: tried to log an icmp packet but couldn't read ipv6 header\n");
		return;
	}

	if(icmp6 == NULL) {
		printf("Database warning: tried to log an icmp packet but couldn't read icmpv6 header\n");
		return;
	}

	char* sql = "INSERT INTO icmp (type, code) VALUES (?, ?)";
	sqlite3_stmt* statement;
	int retval = sqlite3_prepare_v2(sqlite_db, sql, strlen(sql) + 1, &statement, NULL);

	if(retval != SQLITE_OK) {
		printf("Database error: There was an error with sqlite3_prepare_v2: %d\n", retval);
		sqlite3_finalize(statement);
		sqlite3_free(sqlite_db);
		exit(EXIT_FAILURE);
	}

	int type=  icmp6->icmp6_type;
	retval = sqlite3_bind_int(statement, 1, type);
	if(retval != SQLITE_OK) {
		printf("Database error: There was an error with sqlite3_bind_int: %d\n", retval);
		sqlite3_finalize(statement);
		sqlite3_free(sqlite_db);
		exit(EXIT_FAILURE);
	}
	
	retval = sqlite3_bind_int(statement, 2, (int) icmp6->icmp6_code);
	if(retval != SQLITE_OK) {
		printf("Database error: There was an error with sqlite3_bind_int: %d\n", retval);
		sqlite3_finalize(statement);
		sqlite3_free(sqlite_db);
		exit(EXIT_FAILURE);
	}

	while(1) {
		retval = sqlite3_step(statement);
		if(retval == SQLITE_DONE)
			break;
		else
			printf("Database info: still stepping while INSERTING the icmp6 type\n");
	}

	sqlite3_finalize(statement);
	int icmp_id = sqlite3_last_insert_rowid(sqlite_db);

	sqlite3_stmt* stmt_ipv6;

	// we use constant values 6 for the af_inet_type and 58 for the protocol number for icmpv6
	// trying to use the preprocessor macro DB_PROTO_ICMP6 doesn't work here.. so we use
	// hard coded numbers to limit the number of calls to sqlite3_bind_int.
	char* ipv6_sql = "INSERT INTO connection (source, destination, af_inet_type, start_time, end_time, protocol, protocol_id) \
					  VALUES (?, ?, 6, ?, ?, 58, ?);";
	retval = sqlite3_prepare_v2(sqlite_db, ipv6_sql, strlen(ipv6_sql) + 1, &stmt_ipv6, NULL);
   if(retval != SQLITE_OK) {
		printf("Database error: There was an error with sqlite_prepare_v2: %d\n", retval);
        sqlite3_finalize(stmt_ipv6);
        sqlite3_free(sqlite_db);
        exit(EXIT_FAILURE);
   }
   
	char* src = calloc(128, sizeof(char));
	if(src == NULL) {
		printf("Couldn't alloc enough memory for src buffer in line %d\n", __LINE__);
		exit(EXIT_FAILURE);
	}
	inet_ntop(AF_INET6, &(ip6->ip6_src), src, 128 * sizeof(char));
	retval = sqlite3_bind_text(stmt_ipv6, 1, src, -1, NULL);
	if(retval != SQLITE_OK) {
        printf("Database error: There was an error with sqlite3_bind_blob: %d\n", retval);
        sqlite3_finalize(stmt_ipv6);
        sqlite3_free(sqlite_db);
		free(src);
        exit(EXIT_FAILURE);
	}

	char* dst = calloc(128, sizeof(char));
	if(dst == NULL) {
		printf("Couldn't alloc enough memory for dst buffer in line %d\n", __LINE__);
		exit(EXIT_FAILURE);
	}
	inet_ntop(AF_INET6, &(ip6->ip6_dst), dst, 128 * sizeof(char));
   retval = sqlite3_bind_text(stmt_ipv6, 2, dst, -1, NULL);
   if(retval != SQLITE_OK) {
        printf("Database error: There was an error with sqlite3_bind_blob: %d\n", retval);
        sqlite3_finalize(stmt_ipv6);
        sqlite3_free(sqlite_db);
		free(dst);
        exit(EXIT_FAILURE);
   } 

   time_t now = time(NULL);
   retval = sqlite3_bind_int(stmt_ipv6, 3, (int) now);
   if(retval != SQLITE_OK) {
        printf("Database error: There was an error with sqlite3_bind_blob: %d\n", retval);
        sqlite3_finalize(stmt_ipv6);
        sqlite3_free(sqlite_db);
        exit(EXIT_FAILURE);
   } 

   retval = sqlite3_bind_int(stmt_ipv6, 4, (int) now);
   if(retval != SQLITE_OK) {
        printf("Database error: There was an error with sqlite3_bind_blob: %d\n", retval);
        sqlite3_finalize(stmt_ipv6);
        sqlite3_free(sqlite_db);
        exit(EXIT_FAILURE);
   } 

   retval = sqlite3_bind_int(stmt_ipv6, 5, icmp_id);
   if(retval != SQLITE_OK) {
        printf("Database error: There was an error with sqlite3_bind_blob: %d\n", retval);
        sqlite3_finalize(stmt_ipv6);
        sqlite3_free(sqlite_db);
        exit(EXIT_FAILURE);
   } 

	while(1) {
		retval = sqlite3_step(stmt_ipv6);
		if(retval == SQLITE_DONE)
			break;
		else
			printf("Datbase info: still stepping while INSERTING\n");
	}

	free(src);
	free(dst);
	sqlite3_finalize(stmt_ipv6);

}



// writes network layer information into the database.
// includes addresses, timespan, network type, type of upper layer protocol and the id of the row
// requires an open database connection.
// returns the id of the row inserted.
int log_network_layer(struct tcp_con* tcp, struct udp_con* udp, int protocol_id) {
#ifdef USE_SQLITE3
    if(database_usedb == 0)
        return -1;
    
    printf("Im logging the network layer!\n");
    
    // check that there's only one valid parameter 
    if( (tcp == NULL && udp == NULL) || (tcp != NULL && udp != NULL) ) {
        printf("Database warning: one of the tcp or udp paramters must be valid, one must be NULL.\n");
        return -1;
    }

    char* src;
    char* dst;
    char* sql = NULL;
    int ipversion = -1;

    if(tcp == NULL) {
        honeyd_contoa_v2(&(udp->conhdr), &src, &dst);

        if(udp->addr_family == AF_INET)
            ipversion = 4;
        if(udp->addr_family == AF_INET6)
            ipversion = 6;
        
        asprintf(&sql, "INSERT INTO connection \
                (source, destination, af_inet_type, start_time, end_time, protocol, protocol_id) \
                VALUES (\"%s\", \"%s\", %d, %d, %d, %d, %d)", 
                src, dst, ipversion, udp->start_time, udp->end_time, DB_PROTO_UDP, protocol_id);

    } else {
        honeyd_contoa_v2(&(tcp->conhdr), &src, &dst);
       
        if(tcp->addr_family == AF_INET)
            ipversion = 4;
        if(tcp->addr_family == AF_INET6)
            ipversion = 6;
        
        asprintf(&sql, "INSERT INTO connection \
                (source, destination, af_inet_type, start_time, end_time, protocol, protocol_id) \
                VALUES (\"%s\", \"%s\", %d, %d, %d, %d, %d)", 
                src, dst, ipversion, tcp->start_time, tcp->end_time, DB_PROTO_TCP, protocol_id);

    }
    
    database_query(sql, NULL);

    free(src);
    free(dst);
    free(sql);

    return sqlite3_last_insert_rowid(sqlite_db);
#else
    DB_WARN
    return -1;
#endif
}

// writes the contents of the shellcode buffer 
// (more accurately <size> bytes from <buffer> to the datbase
// returns -1 on error and the id of the newly created entry on success.
int log_payload(char* buffer, int size) {
#ifdef USE_SQLITE3
    if(database_usedb == 0)
        return -1;

    printf("Im logging the payload!\n");
    sqlite3_stmt* statement;
    char* query; 
    asprintf(&query, "INSERT INTO payload (payload, state) VALUES (?, %d);", DB_PAYLOAD_STATE_ASSESSABLE);

    printf("there's a query here: %s\n", query);
    int retval = sqlite3_prepare_v2(sqlite_db, query, strlen(query) + 1, &statement, NULL);
    if(retval != SQLITE_OK) {
        printf("Database error: There was an error with sqlite_prepare_v2: %d\n", retval);
        sqlite3_finalize(statement);
        sqlite3_free(sqlite_db);
        exit(EXIT_FAILURE);
    }

    retval = sqlite3_bind_blob(statement, 1, buffer, size, NULL);
    if(retval != SQLITE_OK) {
        printf("Database error: There was an error with sqlite3_bind_blob: %d\n", retval);
        sqlite3_finalize(statement);
        sqlite3_free(sqlite_db);
        exit(EXIT_FAILURE);
    }

    while (1) {
        int retval = sqlite3_step(statement);
        if(retval == SQLITE_DONE)
            break;
        else 
            printf("Database info: still stepping while INSERTing the payload\n");
    }

    sqlite3_finalize(statement);
    return sqlite3_last_insert_rowid(sqlite_db);

#else
    DB_WARN
#endif
}

// performs the CREATE TABLE statements neccessary to correctly setup the database.
void database_create_tables() {
#ifdef USE_SQLITE3
    if (database_usedb == 0)
        return;

    // build a string that creates tables by using the statements defined in tables[]
    char* sql;
    asprintf(&sql, "BEGIN TRANSACTION; %s; %s; %s; %s; COMMIT TRANSACTION;", tables[0], tables[1], tables[2], tables[3]);
   
	//database_query(db, sql, NULL);
    int i;
    for (i = 0; i < ntables; i++) {
        asprintf(&sql, "%s;", tables[i]);
        database_query(sql, NULL);
        free(sql);
    }

#else
    DB_WARN
#endif
}

// thank you http://stackoverflow.com/questions/1601151/how-do-i-check-in-sqlite-whether-a-table-exists
// checks if the database is correct by:
//  - comparing the number of tables in the database with number of tables we defined.
//  - the string needed to create the tables with those reported by the db
//  returns 0 if everything is correct, -1 else.
int database_check_tables() { 
#ifdef USE_SQLITE3
    if(database_usedb == 0) 
        return -1;

    // query the number of tables present in the db
    char *query_num_tables = "SELECT COUNT(*) FROM sqlite_master WHERE type='table';";
    sqlite3_stmt* statement;

    int retval = sqlite3_prepare_v2(sqlite_db, query_num_tables, strlen(query_num_tables) + 1, &statement, NULL);
	if(statement == NULL) {
		printf("statement is null\n");
	}
    if(retval != SQLITE_OK) {
        printf("Database error: There was an error with the sqlite3_prepare (retval=%d)\n", retval );
        sqlite3_finalize(statement);
        sqlite3_free(sqlite_db);
        exit(EXIT_FAILURE);
    }

    // step through the result set -- only one row should be returned so there's no loop here
    if(sqlite3_step(statement) != SQLITE_ROW) {
        printf("Database error: Couldn't retrieve data with sqlite3_step\n");
        sqlite3_finalize(statement);
        sqlite3_free(sqlite_db);
        exit(EXIT_FAILURE);
    }

    // retrieve the value
    int ntables_in_db = sqlite3_column_int(statement, 0);
    if(ntables_in_db != ntables) {
        printf("Database warning: There's something wrong with the database (%s).\nIt should have %d tables, but there are %d.\n", database_filename, ntables, ntables_in_db);
        sqlite3_finalize(statement);
        return -1;
    }

    // query the create-table statements that were needed to create the db.
    sqlite3_finalize(statement);
    char* query_create_table_statements = "SELECT sql FROM sqlite_master WHERE type='table' ORDER BY name ASC;";

    retval = sqlite3_prepare_v2(sqlite_db, query_create_table_statements, strlen(query_create_table_statements) + 1, &statement, NULL);
    if(retval != SQLITE_OK || statement == NULL) {
        printf("Database error: There was an error with the sqlite3_prepare.\n");
        sqlite3_finalize(statement);
        sqlite3_free(sqlite_db);
        exit(EXIT_FAILURE);
    }

    // loop through the result set.
    int table_id=0;
    while(1) {
        int step_type = sqlite3_step(statement);
        if(step_type == SQLITE_ROW) {
            
            // check if the table definitions and the structure in the db match.
            if(strncmp(sqlite3_column_text(statement,0), tables[table_id], strlen(tables[table_id])) != 0) {
                printf("Database warning: There's something wrong with the database (%s):\nTable #%d does not match the correct format.\nI've expected: %s\nBut found: %s\n", database_filename, table_id, tables[table_id], sqlite3_column_text(statement, 0));

                return -1;
            }

            table_id++;

        } else if (step_type == SQLITE_DONE) {
            break;
        } else {
            printf("Database error: Couldn't step through the results.\n");
            sqlite3_finalize(statement);
            sqlite3_free(sqlite_db);
            exit(EXIT_FAILURE);
        }
    }

    printf("Database info: The tables in the database are correct.\n");
    
    sqlite3_finalize(statement);
    return 0;
#else
    DB_WARN
#endif
}

// deletes the database file specified by filename.
// asks the user, they have to choose [y/n]
// will remove the file from the harddisk.
int database_delete_database(char* filename) {
#ifdef USE_SQLITE3
    if(database_usedb == 0)
        return -1;

    char choice = 'U';
    
    while(1) {
        if(isalnum(choice))
            printf("Database warning: Re-create database file? Note: This will delete EVERYTHING from the database file %s [Y/N]: ", filename);

        choice = fgetc(stdin);

        if(choice == 'Y' || choice == 'N' || choice == 'y' || choice == 'n')
            break;
    }
    
    if(choice == 'Y' || choice == 'y') {
        database_close();
        int retval = remove(filename);
        if(retval != 0) {
            perror("Database error: Couldn't delete the database file");
            return -1;
        }
        return 0;

    } else {
        printf("Database info: Nothing was deleted.\n");
        return -1;
    }
#else
    DB_WARN
#endif

}

// sets the database filename - callback function for the config-file parser.
void database_set_dbfile(char* file) {
    if (file != NULL) {
        database_filename = file;
        database_usedb = 1;
    }
}

// sets the directory for where to put the shellcodes
void database_set_shellcodedir(char* path) {

    if(path == NULL) {
        printf("error parsing shellcodedir path.\n");
        exit(EXIT_FAILURE);
    }

    // remove trailing slash
    if(path[strlen(path) - 1] == '/')
        path[strlen(path) - 1] = '\0';

    database_shellcodedir = path;
    database_shellcode_detection = 1;
}


// opens the database, retrieves all ASSESSABLE payloads and 
// checks them one by one.
// Will mark them as being INTERESTING or BORING.
void database_assess_payloads() {
#ifdef USE_SQLITE3
    if(database_usedb == 0)
        return;

    // query the DB for all ASSESSABLE payloads
    char *sql;
    asprintf(&sql, "SELECT id, payload FROM payload WHERE state = %d;", DB_PAYLOAD_STATE_ASSESSABLE);

    // BEGIN CRITICAL SECTION - copy entries from the database into memory
    pthread_mutex_lock(&mutex);
    #ifdef VERBOSE_PTHREADS
    printf("Database info [ASSESS]: Fetching assessable payloads. Aquired database lock.\n");
    int assessable_counter = 0;
    #endif

    sqlite3_stmt* statement;
    int retval = sqlite3_prepare_v2(sqlite_db, sql, strlen(sql) + 1, &statement, NULL);
    if(retval != SQLITE_OK) {
        printf("Error in sqlite3_prepare_v2 at line %d: %d\n", __LINE__, retval);        
        sqlite3_finalize(statement);
        sqlite3_free(sqlite_db);
        exit(EXIT_FAILURE);
    }

    // loop through the results
    while(1) {
    
        int step_type = sqlite3_step(statement);
        if(step_type == SQLITE_ROW) {
        
            // move the info from the database into memory.
            
            // allocate sapce
            struct shellcode* entry;
            entry = calloc(1, sizeof(struct shellcode));
            if(entry == NULL) {
                printf("Error mallocing memory for temp shellcode buffer thing.\n");
                sqlite3_finalize(statement);
                sqlite3_free(sqlite_db);
                exit(EXIT_FAILURE);
            }

            // get data from database
            int length = sqlite3_column_bytes(statement, 1);
            int id = sqlite3_column_int(statement, 0);
            char* result = sqlite3_column_blob(statement, 1);
   
            entry->buf = calloc(length, sizeof(char));
            if( (entry->buf) == NULL) {
                printf("Couldn't malloc memory for the shellcode buffer\n");
                exit(EXIT_FAILURE);
            }
            if( (memcpy(entry->buf, result, length)) == NULL) {
                printf("Error memcpy-ing\n");
                exit(EXIT_FAILURE);
            }
            
            entry->database_id = id;
            entry->size = length;
            entry->state = DB_PAYLOAD_STATE_ASSESSABLE;
           
            // insert them into the temp queue
            TAILQ_INSERT_TAIL(&shellcode_assessment_queue, entry, entries);
            #ifdef VERBOSE_PTHREADS
            assessable_counter++;
            #endif

        } else if(step_type == SQLITE_DONE) {
            break;
        } else {
            // some error
            printf("Some error stepping through the result set: %d\n", step_type);
            sqlite3_finalize(statement);
            sqlite3_free(sqlite_db);
            exit(EXIT_FAILURE);
        }
    }
    #ifdef VERBOSE_PTHREADS
    printf("Database info [ASSESS]: Found %d assessable payloads. Releasing database lock\n", assessable_counter);
    int current_counter = 0;
    #endif

    sqlite3_finalize(statement);
    pthread_mutex_unlock(&mutex);
    // END CRITICIAL SECTION - now that everything lives in memory, do some work on it

    // loop over all items in the queue
    struct shellcode* tmp;
    TAILQ_FOREACH(tmp, &shellcode_assessment_queue, entries) {

        // wrapper for libemu's getpc_check, set the state accordingly
        if(shellcode_test(tmp->buf, tmp->size) >= 0) {
            tmp->state = DB_PAYLOAD_STATE_INTERESTING;

        } else {
            tmp->state = DB_PAYLOAD_STATE_BORING;
        }
        #ifdef VERBOSE_PTHREADS
        current_counter++;
        printf("Database info [ASSESS]: Progress assessing payloads: %d of %d\n", current_counter, assessable_counter);
        #endif
    }


    // BEGIN CRITICAL SECTION - the work is done, we write information back to the database
    pthread_mutex_lock(&mutex);
    
    #ifdef VERBOSE_PTHREADS
    printf("Database info [ASSESS]: Done assessing %d payloads, now updating the database. Aquired database lock\n", assessable_counter);
    current_counter = 0;
    #endif

    // prepare the update statement - this will update the state of all the items in the queue
    char* update_sql = "UPDATE payload SET state=? WHERE id=?;";
    sqlite3_stmt* update_statement;

    retval = sqlite3_prepare_v2(sqlite_db, update_sql, strlen(update_sql) +1, &update_statement, NULL);
    if(retval != SQLITE_OK) {
        printf("Error preparing at line %d: %d\n", __LINE__, retval);
        sqlite3_finalize(update_statement);
        sqlite3_free(sqlite_db);
        exit(EXIT_FAILURE);
    }

    TAILQ_FOREACH(tmp, &shellcode_assessment_queue, entries) {
        // fill the missing numbers in the sql query
        sqlite3_bind_int(update_statement, 1, tmp->state);
        sqlite3_bind_int(update_statement, 2, tmp->database_id);

        int step_type;
        step_type = sqlite3_step(update_statement);
        if( step_type != SQLITE_DONE) {
            printf("Error: stepping through the UPDATE statement wasn't SQLITE_DONE but was %d\n", step_type);
        }
        sqlite3_reset(update_statement);
        #ifdef VERBOSE_PTHREADS
        current_counter++;
        printf("Database info [ASSESS]: Progress updateing assessed payloads: %d of %d\n", current_counter, assessable_counter);
        #endif
    }

    #ifdef VERBOSE_PTHREADS
    printf("Database info [ASSESS]: Done updating %d assessed payloads. Releasing database lock\n", assessable_counter);
    #endif

    sqlite3_finalize(update_statement);
    pthread_mutex_unlock(&mutex);
    // CRITICAL SECTION DONE -- everything is back in the database, remove the in-memory entries
    
   
    // remove all the entries from the queue
    struct shellcode* entry;
    while (entry = TAILQ_FIRST(&shellcode_assessment_queue)) {
                TAILQ_REMOVE(&shellcode_assessment_queue, entry, entries);
                free(entry->buf);
                free(entry);
    }

#else
    DB_WARN
#endif
}

// Fetch payloads marked as INTERESTING from the database and
// convert them with shellcode_convert, one by one.
void database_build_executables() {
#ifdef USE_SQLITE3
    if(database_usedb == 0 || database_shellcode_detection == 0)
        return;

    // BEGIN CRITICAL SECTION -- get interesting entries from the database to memory
    pthread_mutex_lock(&mutex);
    
    #ifdef VERBOSE_PTHREADS
    printf("Database info [BUILD]: Fetching payloads to build executables for. Aquired database lock\n");
    int build_exec_counter = 0;
    #endif

    // query the DB for all INTERESTING payloads
    char *sql;
    asprintf(&sql, "SELECT id, payload FROM payload WHERE state = %d;", DB_PAYLOAD_STATE_INTERESTING);

    sqlite3_stmt* statement;
    int retval = sqlite3_prepare_v2(sqlite_db, sql, strlen(sql) + 1, &statement, NULL);
    if(retval != SQLITE_OK) {
        printf("Error in sqlite3_prepare_v2 at line %d: %d\n", __LINE__, retval);        
        sqlite3_finalize(statement);
        sqlite3_free(sqlite_db);
        exit(EXIT_FAILURE);
    }

    // loop through the results
    while(1) {
    
        int step_type = sqlite3_step(statement);
        if(step_type == SQLITE_ROW) {
        
            // move the info from the database into memory.
            
            // allocate sapce
            struct shellcode* entry;
            entry = calloc(1, sizeof(struct shellcode));
            if(entry == NULL) {
                printf("Error mallocing memory for temp shellcode buffer thing.\n");
                sqlite3_finalize(statement);
                sqlite3_free(sqlite_db);
                exit(EXIT_FAILURE);
            }

            // get data from database
            int length = sqlite3_column_bytes(statement, 1);
            int id = sqlite3_column_int(statement, 0);
            char* result = sqlite3_column_blob(statement, 1);
   
            entry->buf = calloc(length, sizeof(char));
            if( (entry->buf) == NULL) {
                printf("Couldn't malloc memory for the shellcode buffer\n");
                exit(EXIT_FAILURE);
            }
            if( (memcpy(entry->buf, result, length)) == NULL) {
                printf("Error memcpy-ing\n");
                exit(EXIT_FAILURE);
            }
           
            entry->size = length;
            entry->database_id = id;
   
            // insert them into the temp queue
            TAILQ_INSERT_TAIL(&shellcode_build_queue, entry, entries);
            #ifdef VERBOSE_PTHREADS
            build_exec_counter++;
            #endif

        } else if(step_type == SQLITE_DONE) {
            break;
        } else {
            // some error
            printf("Some error stepping through the result set: %d\n", step_type);
            sqlite3_finalize(statement);
            sqlite3_free(sqlite_db);
            exit(EXIT_FAILURE);
        }
        
    }
    #ifdef VERBOSE_PTHREADS
    printf("Database info [BUILD]: Found %d payloads to build executables for. Releasing database lock\n", build_exec_counter);
    int current_counter = 0;
    #endif

    sqlite3_finalize(statement);
    pthread_mutex_unlock(&mutex);
    // CRITICAL SECTION END -- now that everything is in memory, do some work on it.


    // loop over all items in the queue
    struct shellcode* tmp;
    TAILQ_FOREACH(tmp, &shellcode_build_queue, entries) {

        tmp->filename = shellcode_convert(tmp->buf, tmp->size);
        #ifdef VERBOSE_PTHREADS
        current_counter++;
        printf("Database info [BUILD]: Progress building executables: %d of %d\n", current_counter, build_exec_counter); 
        #endif
    }

    // CRITICIAL SECTION START -- our work is done and we must propagate the changes back to the database
    pthread_mutex_lock(&mutex);
    #ifdef VERBOSE_PTHREADS
    printf("Database info [BUILD]: Done building %d executables, now updating the database. Aquired database lock.\n", build_exec_counter);
    current_counter = 0;
    #endif

    // prepare the update statement - this will update the state of all the items in the queue
    char* update_sql = "UPDATE payload SET state=?, filename=? WHERE id=?;";
    sqlite3_stmt* update_statement;

    retval = sqlite3_prepare_v2(sqlite_db, update_sql, strlen(update_sql) +1, &update_statement, NULL);
    if(retval != SQLITE_OK) {
        printf("Error preparing at line %d: %d\n", __LINE__, retval);
        sqlite3_finalize(update_statement);
        sqlite3_free(sqlite_db);
        exit(EXIT_FAILURE);
    }

    // loop over all items in the queue
    TAILQ_FOREACH(tmp, &shellcode_build_queue, entries) {

        sqlite3_bind_int(update_statement, 3, tmp->database_id);
        
        if(tmp->filename == NULL) {
            sqlite3_bind_int(update_statement, 1, DB_PAYLOAD_STATE_ERROR);
            sqlite3_bind_null(update_statement, 2);
        } else {
            sqlite3_bind_int(update_statement, 1, DB_PAYLOAD_STATE_SUBMITTABLE);
            sqlite3_bind_text(update_statement, 2, tmp->filename, -1, SQLITE_STATIC);
        }

        int step_type;
        step_type = sqlite3_step(update_statement);
        if(step_type != SQLITE_DONE) {
            printf("Error: stepping through the UPDATE statement wasn't SQLITE_DONE but was %d\n", step_type);
        }

        sqlite3_reset(update_statement);
        #ifdef VERBOSE_PTHREADS
        current_counter++;
        printf("Database info [BUILD]: Progress updating executables: %d of %d\n", current_counter, build_exec_counter);
        #endif
    }

    #ifdef VERBOSE_PTHREADS
    printf("Database info [BUILD]: Done updating %d executables. Releasing database lock\n", build_exec_counter);    
    #endif
    sqlite3_finalize(update_statement);
    pthread_mutex_unlock(&mutex);
    // CRITICIAL SECTION END -- everything is back in the database, now delete the in-memory entries.

    // remove all the entries from the queue
    struct shellcode* entry;
    while (entry = TAILQ_FIRST(&shellcode_build_queue)) {
                TAILQ_REMOVE(&shellcode_build_queue, entry, entries);
                free(entry->buf);
                free(entry);
    }

#else
    DB_WARN
#endif
}


// will submit payloads to $YOUR-PAYLOAD-ANALYZER-OF-CHOICE (currently anubis)
// (define others in submission.c) and update the report_url field in the database
void database_submit_payloads() {
#ifdef USE_SQLITE3
    if(database_usedb == 0)
        return;

    // query the DB for all SUBMITTABLE payloads
    char *sql;
    asprintf(&sql, "SELECT id, filename FROM payload WHERE state = %d;", DB_PAYLOAD_STATE_SUBMITTABLE);

    // CRITICIAL SECTION START -- get all the submittable entries from the database
    pthread_mutex_lock(&mutex);
    #ifdef VERBOSE_PTHREADS
    printf("Database info [SUBMIT]: Fetching payloads for submission. Aquired database lock\n");
    int submission_counter = 0;
    #endif

    sqlite3_stmt* statement;
    int retval = sqlite3_prepare_v2(sqlite_db, sql, strlen(sql) + 1, &statement, NULL);
    if(retval != SQLITE_OK) {
        printf("Error in sqlite3_prepare_v2 at line %d: %d\n", __LINE__, retval);        
        sqlite3_finalize(statement);
        sqlite3_free(sqlite_db);
        exit(EXIT_FAILURE);
    }

    // loop through the results
    while(1) {
    
        int step_type = sqlite3_step(statement);
        if(step_type == SQLITE_ROW) {
        
            // move the info from the database into memory.
            
            // allocate sapce
            struct shellcode* entry;
            entry = calloc(1, sizeof(struct shellcode));
            if(entry == NULL) {
                printf("Error mallocing memory for temp shellcode buffer thing.\n");
                sqlite3_finalize(statement);
                sqlite3_free(sqlite_db);
                exit(EXIT_FAILURE);
            }

            // get data from database
            int length = sqlite3_column_bytes(statement, 1);
            int id = sqlite3_column_int(statement, 0);
            char* result = sqlite3_column_text(statement, 1);
   
            entry->filename = calloc(length, sizeof(char));
            if( (entry->filename) == NULL) {
                printf("Couldn't malloc memory for the shellcode buffer\n");
                exit(EXIT_FAILURE);
            }
            if( (memcpy(entry->filename, result, length)) == NULL) {
                printf("Error memcpy-ing\n");
                exit(EXIT_FAILURE);
            }
            
            entry->database_id = id;
   
            // insert them into the temp queue
            TAILQ_INSERT_TAIL(&shellcode_submission_queue, entry, entries);
            #ifdef VERBOSE_PTHREADS
            submission_counter++;
            #endif

        } else if(step_type == SQLITE_DONE) {
            break;
        } else {
            // some error
            printf("Some error stepping through the result set: %d\n", step_type);
            sqlite3_finalize(statement);
            sqlite3_free(sqlite_db);
            exit(EXIT_FAILURE);
        }
    }
    #ifdef VERBOSE_PTHREADS
    printf("Database info [SUBMIT]: Found %d executables to submit. Releasing database lock.\n", submission_counter);
    int current_counter = 0;
    #endif

    sqlite3_finalize(statement);
    pthread_mutex_unlock(&mutex);
    // CRITICIAL SECTION END -- now that everything is in memory we can do some work on it.
    
    // loop over all items in the queue
    struct shellcode* tmp;
    TAILQ_FOREACH(tmp, &shellcode_submission_queue, entries) {

        // build the absolute filepath
        char* filepath;
        if(asprintf(&filepath, "%s/%s/shellcode.exe", database_shellcodedir, tmp->filename) == NULL ) {
            printf("shellcode error: couldn't asprintf into the filepath string\n");    
            free(filepath);
            return NULL;
        }

        // check if that file is accessible
        struct stat st;
        if(stat(filepath, &st) != 0) {
            printf("database error: database claims %s is a shellcode but I couldn't access it\n", filepath);

            tmp->state = DB_PAYLOAD_STATE_ERROR;

        }  else {
            // upload it to the selected service
            submission_submit(filepath);
            tmp->report_url = submission_current_url();
            
            if(tmp->report_url == NULL) {
                tmp->state = DB_PAYLOAD_STATE_ERROR;
               
            } else {
                tmp->state = DB_PAYLOAD_STATE_SUBMITTED;
            }
        }
        #ifdef VERBOSE_PTHREADS
        current_counter++;
        printf("Database info [SUBMIT]: Progress submitting payloads: %d of %d\n", current_counter, submission_counter);
        #endif
    }

    // CRITICAL SECTION START -- now that the work is done we need to propagate this stuff back to the database
    pthread_mutex_lock(&mutex);
    #ifdef VERBOSE_PTHREADS
    printf("Database info [SUBMIT]: Done submitting %d payloads, now updating the database. Aquired database lock\n", submission_counter);
    current_counter = 0;
    #endif

    // prepare the update statement - this will update the state of all the items in the queue
    char* update_sql = "UPDATE payload SET report_url=?, state=? WHERE id=?;";
    sqlite3_stmt* update_statement;

    retval = sqlite3_prepare_v2(sqlite_db, update_sql, strlen(update_sql) +1, &update_statement, NULL);
    if(retval != SQLITE_OK) {
        printf("Error preparing at line %d: %d\n", __LINE__, retval);
        sqlite3_finalize(update_statement);
        sqlite3_free(sqlite_db);
        exit(EXIT_FAILURE);
    }

    // loop over all items in the queue
    TAILQ_FOREACH(tmp, &shellcode_submission_queue, entries) {

        sqlite3_bind_int(update_statement, 3, tmp->database_id);

        if(tmp->state == DB_PAYLOAD_STATE_ERROR) {
            sqlite3_bind_null(update_statement, 1); 
            sqlite3_bind_int(update_statement, 2, DB_PAYLOAD_STATE_ERROR);
        } else {
            sqlite3_bind_text(update_statement, 1, tmp->report_url, -1, SQLITE_STATIC);
            sqlite3_bind_int(update_statement, 2, DB_PAYLOAD_STATE_SUBMITTED);
        }

        int step_type;
        step_type = sqlite3_step(update_statement);
        if(step_type != SQLITE_DONE) {
            printf("Error: Stepping through the UPDATE statement wasn't SQLITE_OK but was %d\n", step_type);
        }
        
        sqlite3_reset(update_statement);
        #ifdef VERBOSE_PTHREADS
        current_counter++;
        printf("Database info [SUBMIT]: Progress updating submitted payloads: %d of %d\n", current_counter, submission_counter);
        #endif
    }
    #ifdef VERBOSE_PTHREADS
    printf("Database info [SUBMIT]: Done updating %d submitted payloads. Releasing database lock\n", submission_counter);
    #endif
    sqlite3_finalize(update_statement);
    pthread_mutex_unlock(&mutex);
    // CRITICAL SECTION END -- everything is back at the database. now delete the in-memory entries.

    //remove all the entries from the queue
    struct shellcode* entry;
    while (entry = TAILQ_FIRST(&shellcode_submission_queue)) {
                TAILQ_REMOVE(&shellcode_submission_queue, entry, entries);
                free(entry->buf);
                free(entry);
    }

    free(sql);
#else
    DB_WARN
#endif

}

// a stupid trigger function to be used by a pthread. port to using libevent soon. Real soon.
void* database_stupidly_trigger_assessment() {
#ifdef USE_SQLITE3
    if(database_usedb == 0 || database_shellcode_detection == 0)
        return NULL;


    while(1) {
        sleep(DB_STUPIDLY_TRIGGER_SLEEP_SECS);
        database_assess_payloads(sqlite_db);
    }
    printf("Assessment Thread quitting\n");
#else
    DB_WARN
#endif
}

// a stupid trigger function to be used by a pthread. port to using libevent soon. Real soon (tm).
void* database_stupidly_trigger_conversion() {
#ifdef USE_SQLITE3
    if(database_usedb == 0 || database_shellcode_detection == 0)
        return NULL;


    while(1) {
        sleep(DB_STUPIDLY_TRIGGER_SLEEP_SECS);
        database_build_executables(sqlite_db);
    }
    printf("Conversion Thread quitting\n");
#else
    DB_WARN
#endif
}

void* database_stupidly_trigger_submission() {
#ifdef USE_SQLITE3
    if(database_usedb == 0 || database_shellcode_detection == 0 || submission_do_submission == 0)
        return NULL;

    while(1) {
        sleep(DB_STUPIDLY_TRIGGER_SLEEP_SECS);
        database_submit_payloads(sqlite_db);
    }
    printf("Submission Thread quitting\n");
#else
    DB_WARN
#endif

}
