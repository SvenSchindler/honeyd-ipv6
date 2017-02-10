#ifndef _HIHMANAGER_H_
#define _HIHMANAGER_H_

#include <libvirt/libvirt.h>
#include "config.h"
#include <dnet.h>
#include <sys/tree.h>
#include <sys/queue.h>
#include <event.h>
#include <sys/tree.h>
#include "honeyd.h"
#include <time.h>

#define HIH_POOL_SIZE 1
#define HIH_BACKUP_AND_REMOVE_TIMEOUT 3600

enum hih_status
{
 	HIH_AVAILABLE, HIH_IN_USE, HIH_BOOTING
};


typedef struct hih_pool_entry
{
	virDomainPtr domain;
	char *xml_configuration;
	char *path_to_hd_image;
	int vnc_port;
	struct addr mac_address;
	struct addr real_addr;
	struct addr addr_expected_by_attacker;
	enum hih_status hih_status;
	struct event backup_and_remove_timeout;
	struct event hd_preparation_finished;
	SPLAY_HEAD(attackers, attacker) assigned_attackers;
} hih_pool_entry_t;

struct hd_initialization_params {
	hih_pool_entry_t *hih_pool_entry;
	char *original_hd_image_path;
	char *new_hd_image_path;
};


struct hih {
	SPLAY_ENTRY(hih) node;
	char *id;
	char *configuration_filename;
	hih_pool_entry_t honeypot_pool[HIH_POOL_SIZE];
};

// copied from https://github.com/rampantpixels/foundation_lib/blob/master/foundation/uuid.c
typedef struct
{
	uint32_t data1;
	uint16_t data2;
	uint16_t data3;
	uint8_t data4[8];
} uuid_raw_t;


struct attacker {
	SPLAY_ENTRY(attacker) node;
	struct addr src_addr;
};

struct backup_params {
	struct hih *hih;
	int pool_index;
};


void hihmanager_init(void);
void hihmanager_startup_hihs(int initialize_with_hihs);
void define_hih(char *hih_id, char *configuration_filename);
struct addr * get_hih_addr_for_attacker(struct tuple * hdr, char *hih_id);
char *load_config_and_get_image_path_for_hih(char *config);
char *get_hd_image_path_from_config(char *config);
void start_hih_ip_config_server(void);
char *set_mac_address_in_configuration(char *configuration, char *mac_address);
char *set_hd_image_path_in_config(char *src_config, char* new_path);
void hihmanager_test(void);
void initialize_machine_pool();
virDomainPtr startup_hih(hih_pool_entry_t * pool_entry);
void initialize_single_hih_pool_entry(struct hih *hih,int pool_index);
void set_send_syn_until_success_timeout(struct tcp_con * hih_con);
void hihmanager_run_integration_test(void);
void bind_lih_connection_to_transparent_hih_connection(struct tcp_con *con, struct addr *hih_addr);
struct timespec print_precise_time(struct timespec *);
int is_exising_hih_available(struct tuple *hdr,char *hih_id);
void bind_lih_connection_to_existing_hih(struct tcp_con *lih_con); 
#endif
