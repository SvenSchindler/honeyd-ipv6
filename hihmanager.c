
#include <stddef.h>
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dumbnet.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/tree.h>
#include <sys/queue.h>
#include <event.h>
#include <pcap.h>
#include <syslog.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "honeyd.h"
#include "hihmanager.h"
#include "template.h"
#include "interface.h"
#include "icmp6.h"
#include "tcp.h"
#include "shellcode.h"
#include <time.h>
#include <errno.h>

#define MAX_HD_IMAGE_POSTFIX_LEN 10
#define MAX_NUMBER_OF_STORED_IMAGES 100
#define UUID_STR_LEN 38
#define VNC_PORT_STR_LEN 6

/* not published in honeyd.h */
struct action *honeyd_protocol(struct template *, int);

SPLAY_HEAD(hihs, hih) hihs;

/* initialized in honeyd manager init */
struct addr ethernet_addr_for_hih;

int hd_image_counter = 0;
int uuid_counter = 1;
int vnc_port_counter = 1200;

static int startup_hihs;

static int skip_hd_image_copy = 0;

virConnectPtr virt_connection = NULL;

struct timespec print_precise_time(struct timespec *lastTime) {
	struct timespec t;
	double elapsed;
	clock_gettime(CLOCK_REALTIME, &t);
	if (lastTime == NULL) {
		//XXX cleanup
	} else {
		elapsed = (t.tv_sec - lastTime->tv_sec);
		elapsed += (t.tv_nsec - lastTime->tv_nsec) / 1000000000.0;
	}
	return t;
}

int attacker_compare(struct attacker *a, struct attacker *b)
{
    return addr_cmp(&a->src_addr, &b->src_addr);
}
SPLAY_PROTOTYPE(attackers, attacker, node, attacker_compare);
SPLAY_GENERATE(attackers, attacker, node, attacker_compare);



int hih_compare(struct hih *a, struct hih *b)
{
    return strcmp(a->id, b->id);
}
SPLAY_PROTOTYPE(hihs, hih, node, hih_compare);
SPLAY_GENERATE(hihs, hih, node, hih_compare);


void define_hih(char *hih_id, char *configuration_filename)
{
	struct hih *hih;
	hih = (struct hih*)calloc(1,sizeof(struct hih));
	if (hih == NULL)
	{
		syslog(LOG_DEBUG,"ERROR: could not allocate memory for high interaction honeypot");
		return;
	}

	hih->id = hih_id;
	hih->configuration_filename=configuration_filename;
	SPLAY_INSERT(hihs,&hihs,hih);
}

struct addr compute_new_ethernet_address(void)
{
	u_int32_t *last_four_bytes = (u_int32_t *)&ethernet_addr_for_hih.addr_data8[2];
	u_int32_t last_four_bytes_host_order = ntohl(*last_four_bytes);
	last_four_bytes_host_order++;
	*last_four_bytes=htonl(last_four_bytes_host_order);
	return ethernet_addr_for_hih;
}

void startup_pool_hih_if_startup_is_enabled(hih_pool_entry_t *pool_entry)
{
	if (startup_hihs)
	{
		startup_hih(pool_entry);
	}
	else
	{
		syslog(LOG_DEBUG, "WARNING: honeyd started without -H option, skipping hih creation");
	}
}

long get_file_length(FILE *file)
{
	long file_size = -1;
	fseek(file, 0, SEEK_END);
	file_size = ftell(file);
	rewind(file);
	return file_size;
}

char * load_machine_config(char *filename)
{
	FILE *config_file;
	long config_file_length;
	char *config_file_content = NULL;
	config_file = fopen(filename, "r");
	if (config_file != NULL)
	{
		config_file_length = get_file_length(config_file);
		config_file_content = (char *) calloc(sizeof(char), config_file_length + 1);
		fread(config_file_content, 1, config_file_length, config_file);
		config_file_content[config_file_length] = 0x0;
		fclose(config_file);
	}
	return config_file_content;

}


char *compute_new_hd_image_path(char *configuration)
{
	if (hd_image_counter > MAX_NUMBER_OF_STORED_IMAGES)
	{
		syslog(LOG_DEBUG,"WARNING: reached maximum number allowed image backups, no new image path will be computed");
		return NULL;
	}

	char *result = NULL;
	char *original_hd_image_path = get_hd_image_path_from_config(configuration);

	if (original_hd_image_path == NULL)
	{
		return NULL;
	}

	result = (char *)calloc(1,strlen(original_hd_image_path) + MAX_HD_IMAGE_POSTFIX_LEN);
	if (result == NULL)
	{
		syslog(LOG_DEBUG,"ERROR: could not allocate memory for new hd image path");
		return NULL;
	}

	strcpy(result,original_hd_image_path);
	sprintf(result+strlen(original_hd_image_path),".%d",hd_image_counter);
	hd_image_counter++;
	return result;
}

void *prepare_hih_hd_image_and_start_hih(void *params)
{
	struct hd_initialization_params *initialization_params = (struct hd_initialization_params*)params;
	int status = 0;
	if (initialization_params->new_hd_image_path != NULL && skip_hd_image_copy==0)
	{
		pid_t pid = fork(), wpid = -1;
		if (pid < 0)
		{
			syslog(LOG_DEBUG, "ERROR: could not fork process to create new image copy");
			return NULL;
		}
		if (pid == 0)
		{
			/* child does the copy */
			execl("/bin/cp", "/bin/cp", initialization_params->original_hd_image_path, initialization_params->new_hd_image_path, (char *) 0);
		}
		else
		{
			syslog(LOG_DEBUG, "INFO: waiting for copy operation to finish, time: %u",(unsigned)time(NULL));
			struct timespec l = print_precise_time(NULL);
			waitpid(pid, &status, 0);
			initialization_params->hih_pool_entry->path_to_hd_image = (char *) calloc(1,strlen(initialization_params->new_hd_image_path) + 1);
			strcpy(initialization_params->hih_pool_entry->path_to_hd_image, initialization_params->new_hd_image_path);
			initialization_params->hih_pool_entry->path_to_hd_image[strlen(initialization_params->new_hd_image_path)]='\0';
			
			print_precise_time(&l);

			startup_pool_hih_if_startup_is_enabled(initialization_params->hih_pool_entry);
			free(params);
		}

	}

	return NULL;

}

void free_if_not_null(void *value)
{
	if (value != NULL)
	{
		free(value);
	}
}



int connect_to_virt(void)
{
	virt_connection = virConnectOpen("qemu:///system");
	if (virt_connection == NULL)
	{
		fprintf(stderr, "Failed to open connection to qemu:///system\n");
		return 1;
	}
	return 0;
}

char *load_config_and_get_image_path_for_hih(char *configuration_filename)
{
	char *xmlconfig = load_machine_config(configuration_filename);
	char *result = NULL;
	if (xmlconfig != NULL)
	{
		result = get_hd_image_path_from_config(xmlconfig);
		free(xmlconfig);
		return result;
	}
	else
	{
		return NULL;
	}
}


void disconnect_from_virt(void)
{
	if (virt_connection != NULL)
	{
		virConnectClose(virt_connection);
	}
}


void hihmanager_startup_hihs(int initialize_with_hihs)
{
	startup_hihs = initialize_with_hihs;
	start_hih_ip_config_server();
	connect_to_virt();
	initialize_machine_pool();
}


void hihmanager_init(void)
{
	SPLAY_INIT(&hihs);
	addr_aton("52:54:00:d5:78:97",&ethernet_addr_for_hih);
}




virDomainPtr startup_hih(hih_pool_entry_t * pool_entry)
{
	virDomainPtr dom;

	dom = virDomainCreateXML(virt_connection, pool_entry->xml_configuration, 0);

	if (!dom)
	{
		syslog(LOG_DEBUG, "ERROR: startup_hih: High interaction honeypot creation failed, config: \n%s\n",pool_entry->xml_configuration);
		return NULL;
	}

	pool_entry->domain = dom;
	syslog(LOG_DEBUG, "INFO: high interaction honeypot %s with vnc port %d is booting, time: %u\n", virDomainGetName(dom),pool_entry->vnc_port,(unsigned)time(NULL));
	print_precise_time(NULL);
	return dom;
}

void free_hih(virDomainPtr dom)
{
	virDomainFree(dom);
}

void configure_ip_address_of_hih(struct addr *mac_addr_of_hih, struct addr *new_ipv6_addr)
{
	int i;
	char *new_ip_str = addr_ntoa(new_ipv6_addr);
	struct hih *hih;
	hih_pool_entry_t *pool_entry = NULL;
	int found_hih = 0;
	//get pool entry for hih
	SPLAY_FOREACH(hih,hihs,&hihs)
		{
			for (i = 0; i < HIH_POOL_SIZE; i++)
			{
				//use str comp in order to avoid comparison failures because of different network size or so
				if (strcmp(addr_ntoa(&hih->honeypot_pool[i].mac_address),addr_ntoa(mac_addr_of_hih)) == 0)
				{
					found_hih = 1;
					pool_entry = &hih->honeypot_pool[i];
					break;
				}
			}
		}
	
	if (!startup_hihs) {
		addr_aton("2001:db8:10::5254:00ff:fed5:7898",&pool_entry->real_addr);
	}
	
	if (!found_hih) {
		syslog(LOG_DEBUG, "WARNING: could not find a hih with mac addr %s",addr_ntoa(mac_addr_of_hih));
		return;
	} else {
		syslog(LOG_DEBUG, "INFO: found hih with ipv6 addr %s",addr_ntoa(&pool_entry->real_addr));
	}
	
	/* connect to machine using initial ip and send new ip as string */
	int sockfd;
	struct sockaddr_in6 dest;
	if ((sockfd = socket(AF_INET6, SOCK_STREAM, 0)) < 0)
	{
		syslog(LOG_DEBUG, "ERROR: could not create socket for hih address configuration");
		return;
	}
	memset(&dest, 0, sizeof(dest));
	dest.sin6_family = AF_INET6;
	dest.sin6_port = htons(50000);

	inet_pton(AF_INET6, addr_ntoa(&pool_entry->real_addr) , &(dest.sin6_addr));
	if (connect(sockfd, (struct sockaddr*) &dest, sizeof(dest)) != 0)
	{
		syslog(LOG_DEBUG, "ERROR: could not connect to hih");
		return;
	}

	send(sockfd, new_ip_str, strlen(new_ip_str), 0);

	close(sockfd);
	pool_entry->real_addr = *new_ipv6_addr;
	syslog(LOG_DEBUG, "INFO: updating hih address to %s",addr_ntoa(&pool_entry->real_addr));

}

int is_attacker_assigned_to_hih(struct hih *hih, int pool_index,struct addr *attacker_addr)
{
	struct attacker tmp;
	tmp.src_addr=*attacker_addr;
	if (SPLAY_FIND(attackers,&hih->honeypot_pool[pool_index].assigned_attackers,&tmp) != NULL) {
		return 1;
	}
	return 0;
}

int assign_attacker_to_hih(struct hih *hih,int pool_index, struct addr *attacker_src)
{
	if (is_attacker_assigned_to_hih(hih,pool_index,attacker_src))
	{
		return 1;
	}
	/* assign attacker to machine */
	struct attacker *attacker = calloc(1,sizeof(struct attacker));
	if (attacker == NULL)
	{
		syslog(LOG_DEBUG,"could not allocate memory attacker assignement to hih");
		return 0;
	}
	attacker->src_addr = *attacker_src;
	SPLAY_INSERT(attackers, &hih->honeypot_pool[pool_index].assigned_attackers, attacker);
	return 1;
}

char *extract_string_from_quotes(char *string)
{
	char *string_copy = (char*)calloc(1,strlen(string)+1);
	char *string_end;
	char *result;
	strcpy(string_copy,string);
	result = index(string_copy, '\'') + 1;
	string_end = index(result, '\'');
	string_end[0] = '\0';
	return result;
}

char *get_hd_image_path_from_config(char *config)
{
	int is_disk_section = 0;
	int config_length = strlen(config) + 1;
	char *config_copy = calloc(1,config_length);
	strcpy(config_copy, config);
	char *line = NULL, *result = NULL;
	if (config_copy == NULL)
	{
		return NULL;
	}

	line = strtok(config_copy, "\n");
	while (line != NULL)
	{
		if (is_disk_section)
		{
			if (strstr(line,"file=")!= NULL){
				result = extract_string_from_quotes(line);
				is_disk_section = 0;
			}
		}

		if (strstr(line, "disk") != NULL)
		{
			is_disk_section = 1;
		}
		line = strtok(NULL, "\n");

	}

	if (config_copy != NULL)
	{
		free(config_copy);
	}

	return result;
}

char *set_value_in_config(char *src_config, char* new_value, char *prefix, char *postfix, char *section_hint)
{

	int is_required_section = 0, is_new_path_added = 0;
	int src_config_length = strlen(src_config) + 1;
	/* size of <source file=''/> is about 20 */
	int new_value_length = strlen(new_value) + 20;
	char *config_copy = calloc(1,src_config_length);
	strcpy(config_copy,src_config);
	char *result_config = calloc(1,src_config_length + new_value_length);
	int pos_in_file = 0;
	char *line = NULL;
	if (config_copy == NULL)
	{
		return NULL;
	}

	line = strtok(config_copy, "\n");
	while (line != NULL)
	{
		if (is_required_section && !is_new_path_added && strstr(line, prefix) != NULL)
		{
			strcpy(result_config + pos_in_file,prefix);
			pos_in_file+=strlen(prefix);
			strcpy(result_config + pos_in_file, new_value);
			pos_in_file+=strlen(new_value);
			strcpy(result_config + pos_in_file,postfix);
			pos_in_file+=strlen(postfix);

			is_required_section = 0;
			is_new_path_added = 1;

		}
		else
		{
			strcpy(result_config + pos_in_file, line);
			pos_in_file += strlen(line);

		}


		if (strstr(line, section_hint) != NULL)
		{
			is_required_section = 1;
		}

		line = strtok(NULL, "\n");

		/* add newline after each line except the last one */
		if (line != NULL) {
			result_config[pos_in_file] = '\n';
			pos_in_file++;
		}
	}

	result_config[pos_in_file] = '\0';

	if (config_copy != NULL)
	{
		free(config_copy);
	}

	return result_config;
}

char *set_hd_image_path_in_config(char *src_config, char* new_path)
{
	char *prefix = "<source file='", *postfix="'/>";
	return set_value_in_config(src_config, new_path,  prefix, postfix, "disk");
}

char *set_name_in_config(char *src_config, char* new_name)
{
	char *prefix = "<name>", *postfix="</name>";
	return set_value_in_config(src_config, new_name,  prefix, postfix, "domain");
}

char *set_vnc_port_in_config(char *src_config, char* new_name)
{
	char *prefix = "  <graphics type='vnc' port='", *postfix="' listen='192.168.56.102'/>";
	return set_value_in_config(src_config, new_name,  prefix, postfix, "domain");
}


void backup_hih_memory_to_file(struct hih *hih,int pool_index)
{
	virDomainPtr dom = hih->honeypot_pool[pool_index].domain;
	char *memory_backup_filename = "hihs/memory_backups/backup.img";
	if (dom != NULL)
	{
		virDomainSave(dom, memory_backup_filename);
	}
	else
	{
		syslog(LOG_DEBUG, "ERROR: no available domain pointer set, cancel saving");
	}
}

void backup_hd_state(struct hih *hih, int pool_index)
{
	pid_t pid = fork();
	char *hd_image_path = hih->honeypot_pool[pool_index].path_to_hd_image;

	if (pid == 0)
	{ /* child */
		syslog(LOG_DEBUG, "INFO: creating backup for %s", hd_image_path);
		execl("/bin/cp", "/bin/cp", hd_image_path, "hihs/hd_backups/backup.img", (char *) 0);
	}
	else if (pid < 0)
	{
		syslog(LOG_DEBUG,"ERROR: could not backup hd image");
	}
}

char *create_cow_image_of_initial_hd_image(int pool_index)
{
	return NULL;
}

void *backup_remove_restart_hih_thread(void *params)
{
	struct backup_params *backup_params = (struct backup_params *)params;
	syslog(LOG_DEBUG,"INFO: starting backup of honeypot %s with index %d",backup_params->hih->id,backup_params->pool_index);
	backup_hih_memory_to_file(backup_params->hih, backup_params->pool_index);
	backup_hd_state(backup_params->hih, backup_params->pool_index);

	/*TODO: free old honeypot resources*/
	syslog(LOG_DEBUG,"INFO: backup of hih finished, starting new machine");
	print_precise_time(NULL);
	initialize_single_hih_pool_entry(backup_params->hih,backup_params->pool_index);


	return NULL;
}

void backup_and_remove_hih_cb(int fd, short which, void *arg)
{
	struct backup_params *params = (struct backup_params *)arg;
	if (params != NULL)
	{
		pthread_t backup_thread;
		//TODO: process status
		pthread_create(&backup_thread, NULL,&backup_remove_restart_hih_thread,params);
	}
}

void set_backup_and_remove_timeout(struct hih *hih, int pool_index)
{
	struct backup_params *params = (struct backup_params*)calloc(1,sizeof(struct backup_params));
	if (params == NULL)
	{
		syslog(LOG_DEBUG,"could not allocate memory for machine removal params");
		return;
	}
	params->pool_index = pool_index;
	params->hih = hih;
	struct timeval tv = { HIH_BACKUP_AND_REMOVE_TIMEOUT, 0};
	evtimer_del(&hih->honeypot_pool[pool_index].backup_and_remove_timeout);
	evtimer_set(&hih->honeypot_pool[pool_index].backup_and_remove_timeout,backup_and_remove_hih_cb , params);
	evtimer_add(&hih->honeypot_pool[pool_index].backup_and_remove_timeout, &tv);
}

struct addr *get_hih_addr_for_attacker(struct tuple *hdr,char *hih_id)
{
	if (!startup_hihs) {
		struct addr * test = calloc(sizeof(struct addr),1);
		addr_aton("2001:db8:10::5254:00ff:fed5:7898",test);
		return test;
	}

	
	int i;
	struct hih tmp;
	tmp.id = hih_id;
	struct hih *hih = SPLAY_FIND(hihs,&hihs,&tmp);

	if (hih == NULL)
	{
		syslog(LOG_DEBUG, "WARNING: could not find hih with id %s",hih_id);
		return NULL;
	}

	for (i = 0; i < HIH_POOL_SIZE; i++)
	{
		if (hih->honeypot_pool[i].hih_status == HIH_AVAILABLE || 
			((is_attacker_assigned_to_hih(hih,i,&hdr->src_addr)) && addr_cmp(&hdr->dst_addr,&hih->honeypot_pool[i].addr_expected_by_attacker)==0))
		{
			hih->honeypot_pool[i].hih_status = HIH_IN_USE;
			hih->honeypot_pool[i].addr_expected_by_attacker = hdr->dst_addr;
			assign_attacker_to_hih(hih,i,&hdr->src_addr);
			set_backup_and_remove_timeout(hih,i);
			return &hih->honeypot_pool[i].real_addr;
		}
	}
	syslog(LOG_DEBUG, "WARNING: no more available machines in machine pool");
	return NULL;
}


int is_exising_hih_available(struct tuple *hdr,char *hih_id)
{
	int i;
	struct hih tmp;
	tmp.id = hih_id;
	struct hih *hih = SPLAY_FIND(hihs,&hihs,&tmp);

	if (hih == NULL)
	{
		return 0;
	}

	for (i = 0; i < HIH_POOL_SIZE; i++)
	{
		if (hih->honeypot_pool[i].hih_status==HIH_IN_USE && addr_cmp(&hdr->dst_addr,&hih->honeypot_pool[i].addr_expected_by_attacker)==0)
		{
			return 1; 
		}
	}
	return 0;
}



void update_ip_assignements_from_configuration_message(char *message)
{
	char *mac_address_string = NULL, *new_ip_address_string = NULL;
	struct addr mac_address, new_ip_address;
	char *message_copy = NULL;
	int i;
	struct hih *hih;
	int could_assign_ip = 0;

	if (message == NULL)
	{
		syslog(LOG_DEBUG, "WARNING: ip configuration method cannot be null");
		return;
	}
	message_copy = (char *) calloc(1,strlen(message) + 1);
	if (message_copy == NULL)
	{
		syslog(LOG_DEBUG, "ERROR: could not process configuration message because no memory could be allocated for a message copy");
		return;
	}
	strcpy(message_copy, message);

	/* parse simple ip update message, format: mac;ip, eg. "34:34....:43;2001:304....::32" */
	mac_address_string = strtok(message_copy, ";");
	new_ip_address_string = strtok(NULL, ";");
	addr_aton(mac_address_string, &mac_address);
	addr_aton(new_ip_address_string, &new_ip_address);

	SPLAY_FOREACH(hih,hihs,&hihs)
	{
		for (i = 0; i < HIH_POOL_SIZE; i++)
		{
			if (addr_cmp(&hih->honeypot_pool[i].mac_address,&mac_address) == 0)
			{
				hih->honeypot_pool[i].real_addr = new_ip_address;
				hih->honeypot_pool[i].hih_status = HIH_AVAILABLE;
				syslog(LOG_DEBUG,"INFO: configuration message received from honeypot and successfully updated honeypot %s to %s",addr_ntoa(&mac_address),addr_ntoa(&new_ip_address));
				print_precise_time(NULL);
				could_assign_ip = 1;
			}
		}
	}

	if (message_copy != NULL)
	{
		free(message_copy);
	}

	if (!could_assign_ip)
	{
		syslog(LOG_DEBUG,"ERROR: could not find honeypot matching %s",addr_ntoa(&mac_address));
	}

}

struct addr* get_mac_addr_of_hih_with_ipv6(struct addr *ipv6_addr) {
	//test configuration
	static int test_machine_configured = 0;
	if (!startup_hihs && !test_machine_configured) {
		struct addr * test = calloc(sizeof(struct addr),1);
		addr_aton("52:54:00:d5:78:98",test);
		test_machine_configured = 1;
		return test;
	} else if (!startup_hihs && test_machine_configured) {
		return NULL;
	}
	
	int i;
	struct hih *hih;
	SPLAY_FOREACH(hih,hihs,&hihs)
		{
			for (i = 0; i < HIH_POOL_SIZE; i++)
			{
				if (addr_cmp(&hih->honeypot_pool[i].real_addr,ipv6_addr) == 0)
				{
					return &hih->honeypot_pool[i].mac_address;
				}
			}
		}
	
	return NULL;

}

/**
 * based on example from http://www.thegeekstuff.com/2011/12/c-socket-programming/
 */
void *hih_ip_config_server_thread(void *params)
{
	int listenfd = 0, connfd = 0;
	struct sockaddr_in6 serv_addr;
	char buffer[300];
	int message_length = 0;
	syslog(LOG_DEBUG, "INFO: starting hih ip configuration server");
	listenfd = socket(AF_INET6, SOCK_STREAM, 0);
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin6_family = AF_INET6;
	serv_addr.sin6_port = htons(4455);
	inet_pton(AF_INET6, "2001:db8:10::1", &(serv_addr.sin6_addr));
	bind(listenfd, (struct sockaddr*) &serv_addr, sizeof(serv_addr));
	listen(listenfd, 10);
	if (listenfd < 0)
	{
		syslog(LOG_DEBUG, "ERROR: could not bind to ip config server ip");
	}
	while (1)
	{
		print_precise_time(NULL);
		connfd = accept(listenfd, (struct sockaddr*) NULL, NULL);
		message_length = read(connfd, buffer, 299);
		buffer[message_length] = '\0';

		
		if (connfd < 0)
		{
			syslog(LOG_DEBUG, "ERROR: could not accept connection");
		}

		if (message_length > 0)
		{
			update_ip_assignements_from_configuration_message(buffer);
		}

		close(connfd);

	}
}


void start_hih_ip_config_server(void)
{
	pthread_t server_thread;
	int thread_create_status = pthread_create(&server_thread, NULL,&hih_ip_config_server_thread,NULL);
	if (thread_create_status != 0)
	{
		syslog(LOG_DEBUG,"ERROR: could not start ip server thread");
	}
	else
	{
		syslog(LOG_DEBUG,"INFO: ip server thread started succesfully");
	}
}

char *set_fixed_length_value_in_configuration(char *configuration, char *value,char *anchor)
{
	char *result;
	char *pointer_declaration_in_string = NULL;


	if (configuration == NULL || value == NULL)
	{
		syslog(LOG_DEBUG,"ERROR: cant set fixed length value, configuration or value address is null");
		return NULL;
	}

	result = (char *)calloc(1,strlen(configuration)+1);
	result[strlen(configuration)]='\0';
	if (result == NULL)
	{
		syslog(LOG_DEBUG,"ERROR: cant set fixed length value in configuration, memory for new configuration could not be allocated");
		return NULL;
	}

	strcpy(result,configuration);
	pointer_declaration_in_string = strstr(result,anchor);
	if (pointer_declaration_in_string != NULL)
	{
		strncpy(pointer_declaration_in_string+strlen(anchor),value,strlen(value));
	}
	return result;
}

char *set_mac_address_in_config(char *configuration, char *mac_address)
{
	return set_fixed_length_value_in_configuration(configuration,mac_address,"mac address='");
}


char *set_uuid_in_config(char *configuration,char *uuid)
{
	return set_fixed_length_value_in_configuration(configuration,uuid,"<uuid>");
}

//based on https://github.com/rampantpixels/foundation_lib/blob/master/foundation/uuid.c
char * uuid_generate(void)
{
	uuid_raw_t uuid;
	char *result = (char*)calloc(1,UUID_STR_LEN);
	memset(&uuid,0,sizeof(uuid));
	uuid.data1 = uuid_counter;
	uuid_counter++;

	//Add variant and version
	uuid.data3 &= 0x0FFF;
	uuid.data3 |= 0x4000;
	uuid.data4[0] &= 0x3F;
	uuid.data4[0] |= 0x80;
	sprintf( result, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x", uuid.data1, uuid.data2, uuid.data3, uuid.data4[0], uuid.data4[1], uuid.data4[2], uuid.data4[3], uuid.data4[4], uuid.data4[5], uuid.data4[6], uuid.data4[7] );
	return result;
}

int get_next_vnc_port(void)
{
	return vnc_port_counter++;
}


void configure_pool_entry(struct hih *hih, int pool_index)
{
	hih_pool_entry_t *pool_entry = &hih->honeypot_pool[pool_index];
	char *xmlconfig = load_machine_config(hih->configuration_filename);

	struct addr mac_address = compute_new_ethernet_address();
	char *original_hd_image_path = get_hd_image_path_from_config(xmlconfig);
	char *new_hd_image_path = compute_new_hd_image_path(xmlconfig);
	char *uuid = uuid_generate();
	int vnc_port = get_next_vnc_port();
	char *tmp_config = xmlconfig;
	char *vnc_port_string = (char *)calloc(1,VNC_PORT_STR_LEN);

	char *configuration = set_hd_image_path_in_config(xmlconfig,new_hd_image_path);
	free_if_not_null(tmp_config);

	tmp_config = configuration;
	configuration = set_mac_address_in_config(configuration, addr_ntoa(&mac_address));
	free_if_not_null(tmp_config);

	tmp_config = configuration;
	configuration = set_uuid_in_config(configuration,uuid);
	free_if_not_null(tmp_config);

	tmp_config = configuration;
	sprintf(vnc_port_string,"%d",vnc_port);
	configuration = set_vnc_port_in_config(configuration,vnc_port_string);
	free_if_not_null(tmp_config);

	/* lets keep it simple and set name to uuid */
	tmp_config = configuration;
	configuration = set_name_in_config(configuration,uuid);
	free_if_not_null(tmp_config);

	pool_entry->xml_configuration = configuration;
	pool_entry->mac_address = mac_address;
	pool_entry->vnc_port = vnc_port;
	
	/* start preparing the hd image */
	struct hd_initialization_params *params = calloc(1,sizeof(struct hd_initialization_params));
	if (params == NULL)
	{
		syslog(LOG_DEBUG, "ERROR: could not allocate memory for hd preparation params");
		return;
	}
	else
	{
		params->hih_pool_entry = pool_entry;
		params->original_hd_image_path = original_hd_image_path;
		params->new_hd_image_path = new_hd_image_path;
		pthread_t hd_prepare_thread;
	    //TODO: process status
		pthread_create(&hd_prepare_thread, NULL,&prepare_hih_hd_image_and_start_hih,params);
	}
}

void initialize_single_hih_pool_entry(struct hih *hih,int pool_index)
{
	syslog(LOG_DEBUG,"INFO: initializing hih with configuration %s",hih->configuration_filename);
	hih->honeypot_pool[pool_index].hih_status = HIH_BOOTING;
	configure_pool_entry(hih,pool_index);
	SPLAY_INIT(&hih->honeypot_pool[pool_index].assigned_attackers);
}

void initialize_pool_of_single_hih(struct hih* hih)
{
	int pool_index;
	for (pool_index = 0; pool_index < HIH_POOL_SIZE; pool_index++)
	{
		initialize_single_hih_pool_entry(hih, pool_index);
	}

}

void initialize_machine_pool(void)
{
	struct hih *hih;
	SPLAY_FOREACH(hih,hihs,&hihs)
	{
		initialize_pool_of_single_hih(hih);
	}

}


void add_ipv6_addr_to_system_routing_table(struct addr *addr) {
	//add ipv6 route
	syslog(LOG_DEBUG,"INFO: adding ip route to system");
	char *command = (char*)calloc(1,300);
	if (command == NULL) {
		syslog(LOG_DEBUG,"ERROR: not enough memory for ip route command");
		return;
	}
	sprintf(command,"ip -6 route add %s dev br0",addr_ntoa(addr));
	system(command);
}


/* 
 * inserts a template that represents the lih itself so
 * that we can communicate with the high interaction
 * honeypot using our own tcp stack
 */
struct template* insert_hih_proxy_template(struct addr *ipv6_addr_of_attacker,struct addr *expected_hih_addr, struct addr *real_hih_ip_addr, int configure_new_hih)
{
	struct addr *src_ip_addr, 
	*dst_ip_addr_before_reconfiguration,
	*dst_ip_addr_after_reconfiguration, 
	*dst_eth_addr,
	*src_ip4_addr;
	struct template *result = NULL;
	//TODO: verify successful memory allocation
	dst_ip_addr_after_reconfiguration = expected_hih_addr;
	dst_ip_addr_before_reconfiguration = real_hih_ip_addr;
	src_ip_addr = (struct addr *)calloc(1,sizeof(struct addr));
	src_ip4_addr = (struct addr *)calloc(1,sizeof(struct addr));
	
	src_ip_addr = ipv6_addr_of_attacker;
	dst_eth_addr = get_mac_addr_of_hih_with_ipv6(dst_ip_addr_before_reconfiguration);
	
	//if the address is null, it means that the honeypot has already been reconfigured and we can skip this step
	if (dst_eth_addr == NULL) {
		//TODO: cleanup
	} else if(configure_new_hih) {
		addr_aton("192.168.1.4", src_ip4_addr);
		configure_ip_address_of_hih(dst_eth_addr,dst_ip_addr_after_reconfiguration);
		add_ipv6_addr_to_system_routing_table(expected_hih_addr);
	}
	
	
	//insert template that represents attacker machine in our template tree so that we can use it as a communication source	
	result = template_find(addr_ntoa(ipv6_addr_of_attacker));
	if (result != NULL) {
		/* update mac in hih neighbor entry */
		struct ndp_neighbor_req *neighbor_entry = NULL;
		neighbor_entry = ndp_neighbor_find(dst_ip_addr_after_reconfiguration);
		if (neighbor_entry != NULL && dst_eth_addr != NULL) {
			neighbor_entry->target_mac_addr = *dst_eth_addr;
		}
	} else {
		struct template *tmpl = template_create(addr_ntoa(ipv6_addr_of_attacker));
		tmpl->ethernet_addr = (struct addr *)calloc(1,sizeof(struct addr));
		addr_aton("52:55:03:d5:78:97", tmpl->ethernet_addr);

		tmpl->inter = interface_new("br0");
		tmpl->inter->if_eth = eth_open(tmpl->inter->if_ent.intf_name);
		struct action *action = honeyd_protocol(tmpl, IP_PROTO_TCP);
		template_add(tmpl, 0, 0, action);
			
		ndp_neighbor_new(tmpl->inter, tmpl->ethernet_addr, src_ip_addr,
				dst_eth_addr, dst_ip_addr_after_reconfiguration);
		
		syslog(LOG_DEBUG,"INFO: template %s for proxy added",tmpl->name);

		//multicast stuff to process neighbor solicitations
		struct addr *solicited_node_addr;
		solicited_node_addr = (struct addr *)calloc(1,sizeof(struct addr));
		if (solicited_node_addr != NULL) {
			compute_solicited_node_address(src_ip_addr, solicited_node_addr);
			multicast_group_new(solicited_node_addr);
			add_host_to_multicast_group(src_ip_addr, solicited_node_addr);
			free(solicited_node_addr);
		}
		result =  tmpl;
	}
	
	return result;
}

struct callback cb_tcp_managed = { cmd_tcp_read, cmd_tcp_write, cmd_tcp_eread, cmd_tcp_connect_cb };

void bind_lih_to_hih(struct tcp_con *lih_con, struct tcp_con *hih_con) {
	
	int hih_to_lih_pair[2];
	int lih_to_hih_pair[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, hih_to_lih_pair) != 0) {
		syslog(LOG_DEBUG, "ERROR: cannot create socket pair - %s",strerror(errno));
	} 
	
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, lih_to_hih_pair) != 0) {
		syslog(LOG_DEBUG, "ERROR: cannot create socket pair -  %s",strerror(errno));
	}
	
	lih_con->cmd_pfd = hih_to_lih_pair[0];
	hih_con->hih_to_lih_pfd = hih_to_lih_pair[1];
	
	hih_con->cmd_pfd = lih_to_hih_pair[0];
	lih_con->lih_to_hih_pfd = lih_to_hih_pair[1];
	
	cmd_ready_fd(&lih_con->cmd, &cb_tcp_managed, lih_con);
	cmd_ready_fd(&hih_con->cmd, &cb_tcp_managed, hih_con);
	
	hih_con->lih_con = lih_con;
	lih_con->hih_con = hih_con;
}

void send_syn_until_success_cb(int fd, short which, void *arg) {
	struct tcp_con *hih_con = (struct tcp_con *)(arg);
	hih_con->snd_una--;
	tcp_send(hih_con, TH_SYN, NULL, 0);
	hih_con->snd_una++;
	if (hih_con->connect_attampts < 50) {
		hih_con->connect_attampts++;
		set_send_syn_until_success_timeout(hih_con);
	} else {
		syslog(LOG_DEBUG,"WARNING: cancel syn to hih, max retries reached");
	}
}

void set_send_syn_until_success_timeout(struct tcp_con * hih_con) {
	struct timeval tv = { 0, 300000};
	evtimer_del(&hih_con->try_to_connect_event);
	evtimer_set(&hih_con->try_to_connect_event,send_syn_until_success_cb, (void *)hih_con);
	evtimer_add(&hih_con->try_to_connect_event, &tv);
}

struct tcp_con* proxy_connect_to_hih(struct tcp_con *lih_con, struct addr * real_hih_ip_addr, int configure_new_hih)
{
	struct template *tmpl = NULL;
		
	struct tcp_con *hih_con = (struct tcp_con*)calloc(1,sizeof(struct tcp_con));	
	
	lih_con->packet_queue.first = 0;
	lih_con->packet_queue.next = 0;
	
	/* set conhdr buffers */
	tcp_setupconnect(hih_con);
		
	struct tuple *tuple = &hih_con->conhdr;
	
	tuple->src_addr = lih_con->conhdr.dst_addr;
	tuple->dst_addr = lih_con->conhdr.src_addr;

	tuple->interface_name = calloc(1, strlen("br0") + 1);
	if (!tuple->interface_name) {
		syslog(LOG_DEBUG, "ERROR: could not allocate memory for hih connection interface name!");
		return NULL;
	}
	strcpy(tuple->interface_name, "br0");

	if (configure_new_hih) {	
		tmpl = insert_hih_proxy_template(&lih_con->conhdr.src_addr,&tuple->src_addr,real_hih_ip_addr, configure_new_hih);
	}	

	hih_con->tmpl = tmpl;

	hih_con->addr_family = AF_INET6;

	hih_con->conhdr = *tuple;
		
	evtimer_set(&hih_con->conhdr.timeout, honeyd_tcp_timeout, hih_con);
	
	//this is actually honeyds source port
	hih_con->conhdr.dport=lih_con->conhdr.sport;
	
	//this is actually the hihs dest port
	hih_con->conhdr.sport=lih_con->conhdr.dport;
		
	//initial sequence number
	hih_con->snd_una=lih_con->rcv_next-1;
	
	hih_con->state=TCP_STATE_SYN_SENT;
	
	hih_con->is_managed = 1;
	
	hih_con->shellcode_size = SHELLCODE_BUF_MAXSIZE;
	hih_con->shellcode_buf = (char*)calloc(1,SHELLCODE_BUF_MAXSIZE);
	
	hih_con->readbuf = (u_char *)calloc(1,1024);
	
	bind_lih_to_hih(lih_con, hih_con);
	
	evtimer_set(&hih_con->retrans_timeout, tcp_retrans_timeout, hih_con);
	
	tcp_connection_insert(&hih_con->conhdr);
	
	//connect, retry until hih handshake is finished
	tcp_send(hih_con, TH_SYN, NULL, 0);
	set_send_syn_until_success_timeout(hih_con);
	
	hih_con->snd_una++;
	
	return hih_con;
}

void bind_lih_connection_to_transparent_hih_connection(struct tcp_con *lih_con, struct addr * hih_addr) {
	proxy_connect_to_hih(lih_con, hih_addr, 1);
}

void bind_lih_connection_to_existing_hih(struct tcp_con *lih_con) {
	proxy_connect_to_hih(lih_con, &lih_con->conhdr.dst_addr, 0);
}


void test_update_ip_assignements_from_configuration_message()
{
	hihmanager_init();
	startup_hihs = 0;
	define_hih("testmachine1", "tests/testmachine.xml");
	define_hih("testmachine2", "tests/testmachine.xml");
	initialize_machine_pool();

	/* set deault values */
	struct hih tmp, *test_hih;

	tmp.id = "testmachine1";
	test_hih = SPLAY_FIND(hihs,&hihs,&tmp);
	addr_aton("52:55:02:d5:78:97", &test_hih->honeypot_pool[0].mac_address);
	addr_aton("2001:db8:10::2", &test_hih->honeypot_pool[0].real_addr);

	tmp.id = "testmachine2";
	test_hih = SPLAY_FIND(hihs,&hihs,&tmp);
	addr_aton("52:54:00:d5:78:97", &test_hih->honeypot_pool[0].mac_address);
	addr_aton("2001:db8:10::3", &test_hih->honeypot_pool[0].real_addr);

	update_ip_assignements_from_configuration_message("52:54:00:d5:78:97;2001:db8:10::32");

	tmp.id = "testmachine1";
	test_hih = SPLAY_FIND(hihs,&hihs,&tmp);
	if (strcmp("2001:db8:10::2", addr_ntoa(&test_hih->honeypot_pool[0].real_addr)) != 0)
	{
		fprintf(stderr, "ERROR: wrong ip address has changed\n");
		return;
	}

	tmp.id = "testmachine2";
	test_hih = SPLAY_FIND(hihs,&hihs,&tmp);
	if (strcmp("2001:db8:10::32", addr_ntoa(&test_hih->honeypot_pool[0].real_addr)) != 0)
	{
		fprintf(stderr, "ERROR: wrong ip set, expected: 2001:db8:10::32, got: %s\n", addr_ntoa(&test_hih->honeypot_pool[0].real_addr));
		return;
	}

	if (test_hih->honeypot_pool[0].hih_status != HIH_AVAILABLE)
	{
		fprintf(stderr, "ERROR: wrong honeypot status returned");
		return;
	}

	fprintf(stderr, "\t%s: OK\n", __func__);
}

void test_load_machine_config(void)
{
	char *expected_config = "<domain type='kvm'>\n"
			"  <name>honeypot</name>\n"
			"  <uuid>7816585d-b711-703a-1a1c-78e557e8afea</uuid>\n"
			"  <memory>256536</memory>\n"
			"  <currentMemory>65536</currentMemory>\n"
			"  <vcpu>1</vcpu>\n"
			"  <os>\n"
			"    <type arch='x86_64'>hvm</type>\n"
			"    <boot dev='hd'/>\n"
			"  </os>\n"
			"  <features>\n"
			"    <acpi/>\n"
			"  </features>\n"
			"  <clock offset='utc'/>\n"
			"  <on_poweroff>destroy</on_poweroff>\n"
			"  <on_reboot>restart</on_reboot>\n"
			"  <on_crash>destroy</on_crash>\n"
			"  <devices>\n"
			"    <emulator>/usr/bin/qemu-system-x86_64</emulator>\n"
			"    <disk type='file' device='disk'>\n"
			"      <source file='/test.img'/>\n"
			"    <driver name='qemu' type='qcow2'/>\n"
			"      <target dev='hda' bus='ide'/>\n"
			"      <address type='drive' controller='0' bus='0' unit='0'/>\n"
			"    </disk>\n"
			"    <controller type='ide' index='0'/>\n"
			"    <input type='mouse' bus='ps2'/>\n"
			"  <graphics type='vnc' port='1056'/>\n"
			"  <interface type='bridge'>\n"
			"     <source bridge='br0'/>\n"
			"     <mac address='00:16:3e:1d:b3:4a'/>\n"
			"  </interface>\n"
			"  </devices>\n"
			"</domain>\n";

	char *actual_config = load_machine_config("tests/testmachine.xml");
	if (actual_config == NULL || strcmp(expected_config, actual_config) != 0)
	{
		fprintf(stderr, "loading config failed, \n%s\n%s\n", actual_config, expected_config);
		return;
	}
	fprintf(stderr, "\t%s: OK\n", __func__);
}

void test_startup_hih(void)
{
	connect_to_virt();
	struct hih hih;
	hih.configuration_filename = "hihs/xmls/test1.xml";
	configure_pool_entry(&hih,0);
	virDomainPtr honeypot = startup_hih(&hih.honeypot_pool[0]);
	free_hih(honeypot);
	disconnect_from_virt();
	fprintf(stderr, "\t%s: OK\n", __func__);
}

void test_initialize_machine_pool(void)
{

	fprintf(stderr, "\t%s: NOT IMPLEMENTED\n", __func__);
}

void test_configure_ip_address_of_machine(void)
{
	struct addr testaddr;
	addr_aton("2001:db8:9::99", &testaddr);
	configure_ip_address_of_hih(0, &testaddr);
	fprintf(stderr, "\t%s: OK\n", __func__);
}

void test_get_hd_image_path_from_config(void)
{
	char *config = "    <disk type='file' device='disk'>\n"
       "	<source file='/test.img'/>\n"
       "<driver name='qemu' type='qcow2'/>";
	int original_config_len = strlen(config);
	char *hd_image_path = get_hd_image_path_from_config(config);
	char *expected_hd_image_path = "/test.img";
	if (hd_image_path == NULL || strcmp(hd_image_path,expected_hd_image_path)!=0)
	{
		fprintf(stderr, "\tERROR: could not parse hd image path\n");
		return;
	}
	if (strlen(config) != original_config_len)
	{
		fprintf(stderr, "\tERROR: config has changed\n");
	}
	fprintf(stderr, "\t%s: OK\n", __func__);
}

void test_get_hd_image_path_from_config_with_empty_disk(void)
{
	char *config = "<source file='/test.img'/>\n"
       "<driver name='qemu' type='qcow2'/>";
	char *hd_image_path = get_hd_image_path_from_config(config);
	if (hd_image_path != NULL)
	{
		fprintf(stderr, "\tERROR: hd image path should be NULL\n");
		return;
	}
	fprintf(stderr, "\t%s: OK\n", __func__);
}

void test_set_hd_image_path_from_config(void)
{
	char *config = "    <disk type='file' device='disk'>\n"
			"	<source file='/test.img'/>\n"
			"<driver name='qemu' type='qcow2'/>";

	char *new_path = "/result.img";

	char *new_config = set_hd_image_path_in_config(config, new_path);

	char *expected_result = "    <disk type='file' device='disk'>\n"
			"<source file='/result.img'/>\n"
			"<driver name='qemu' type='qcow2'/>";

	if (new_config == NULL || strcmp(new_config, expected_result) != 0)
	{
		fprintf(stderr, "\tERROR: hd image path was not set properly\n");
		return;
	}

	fprintf(stderr, "\t%s: OK\n", __func__);
}

void test_set_mac_address_in_config()
{
	char *config_to_update = "  <interface type='bridge'>\n"
			"<source bridge='br0'/>\n"
			"<mac address='00:16:3e:1d:b3:4a'/>\n"
			"</interface>";

	char *expected_config = "  <interface type='bridge'>\n"
			"<source bridge='br0'/>\n"
			"<mac address='11:16:3e:23:77:11'/>\n"
			"</interface>";

	char *result = set_mac_address_in_config(config_to_update, "11:16:3e:23:77:11");
	if (strcmp(result, expected_config) != 0)
	{
		fprintf(stderr, "\tERROR: could not set mac address, expected: \n%s,\nresult: \n%s\n",expected_config,result);
		return;
	}

	fprintf(stderr, "\t%s: OK\n", __func__);
}

void test_compute_new_ethernet_address(void)
{
	struct addr expected_addr;

	addr_aton("52:54:00:d5:78:f7",&ethernet_addr_for_hih);
	addr_aton("52:54:00:d5:78:fb",&expected_addr);

	compute_new_ethernet_address();
	compute_new_ethernet_address();
	compute_new_ethernet_address();

	struct addr result = compute_new_ethernet_address();
	if (addr_cmp(&expected_addr,&result) != 0)
	{
		fprintf(stderr,"\tERROR: wrong ethernet address computed, expected: %s, got: %s\n",addr_ntoa(&expected_addr),addr_ntoa(&result));
		return;
	}

	addr_aton("52:54:00:d5:78:ff",&ethernet_addr_for_hih);
	addr_aton("52:54:00:d5:79:02",&expected_addr);

	compute_new_ethernet_address();
	compute_new_ethernet_address();

	result = compute_new_ethernet_address();
	if (addr_cmp(&expected_addr,&result) != 0)
	{
		fprintf(stderr,"\tERROR: wrong ethernet address computed, expected: %s, got: %s\n",addr_ntoa(&expected_addr),addr_ntoa(&result));
		return;
	}

	fprintf(stderr, "\t%s: OK\n", __func__);
}

void test_compute_new_hd_image_path(void)
{
	hd_image_counter = 3;
	char *config = "    <disk type='file' device='disk'>\n"
				"	<source file='//test.img'/>\n"
				"<driver name='qemu' type='qcow2'/>";

	/* do a dummy call to increase the counter */
	compute_new_hd_image_path(config);

	char *result = compute_new_hd_image_path(config);
	char *expected_result = "/home/bongo/programming/honeyd/diss_honeyd/honeydv6/tests/test.img.4";
	if (result == NULL || strcmp(result,expected_result)!=0)
	{
		fprintf(stderr,"\tERROR: wrong hd image path computed, expected: %s, got: %s\n",expected_result,result);
		return;
	}
	fprintf(stderr, "\t%s: OK\n", __func__);
}

void test_uuid_generate_random_valid_length(void)
{
	char *result = uuid_generate();

	if (result == NULL || strlen(result) != 36)
	{
		fprintf(stderr, "\tERROR: uuid with invalid length returned: %s\n", result);
		return;
	}

	fprintf(stderr, "\t%s: OK\n", __func__);
}

void test_multiple_uuid_generate_random_calls_return_different(void)
{
	char *result1 = uuid_generate();
	char *result2 = uuid_generate();
	char *result3 = uuid_generate();

	if (strcmp(result1, result2) == 0 || strcmp(result1, result3) == 0 || strcmp(result2, result3) == 0)
	{
		fprintf(stderr, "\tERROR: multiple uuid generations did not return different result\n");
		return;
	}

	fprintf(stderr, "\t%s: OK\n", __func__);
}


void test_set_uuid(void)
{
	char *config = "<name>honeypot</name>\n"
			"<uuid>7816585d-b711-703a-1a1c-78e557e8afea</uuid>\n"
			"<memory>256536</memory>";

	char *expected_config = "<name>honeypot</name>\n"
				"<uuid>0b0c165e-323a-11e3-b190-047d7b921004</uuid>\n"
				"<memory>256536</memory>";

	char *uuid = "0b0c165e-323a-11e3-b190-047d7b921004";

	char *updated_configuration = set_uuid_in_config(config,uuid);

	if (updated_configuration == NULL || strcmp(updated_configuration,expected_config) != 0)
	{
		fprintf(stderr, "\tERROR: uuid not properly set in config\n");
	}

	fprintf(stderr, "\t%s: OK\n", __func__);
}

void test_set_name_in_config(void)
{
	char *config = "<domain type='kvm'>\n"
	  "<name>honeypot</name>\n"
	  "<uuid>7816585d-b711-703a-1a1c-78e557e8afea</uuid>";

	char *new_name = "anewnameforahoneypot";

	char *expected_config = "<domain type='kvm'>\n"
		  "<name>anewnameforahoneypot</name>\n"
		  "<uuid>7816585d-b711-703a-1a1c-78e557e8afea</uuid>";

	char *result_config = set_name_in_config(config,new_name);

	if (strcmp(result_config,expected_config) != 0)
	{
		fprintf(stderr, "\tERROR: name not properly set in config, got: \n%s\n", result_config);
	}

	fprintf(stderr, "\t%s: OK\n", __func__);

}

void test_configure_pool_entry(void)
{
	uuid_counter = 2;
	hd_image_counter = 3;
	vnc_port_counter = 1245;
	struct hih hih;
	hih.configuration_filename="tests/testmachine.xml";
	configure_pool_entry(&hih,0);

	char *expected_config = "<domain type='kvm'>\n"
				"<name>00000002-0000-4000-8000-000000000000</name>\n"
				"  <uuid>00000002-0000-4000-8000-000000000000</uuid>\n"
				"  <memory>256536</memory>\n"
				"  <currentMemory>65536</currentMemory>\n"
				"  <vcpu>1</vcpu>\n"
				"  <os>\n"
				"    <type arch='x86_64'>hvm</type>\n"
				"    <boot dev='hd'/>\n"
				"  </os>\n"
				"  <features>\n"
				"    <acpi/>\n"
				"  </features>\n"
				"  <clock offset='utc'/>\n"
				"  <on_poweroff>destroy</on_poweroff>\n"
				"  <on_reboot>restart</on_reboot>\n"
				"  <on_crash>destroy</on_crash>\n"
				"  <devices>\n"
				"    <emulator>/usr/bin/qemu-system-x86_64</emulator>\n"
				"    <disk type='file' device='disk'>\n"
				"<source file='/test.img'/>\n"
				"    <driver name='qemu' type='qcow2'/>\n"
				"      <target dev='hda' bus='ide'/>\n"
				"      <address type='drive' controller='0' bus='0' unit='0'/>\n"
				"    </disk>\n"
				"    <controller type='ide' index='0'/>\n"
				"    <input type='mouse' bus='ps2'/>\n"
				"  <graphics type='vnc' port='1245'/>\n"
				"  <interface type='bridge'>\n"
				"     <source bridge='br0'/>\n"
				"     <mac address='52:54:00:d5:79:03'/>\n"
				"  </interface>\n"
				"  </devices>\n"
				"</domain>";

	if (strcmp(hih.honeypot_pool[0].xml_configuration,expected_config)!=0)
	{
		fprintf(stderr, "\tERROR: configure pool entry did something wrong, expected: \n%s\ngot: \n%s\n",expected_config,hih.honeypot_pool[0].xml_configuration);
		return;
	}

	if (strcmp(addr_ntoa(&hih.honeypot_pool[0].mac_address),"52:54:00:d5:79:03" ) != 0)
	{
		fprintf(stderr, "\tERROR: wrong ethernet defined in %s",__func__);
		return;
	}

	fprintf(stderr, "\t%s: OK\n", __func__);
}

void test_proxy_connect_to_hih()
{
	
	//proxy_connect_to_hih();
	fprintf(stderr, "\t%s: OK\n", __func__);
}


void hihmanager_test(void)
{
	//test_load_machine_config();
	//test_update_ip_assignements_from_configuration_message();
	//test_get_hd_image_path_from_config();
	//test_get_hd_image_path_from_config_with_empty_disk();
	//test_set_hd_image_path_from_config();
	//test_set_mac_address_in_config();
	//test_compute_new_ethernet_address();
	//test_compute_new_hd_image_path();
	//test_uuid_generate_random_valid_length();
	//test_multiple_uuid_generate_random_calls_return_different();
	//test_set_uuid();
	//test_set_name_in_config();
	//test_configure_pool_entry();

	
	//test_initialize_machine_pool();
	//test_startup_hih();
	//test_configure_ip_address_of_machine();

	
	
	syslog(LOG_DEBUG,"wait 2 seconds for threads to finish");
	sleep(2);
}

void hihmanager_run_integration_test(void) {
	//test_proxy_connect_to_hih();
}
