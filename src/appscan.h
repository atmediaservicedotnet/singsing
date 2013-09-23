#ifndef _APPSCAN_H_
#define _APPSCAN_H_

#include <stdio.h>
#include <pthread.h>
#include <sys/types.h>  
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#ifdef SOLARIS
#include <arpa/nameser_compat.h>
#endif

#ifdef MAC
#include <netinet/in.h>
#endif

#define APPSCAN_IPV4_MAX_SIZE 		16
#define APPSCAN_MAX_THREAD_NUM		64
#define APPSCAN_DEFAULT_THREAD_NUM	16

#define MIN(a,b)  ((a) < (b) ? (a) : (b))


typedef enum appscan_type {

		TELNET = 0,

		ORACLE = 1,

		SOCKS = 2,

} appscan_type;



typedef struct appscan_descriptor {
	
	unsigned int appscan_processed_scans_num;

	unsigned int appscan_total_scans_num;

	//mutex to print safely a result
	pthread_mutex_t appscan_result_mutex_lock;

	pthread_mutex_t appscan_total_scans_mutex_lock;

	int appscan_socks_connect_ip[4];

	unsigned int appscan_socks_port_ip;
	
	unsigned int appscan_socks_initialized;

	unsigned int appscan_max_thread_num;


} appscan_descriptor;



typedef struct appscan_params {

	char host[ APPSCAN_IPV4_MAX_SIZE ];

	unsigned int port;

	unsigned int connect_timeout;

	unsigned int rw_timeout;

	appscan_type type;

	appscan_descriptor * ad;

} appscan_params;


//Functions declaration
void appscan_create( appscan_descriptor * ad); 

int appscan_run_scan(appscan_type type, appscan_descriptor * ad, const char * host, unsigned int port, unsigned int connect_timeout, unsigned int rw_timeout );

void appscan_wait_scans_results(appscan_descriptor * ad);

void appscan_destroy(appscan_descriptor * ad);

appscan_params * appscan_params_create( appscan_descriptor * ad, appscan_type type, const char * host , unsigned int port, unsigned int connect_timeout, unsigned int rw_timeout); 

void appscan_params_destroy( appscan_params *ap );

void * appscan_monitoring_thread( void * params ); 

void appscan_set_thread_num( appscan_descriptor * ad , unsigned int num ); 

int appscan_net_connect( const char * host, unsigned int port, unsigned int connect_timeout);

int appscan_set_socks_connect_ip_and_port ( appscan_descriptor *ad, const char *ip );

int appscan_telnetd_scan_worker( const char * host, unsigned int port, appscan_params * ap );

int appscan_oracle_scan_worker( const char * host, unsigned int port, char * command, int len, appscan_params * ap );

int appscan_socks_v4_scan_worker( const char * host, unsigned int port, appscan_params * ap );

int appscan_socks_v5_scan_worker( const char * host, unsigned int port, appscan_params * ap );

int appscan_xot_scan_worker( const char * host, unsigned int port, appscan_params * ap );

void * appscan_scan_worker( void * params );

void * appscan_run_scan_thread( void * parms ); 

#endif
