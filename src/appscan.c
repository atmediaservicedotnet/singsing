#include "appscan.h"


//WORKING
static char oraclecommand1[]="\x00\x1e\x00\x06\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07\x76\x65\x72\x73\x69\x6f\x6e\x04\x62\x69\x6e\x64\x00\x00\x10\x00\x03";

//WORKING
static char oraclecommand2[]="\x00\x5a\x00\x00\x01\x00\x00\x00\x01\x36\x01\x2c\x00\x00\x08\x00\x7f\xff\x7f\x08\x00\x00\x00\x01\x00\x20\x00\x3a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x34\xe6\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x28\x43\x4f\x4e\x4e\x45\x43\x54\x5f\x44\x41\x54\x41\x3d\x28\x43\x4f\x4d\x4d\x41\x4e\x44\x3d\x76\x65\x72\x73\x69\x6f\x6e\x29\x29";


int appscan_set_socks_connect_ip_and_port ( appscan_descriptor *ad, const char *ip )
{

	char * star = NULL;

	star = strchr( ip, '.');                                           
	if ( star == NULL )
		return 0; 

    *star = 0x0;
    ad->appscan_socks_connect_ip[0] = atoi(ip);                                          
    ip = star + 1;                                                     
    
    star = strchr( ip, '.');                                           
	if ( star == NULL )
		return 0; 

    *star = 0x0;
    ad->appscan_socks_connect_ip[1] = atoi(ip);                                          
    ip = star + 1;
                                                                       
    star = strchr( ip, '.');                                           
	if ( star == NULL )
		return 0; 

    *star = 0x0;                                                       
    ad->appscan_socks_connect_ip[2] = atoi(ip);                                          
    ip = star + 1;                                                     
    
    star = strchr( ip, ':');                                           
	if ( star == NULL )
		return 0; 

    *star = 0x0;
    ad->appscan_socks_connect_ip[3] = atoi(ip);                                          
    ip = star + 1;

	ad->appscan_socks_port_ip = atol( ip );

	if ( ( ad->appscan_socks_port_ip < 0 ) || ( ad->appscan_socks_port_ip > 65535 ) )
		return 0;

	ad->appscan_socks_initialized = 1;
	return 1;
}


int appscan_net_connect( const char * host, unsigned int port, unsigned int connect_timeout)
{
	int sd = 0;
	struct sockaddr_in servAddr;
	int flags = 0, flags_old = 0, retval = 0;
	unsigned int sock_len = 0;
	struct sockaddr_in sin;
	struct timeval tv;
	fd_set rfds;

	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.s_addr = inet_addr(host);
	servAddr.sin_port = htons( port );

	sd = socket(AF_INET, SOCK_STREAM, 0);
	if(sd<0) {
		perror("cannot open socket ");
		exit(1);
	}

	// Set Non Blocking Socket
	flags_old = fcntl( sd, F_GETFL,0);
	flags = flags_old;
	flags |= O_NONBLOCK;
	fcntl( sd, F_SETFL, flags);

	if( connect(sd, (struct sockaddr *) &servAddr, sizeof(servAddr)) == 0) {
		fcntl( sd, F_SETFL, flags_old);
		return sd;
	}
	
	// Set timeout
	tv.tv_sec = connect_timeout;
	tv.tv_usec = 0;

	FD_ZERO(&rfds);
	FD_SET(sd, &rfds);
	
	retval = select(FD_SETSIZE, NULL, &rfds, NULL, &tv);

	// if retval < 0 error
	if( retval < 0 ) {
		close( sd );
		return -1;
	}
	sock_len = sizeof( sin );

	// Check if port closed
	if( retval ) {
		if( getpeername( sd, (struct  sockaddr  *) &sin, &sock_len) < 0 ) {
			close( sd );
			return -1;
		} else {
			// XXX
			fcntl( sd, F_SETFL, flags_old);
			return sd;
		}
	}
	close( sd );
	return -1;

} 


int appscan_socks_v4_scan_worker( const char * host, unsigned int port, appscan_params * ap )
{

	int sock = 0, flags = 0, i = 0, l = 0;
	char buff[2000] = {0};
	struct timeval tv;
	char * p = NULL;
	time_t cur_time;
	time_t start_time;
	unsigned int target_port = 0;

	fd_set rfds; 

	memset( buff, 0, sizeof(buff));

	p = buff;
	l = 0;

	sock = appscan_net_connect(host, port, ap->connect_timeout);

	if( sock < 0 )
		return 1;

	// Testing V4 protocol
/*    * field 1: SOCKS version number, 1 byte, must be 0x04 for this version
    * field 2: command code, 1 byte:
          o 0x01 = establish a TCP/IP stream connection
          o 0x02 = establish a TCP/IP port binding
    * field 3: network byte order port number, 2 bytes
    * field 4: network byte order IP address, 4 bytes
    * field 5: the user ID string, variable length, terminated with a null (0x00)*/
	/*0x04 | 0x01 | 0x00 0x50 | 0x42 0x66 0x07 0x63 | 0x46 0x72 0x65 0x64 0x00*/


	memcpy(buff, "\x04\x01", 2);

	target_port = htons( ap->ad->appscan_socks_port_ip );

	memcpy(buff + 2, &target_port, 2);
	memcpy(buff + 4, &ap->ad->appscan_socks_connect_ip[0], 1);
    memcpy(buff + 5, &ap->ad->appscan_socks_connect_ip[1], 1);
    memcpy(buff + 6, &ap->ad->appscan_socks_connect_ip[2], 1);
    memcpy(buff + 7, &ap->ad->appscan_socks_connect_ip[3], 1);
	memcpy(buff + 8 , "\x46\x72\x65\x64\x00",5);


	write(sock,buff,13);

	tv.tv_sec = ap->rw_timeout;
	tv.tv_usec = 0;

	flags = fcntl( sock, F_GETFL,0);
	flags |= O_NONBLOCK;
	fcntl( sock, F_SETFL, flags);

	FD_ZERO( &rfds );
	FD_SET( sock, &rfds );

	start_time = time(NULL);

	while( select( FD_SETSIZE , &rfds, (fd_set *) 0, (fd_set *) 0, &tv) > 0) {
		i = read( sock, buff ,sizeof( buff )); 
		l += i;

		cur_time = time(NULL);

		if( i < 0) {
			close( sock );
			return 1;
		}

		if( l >= 8) 
			break;
			
		// resolving CLOSE_WAIT problems
		if( difftime(cur_time, start_time) > ap->rw_timeout) {
			close( sock );
			return 1;
		}

		
			
		usleep(3000);
		p += i;
	}

	if( memcmp(buff,"\x00\x5a", 2 ) == 0 ) {
		pthread_mutex_lock( &(ap->ad->appscan_result_mutex_lock) );
		fprintf(stderr,"\n Socks v4: %s (WORKING)\n\n", host);
		fflush( stderr );
		close(sock);
		pthread_mutex_unlock( &(ap->ad->appscan_result_mutex_lock) );

		return 1;
	}

	if( memcmp(buff,"\x00\x5c", 2 ) == 0 ) { 
		pthread_mutex_lock( &(ap->ad->appscan_result_mutex_lock) );
		fprintf(stderr,"\n Socks v4: %s (REQ IDENTD)\n\n", host);
		fflush( stderr );
		pthread_mutex_unlock( &(ap->ad->appscan_result_mutex_lock) );
	}

	if( memcmp(buff,"\x00\x5d", 2 ) == 0 ) {
		pthread_mutex_lock( &(ap->ad->appscan_result_mutex_lock) );
		fprintf(stderr,"\n Socks v4: %s (IDENTD USER)\n\n", host);
		fflush( stderr );
		pthread_mutex_unlock( &(ap->ad->appscan_result_mutex_lock) );
	}

	close(sock);
	return 0;
}


int appscan_socks_v5_scan_worker( const char * host, unsigned int port , appscan_params * ap)
{
	int sock = 0, flags = 0, i = 0, l = 0;
	char buff[2000] = {0};
	struct timeval tv;
	char * p = NULL;
	time_t cur_time;
	time_t start_time;
	unsigned int target_port = 0;

	fd_set rfds;

	memset( buff, 0, sizeof(buff));

	p = buff;
	l = 0;

	sock = appscan_net_connect(host, port, ap->connect_timeout);

	if( sock < 0 )
		return 0;

	// Testing V5 protocol
	// Requesting socks noauth.

	write(sock,"\x05\x01\x00",3);

	tv.tv_sec = ap->rw_timeout;
	tv.tv_usec = 0;

	flags = fcntl( sock, F_GETFL,0);
	flags |= O_NONBLOCK;
	fcntl( sock, F_SETFL, flags);
    
	FD_ZERO( &rfds );
	FD_SET( sock, &rfds );

    start_time = time(NULL);

	while( select( FD_SETSIZE , &rfds, (fd_set *) 0, (fd_set *) 0, &tv) > 0) {
		i = read( sock, buff ,sizeof( buff ));
		l += i;

		cur_time = time(NULL);

		if( i < 0) {
			close( sock );
			return 1;
		}

		if( l >= 2)
			break;

		// resolving CLOSE_WAIT problems
		if( difftime(cur_time, start_time) > ap->rw_timeout ) {
			close( sock );
			return 1;
		}



		usleep(3000);
		p += i;
	}

	if( memcmp(buff,"\x05\xFF", 2 ) == 0 ) {
		close(sock);
       	return 0;
	}

	memcpy(buff, "\x05\x01\x00\x01", 4);

	target_port = ntohs( ap->ad->appscan_socks_port_ip );

	memcpy(buff + 4, &ap->ad->appscan_socks_connect_ip[0], 1);
	memcpy(buff + 5, &ap->ad->appscan_socks_connect_ip[1], 1);
	memcpy(buff + 6, &ap->ad->appscan_socks_connect_ip[2], 1);
	memcpy(buff + 7, &ap->ad->appscan_socks_connect_ip[3], 1);
	memcpy(buff + 8, &target_port, 2);

	write(sock,buff,10);

	tv.tv_sec = ap->rw_timeout;
	tv.tv_usec = 0;

	flags = fcntl( sock, F_GETFL,0);
	flags |= O_NONBLOCK;
	fcntl( sock, F_SETFL, flags);

	FD_ZERO( &rfds );
	FD_SET( sock, &rfds );

	start_time = time(NULL);

	while( select( FD_SETSIZE , &rfds, (fd_set *) 0, (fd_set *) 0, &tv) > 0) {
		i = read( sock, buff ,sizeof( buff ));
		l += i;

		cur_time = time(NULL);

		if( i < 0) {
			close( sock );		
			return 1;
        }

        if( l >= 10)
			break;

		// resolving CLOSE_WAIT problems
		if( difftime(cur_time, start_time) > ap->rw_timeout ) {
			close( sock );
			return 1;
		}



       	usleep(3000);
		p += i;
	}

	if( memcmp(buff,"\x05\x00", 2 ) == 0 ) { 
		pthread_mutex_lock( &(ap->ad->appscan_result_mutex_lock) );
		fprintf(stderr,"\n Socks v5: %s (WORKING)\n\n", host);
		fflush( stderr );
		pthread_mutex_unlock( &(ap->ad->appscan_result_mutex_lock) );
	}

	close(sock);
	return 0;
		
}


int appscan_telnetd_scan_worker( const char * host, unsigned int port, appscan_params * ap )
{

	int sock = 0, flags = 0, ret = 0, count = 0, count2 = 1, index = 0;
	unsigned char telnet_packet[32] = {0};
	char final_output[1024] = {0};
	char banner[1024] = {0};
	unsigned char fingerprint[32] = {0};
	char * fp = 0;
	struct timeval tv;

	free(fp);
	fd_set rfds; 
	fd_set wfds;

	sock = appscan_net_connect(host, port, ap->connect_timeout);
	if ( sock < 0 )
		return 1;

	flags = fcntl( sock, F_GETFL,0);
	flags |= O_NONBLOCK;
	fcntl( sock, F_SETFL, flags);


	while (1) {

		memset(telnet_packet,'\0',sizeof(telnet_packet));

		FD_ZERO( &rfds );
		FD_SET( sock, &rfds );
		
		tv.tv_sec = ap->rw_timeout;
		tv.tv_usec = 0; 

		ret = select( FD_SETSIZE, &rfds, NULL, NULL, &tv ); 
		if ( ret <= 0 ) {
			#ifdef DEBUG
			fprintf( stderr, "Timeout elapsed or error occurred for telnetd read\n" );
			#endif
			close( sock );
			return 1;
		}

		ret = read( sock, telnet_packet, 1 );
		if ( ret <= 0 ) {
			close( sock );
			return 1;
		}
		
		if ( index < sizeof(fingerprint) ) {
			fingerprint[index]=telnet_packet[0];
			index++;
		}
		//Check IAC (interpret as command) command from server
		if ( telnet_packet[0] == 255 ) {

			FD_ZERO( &rfds );
			FD_SET( sock, &rfds );

			tv.tv_sec = ap->rw_timeout;
			tv.tv_usec = 0; 

			ret = select( FD_SETSIZE, &rfds, NULL, NULL, &tv );
			if ( ret <= 0 ) {
				#ifdef DEBUG
				fprintf( stderr, "Timeout elapsed or error occurred for telnetd read\n" );
				#endif
				close( sock );
				return 1;
			}
			ret = read( sock, telnet_packet+1, 2 );
			if ( ret <= 0 )
				return 1;

			if ( index + 1 < sizeof(fingerprint) ) {
				fingerprint[index]=telnet_packet[1];
				fingerprint[index+1]=telnet_packet[2];
				index+=2;
			}
			//Check for telnet "end of options" option
			if ( telnet_packet[1] == 255 )
				break;

			//Check for "DO" telnet command 
			if ( telnet_packet[1] == 253 ) {
				FD_ZERO( &wfds );
				FD_SET( sock, &wfds );
				
				tv.tv_sec = ap->rw_timeout;
				tv.tv_usec = 0; 

				ret = select( FD_SETSIZE, NULL, &wfds, NULL,  &tv );
				if ( ret <= 0 ) {
					#ifdef DEBUG
					fprintf( stderr, "Timeout elapsed or error occurred for telnetd write\n" );
					#endif
					close( sock );
					return 1;
				}

				//Answer with "WON'T" telnet command
				telnet_packet[1] = 252;
				ret = write( sock , telnet_packet, 3 );
				if ( ret <= 0 ) {
					close( sock );
					return 1;
				}
			}
		}
		else {

			if (index -1 >= 0 )
				fingerprint[index-1] = '\0'; 

			strncpy(final_output, (char *) telnet_packet, 1);
			
			break;
		}
		
	}

	FD_ZERO( &wfds );
	FD_SET( sock, &wfds );

	tv.tv_sec = ap->rw_timeout;
	tv.tv_usec = 0;
	
	ret = select( FD_SETSIZE, NULL, &wfds, NULL, &tv );
	if ( ret <= 0 ) {
		#ifdef DEBUG
		fprintf( stderr, "Timeout elapsed or error occurred for telnetd write\n" );
		#endif
		close( sock );
		return 1;
	}

	ret = write( sock, "\n\n", 2 );
	if ( ret <= 0 ) {
		close( sock );
		return 1;
	}

	FD_ZERO( &rfds );
	FD_SET( sock, &rfds );

	tv.tv_sec = ap->rw_timeout;
	tv.tv_usec = 0;
	
	ret = select( FD_SETSIZE, &rfds,  NULL, NULL, &tv );
	if ( ret <= 0 ) {
		#ifdef DEBUG
		fprintf( stderr, "Timeout elapsed or error occurred for telnetd read\n" );
		#endif
		close( sock );
		return 1;
	}

	ret = read( sock, banner, sizeof( banner ) - 2 );
	if ( ret <= 0 ) {
		close( sock );
		return 1;
	}

	#ifdef DEBUG
	fprintf (stderr, "Read %u banner bytes\n", ret);
	#endif
	
	while ( ( count < MIN(ret,sizeof(final_output)-1) ) ) {
		
		final_output[count2] = banner[count];
		count2++;
		count++;
	}	

	close( sock );

	if ( strlen( banner ) <= 2 ) {
		pthread_mutex_lock( &(ap->ad->appscan_result_mutex_lock) );
		fprintf(stderr, "\n %s:\n No valid output\n", host);
		fflush( stderr );
		pthread_mutex_unlock( &(ap->ad->appscan_result_mutex_lock) );
		return 0;

	}


	pthread_mutex_lock( &(ap->ad->appscan_result_mutex_lock) );
	fprintf(stderr, "\n Banner %s:\n", host);
	fprintf(stderr, " %s\n", final_output);

	fprintf(stderr, "\n Fingerprint %s:\n", host);
	count2 = 0;
	while ( count2 < index  ) {
		fprintf( stderr, " %02x", fingerprint[count2]);
		count2++;
	} 

	fprintf( stderr, "\n\n" );
	fflush( stderr );
	pthread_mutex_unlock( &(ap->ad->appscan_result_mutex_lock) );
	return 0;
}

int appscan_oracle_scan_worker( const char * host, unsigned int port, char * command, int len, appscan_params * ap )
{

	int sock = 0, flags = 0, i = 0, l = 0;
	char buff[2000] = {0};
	struct timeval tv;
	char * p = NULL;
	time_t cur_time;
	time_t start_time;

	fd_set rfds; 

	memset( buff, 0, sizeof(buff));

	p = buff;

	sock = appscan_net_connect(host, port, ap->connect_timeout);

	if( sock < 0 )
		return 0;

	write(sock,command, len );

	tv.tv_sec = ap->rw_timeout;
	tv.tv_usec = 0;

	flags = fcntl( sock, F_GETFL,0);
	flags |= O_NONBLOCK;
	fcntl( sock, F_SETFL, flags);

	FD_ZERO( &rfds );
	FD_SET( sock, &rfds );

    start_time = time(NULL);

	while( select( FD_SETSIZE , &rfds, (fd_set *) 0, (fd_set *) 0, &tv) > 0) {
		i = read( sock, buff ,sizeof( buff )); 
		l += i;

		cur_time = time(NULL);

		if( i < 0) {
			close( sock );
			return 0;
		}

		if( l >= 8) 
			break;
			
		// resolving CLOSE_WAIT problems
		if( difftime(cur_time, start_time) > ap->rw_timeout ) {
			close( sock );
			return 0;
		}

		
			
		usleep(3000);
		p += i;
	}

	if( l > 0 ) {
		pthread_mutex_lock( &(ap->ad->appscan_result_mutex_lock) );
		fprintf(stderr, "\nOracle response at ip: %s read %u bytes\n", host,l);
		fflush( stderr );
		pthread_mutex_unlock( &(ap->ad->appscan_result_mutex_lock) );
	}
	close(sock);
	return l;
}



void * appscan_monitoring_thread( void * params ) 
{

	#ifdef DEBUG 
	fprintf(stderr, " Monitoring appscan thread started\n");
	#endif

	appscan_descriptor * ad = params;

	do {
		
		usleep(1000000);
		
		pthread_mutex_lock( &(ad->appscan_total_scans_mutex_lock) );	
		#ifdef DEBUG
		fprintf( stderr, " Processed scans %d, Finished scans %d\n", ad->appscan_total_scans_num, ad->appscan_processed_scans_num ); 
		#endif
		fflush(stderr);
		if ( ad->appscan_processed_scans_num == ad->appscan_total_scans_num ) {
			#ifdef DEBUG
			fprintf(stderr," All scan threads terminated\n");
			fflush( stderr );
			#endif
			pthread_mutex_unlock( &(ad->appscan_total_scans_mutex_lock) );

			break;

		}


		pthread_mutex_unlock( &(ad->appscan_total_scans_mutex_lock) );	

	} while(1);

	return 0;
}

void appscan_create( appscan_descriptor * ad) 
{

	ad->appscan_total_scans_num = 0;

	ad->appscan_processed_scans_num = 0;

	memset(&ad->appscan_socks_connect_ip, 0, 4*sizeof(int));

	ad->appscan_socks_port_ip = 0;

	ad->appscan_socks_initialized = 0;

	ad->appscan_max_thread_num = APPSCAN_DEFAULT_THREAD_NUM;

	pthread_mutex_init( &(ad->appscan_result_mutex_lock), NULL);

	pthread_mutex_init( &(ad->appscan_total_scans_mutex_lock), NULL);


}

void * appscan_scan_worker( void * params ) 
{

	appscan_params * ap = params;

	switch (ap->type) {

		case TELNET:
					appscan_telnetd_scan_worker( ap->host, ap->port, ap );
					break;


		case ORACLE:
					if ( appscan_oracle_scan_worker( ap->host, ap->port, oraclecommand1, sizeof( oraclecommand1), ap ) < 1 )
						appscan_oracle_scan_worker( ap->host, ap->port, oraclecommand2, sizeof( oraclecommand2), ap ); 

					break;


		case SOCKS:
					appscan_socks_v4_scan_worker( ap->host, ap->port, ap);
					appscan_socks_v5_scan_worker( ap->host, ap->port, ap);
					break;

		default:
					break;
	}

	pthread_mutex_lock( &(ap->ad->appscan_total_scans_mutex_lock) );
	ap->ad->appscan_processed_scans_num++;	
	pthread_mutex_unlock( &(ap->ad->appscan_total_scans_mutex_lock) );

	appscan_params_destroy( ap );

	return 0;

}

void appscan_set_thread_num( appscan_descriptor * ad , unsigned int num ) 
{
	
	if ( num < APPSCAN_MAX_THREAD_NUM ) 
		ad->appscan_max_thread_num = num;
	else
		ad->appscan_max_thread_num = APPSCAN_MAX_THREAD_NUM;

}

void * appscan_run_scan_thread( void * parms ) 
{
	
	int ret = 0;
	pthread_t thread;
	
	appscan_params * ap = parms;

	do {

		pthread_mutex_lock( &(ap->ad->appscan_total_scans_mutex_lock) );
		if ( (ap->ad->appscan_total_scans_num - ap->ad->appscan_processed_scans_num) < ap->ad->appscan_max_thread_num ) {
			
			ap->ad->appscan_total_scans_num++;
			ret = pthread_create( &thread, NULL, appscan_scan_worker, parms );
			if (  ret ) {
				fprintf(stderr, "Problem in starting thread\n");
				ap->ad->appscan_total_scans_num++;
			}
	
			#ifdef DEBUG 
			fprintf(stderr, "Thread %u started\n", ap->ad->appscan_total_scans_num);
			#endif
			
			break;
		}

		pthread_mutex_unlock( &(ap->ad->appscan_total_scans_mutex_lock) );

		#ifdef DEBUG
		fprintf(stderr, "Wait for scan threads");
		#endif
		usleep(500000);

	} while(1);
	
	pthread_mutex_unlock( &(ap->ad->appscan_total_scans_mutex_lock) );
	
	return 0;
}

int appscan_run_scan(appscan_type type, appscan_descriptor * ad, const char * host, unsigned int port, unsigned int connect_timeout, unsigned int rw_timeout )
{

	pthread_t thread;
	int ret = 1;

	if ( host == NULL || port > 65535 || !connect_timeout || !rw_timeout  )
		return ret;

	//SOCKS connect IP and PORT not initialized 
	if ( ( type == SOCKS ) && ( ! ad->appscan_socks_initialized ) ) {
		return ret;
	}

	appscan_params *parms = appscan_params_create( ad, type, host, port, connect_timeout, rw_timeout); 

	//if ( ! (ret = pthread_create( &thread, NULL, appscan_scan_worker, (void*) parms ) ) ) 
	if ( ! (ret = pthread_create( &thread, NULL, appscan_run_scan_thread, (void*) parms ) ) ) { 
		pthread_join( thread, NULL );
	}

	return ret;

}


void appscan_wait_scans_results(appscan_descriptor * ad)
{

	
	pthread_t thread;

	//Run monitoring thread and wait for appscan_total_scans_results == appscan_processed_scans_num
	if ( pthread_create( &thread, NULL, &appscan_monitoring_thread, ad) ) {
		//Manage failed creation of monitoring thread
		pthread_exit(NULL);
		return;
	}

	pthread_join( thread, NULL );
	
}


void appscan_destroy(appscan_descriptor * ad) {

	pthread_mutex_destroy( &(ad->appscan_result_mutex_lock) );

	pthread_mutex_destroy( &(ad->appscan_total_scans_mutex_lock) );

}


appscan_params * appscan_params_create( appscan_descriptor * ad, appscan_type type, const char * host , unsigned int port, unsigned int connect_timeout, unsigned int rw_timeout) 
{

	#ifdef SOLARIS
	pthread_setconcurrency( 4 );
	#endif 

	appscan_params *ap = (appscan_params *) malloc( sizeof(appscan_params) );

	ap->type = type;

	memset(ap->host,'\0', APPSCAN_IPV4_MAX_SIZE );
	
	memcpy( ap->host, host, MIN( strlen(host), APPSCAN_IPV4_MAX_SIZE - 1 ) );	

	ap->port = port;
	
	ap->connect_timeout = connect_timeout;

	ap->rw_timeout = rw_timeout;

	ap->ad = ad;

	return ap;
}


void appscan_params_destroy( appscan_params *ap ) 
{
	
	if ( ap != NULL )
		free(ap);

	ap=NULL;	

}

