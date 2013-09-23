/*****************************************************************************
 * singsing.c is a part of singsing project                                  *
 *                                                                           *
 * $Id:: singsing.c 30 2009-12-14 13:39:53Z inode_                        $: *
 *                                                                           *
 * Copyright (c) 2007, Agazzini Maurizio - inode@mediaservice.net            *
 * All rights reserved.                                                      *
 *                                                                           *
 * Redistribution and use in source and binary forms, with or without        *
 * modification, are permitted provided that the following conditions        *
 * are met:                                                                  *
 *     * Redistributions of source code must retain the above copyright      *
 *       notice, this list of conditions and the following disclaimer.       *
 *     * Redistributions in binary form must reproduce the above copyright   *
 *       notice, this list of conditions and the following disclaimer in     *
 *       the documentation and/or other materials provided with the          *
 *       distribution.                                                       *
 *     * Neither the name of @ Mediaservice.net nor the names of its         *
 *       contributors may be used to endorse or promote products derived     *
 *       from this software without specific prior written permission.       *
 *                                                                           *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS       *
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT         *
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR     *
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT      *
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,     *
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED  *
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR    *
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF    *
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING      *
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS        *
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.              *
 *****************************************************************************/

#include "singsing.h"
#include "singsing_p.h"

// Taken on an ethernet layer
#define SYN_SIZE	58
//#define DEBUG 1

void singsing_get_addresses_to_scan_from_file( const char * filename ) {
	fprintf(stderr,"To be implemented\n");
}

void singsing_parse_addresses_to_exclude_file( struct singsing_descriptor * fd, char * addresses_file_name )
{

	FILE * file = NULL;
	char line[1024]={0};
	int type = 0;
	unsigned long ipaddr = 0;

	if ( addresses_file_name == NULL )
		return;

	file = fopen( addresses_file_name , "r+" );

	if ( file == NULL ) {
		fprintf(stderr, "\n Cannot open file %s\n", addresses_file_name);
		exit(EXIT_FAILURE);
	}

	while ( fgets( line, 1024 ,  file )  != 0 ) {
			
		line[ strlen(line) - 1 ] = '\0';

		type=singsing_validate_ipv4( line );

		if ( type == IP_FOUND ) { 
			ipaddr = ntohl((unsigned long) inet_addr(line)); 
			singsing_add_address_to_exclude( fd, ipaddr );
		}
		else if ( type == NETMASK_FOUND ) {
			singsing_add_netmask_to_exclude( fd, line );	
		}
		else
			fprintf(stderr, " Warning! %s is not a valid address\n", line); 
		

	}

	fclose(file);
}


int singsing_check_ipv4( const char * ipv4 ) 
{
	
		struct sockaddr_in sa;

   		return inet_pton(AF_INET, ipv4, &(sa.sin_addr));

}

int singsing_validate_ipv4( const char * ipv4)
{

	struct sockaddr_in sa;
	
	char *tmp = 0, *to_strtok = 0;

	unsigned int mask = 0, netid = 0, netmask = 0, hostid = 0, hostmask = 0;

	if ( ipv4 == NULL )
		return NO_ADDRESS_FOUND;

	if ( strchr( ipv4, '/') != NULL  ) {
		
		tmp = strdup(ipv4);

		to_strtok = strtok(tmp,"/");
			
		ipv4 = to_strtok;

		to_strtok = strtok(NULL,"/");

		if ( ( to_strtok == NULL ) || ! ( strspn(to_strtok,"0123456789") == strlen(to_strtok ) ) ) {
			free(tmp);
			return NO_ADDRESS_FOUND;
		}
		
		sscanf(to_strtok, "%u", &mask);
		if ( !mask || mask > 32 ) {
			free(tmp);
			return NO_ADDRESS_FOUND;
		}

		if ( ! singsing_check_ipv4( ipv4 ) ) {
			free(tmp);
			return NO_ADDRESS_FOUND;
		}

		inet_aton(ipv4, &(sa.sin_addr));

		netmask = (unsigned int) ( (0xffffffff ) << (32 - mask) );

		hostmask = (unsigned int) ( (0xffffffff ) >> (mask) );

		netid = (unsigned int)ntohl((unsigned int) (sa.sin_addr.s_addr << (32 - mask) ) >> (32-mask));

		hostid = (unsigned int)ntohl((unsigned int) (sa.sin_addr.s_addr >> ( mask) ) << (mask));
		
		free(tmp);

		if ( (netmask<32) && ( !  ((netid & netmask)==netid) || (hostid & hostmask) ) ) {
			fprintf(stderr, "pippo\n");
			return NO_ADDRESS_FOUND;
		}
		else
			return NETMASK_FOUND;

	} 

   	if ( ! singsing_check_ipv4 (ipv4 ) )
		return NO_ADDRESS_FOUND;

	return IP_FOUND;

}

/* Calculate checksum, taken from the net */
int singsing_checksum(unsigned short* data, int length)
{
        register int nleft=length;
        register unsigned short *w = data;
        register int sum=0;
        unsigned short answer=0;

        while (nleft>1)
        {
                sum+=*w++;
                nleft-=2;
        }

        if (nleft==1)
        {
                *(unsigned char *)(&answer) = *(unsigned char *)w;
                sum+=answer;
        }

        sum=(sum>>16) + (sum & 0xffff);
        sum +=(sum>>16);
        answer=~sum;

        return answer;
}

/* Calculate TCP checksum */
unsigned short singsing_in_cksum_tcp(int src, int dst, unsigned short *addr, int len)
{
        struct singsing_psd_tcp buf;
        u_short ans;

        memset(&buf, 0, sizeof(buf));
        buf.src.s_addr = src;   
        buf.dst.s_addr = dst;
        buf.pad = 0;    
        buf.proto = IPPROTO_TCP;
        buf.tcp_len = htons(len);
        memcpy(&(buf.tcp), addr, len);
        ans = singsing_checksum((unsigned short *)&buf, 12 + len);
        return (ans);
}


/* Hey, remember to use free! */
struct singsing_result_queue * singsing_get_result( struct singsing_descriptor * fd ) {

	struct singsing_result_queue * cur = NULL;
	struct singsing_result_queue * cur_old = NULL;

	time_t cur_time;

	cur_time = time(NULL);

	pthread_mutex_lock(&fd->singsing_result_queue_lock);

	cur = fd->singsing_first_result;
	cur_old = NULL;

	if( fd->singsing_scan_mode & SINGSING_NODUP_SCAN ) {
		while( cur != NULL ) {

			if( difftime( cur_time, cur->rec_time) > SINGSING_TIMEOUT )
				break;

			cur_old = cur;
			cur = cur->next;
		}
	}

	if( cur != NULL ) {
	
		if( cur_old != NULL )
			cur_old->next = cur->next;

		if( cur == fd->singsing_first_result ) 
			fd->singsing_first_result = fd->singsing_first_result->next;

		if( cur == fd->singsing_last_result ) 
			fd->singsing_last_result = cur_old;

		if( fd->singsing_first_result == NULL )
			fd->singsing_last_result = NULL;

	}

	pthread_mutex_unlock(&fd->singsing_result_queue_lock);

	return cur;
}

int singsing_add_netmask_to_exclude( struct singsing_descriptor * fd, char * netaddr ) {

	unsigned long interval = 0, i = 0, ipaddr = 0;
	unsigned long masknum = 0;
	char * addr = NULL, * mask = NULL, * tmp = NULL;
	struct singsing_address_to_exclude_list * new_address_net = 0;
	
	tmp = strdup(netaddr);
	addr = strtok(tmp, "/");
	if ( addr == NULL )
		return 1;

	mask = strtok(NULL,"/");
	if (mask==NULL)
		return 1;

	*(mask - 1) = '\0';

	masknum = (unsigned long) atol(mask);

	interval = ( 1<<(32 - masknum) ) - 1;
			
	if ( fd->singsing_first_addr_to_excl == NULL ) {
			new_address_net = (struct singsing_address_to_exclude_list *) malloc(sizeof(struct singsing_address_to_exclude_list));
		    new_address_net->addr = ntohl((unsigned long) inet_addr(addr));
			new_address_net->next = NULL;
   			new_address_net->prev = NULL;
    		new_address_net->interval = interval;
			fd->singsing_first_addr_to_excl = new_address_net;
			fd->singsing_last_addr_to_excl = new_address_net;
			fd->singsing_excluded_addresses_nodes++;
			fd->singsing_addresses_excluded_total += interval + 1;
	}
	else {

		ipaddr = ntohl((unsigned long) inet_addr(addr)); 
				
		while ( i<=interval ) {

			singsing_add_address_to_exclude( fd, ipaddr+i );
			i++;
		}	
	}
	free(tmp);

	return 0;
}

//Add list of addresses to exclusion list
int singsing_add_address_to_exclude( struct singsing_descriptor * fd, unsigned long address)
{

	struct singsing_address_to_exclude_list * new_address = 0;

	struct singsing_address_to_exclude_list * cur = NULL, * tmp = NULL;

	new_address = (struct singsing_address_to_exclude_list *) malloc(sizeof(struct singsing_address_to_exclude_list));

	//Setting up struct content

	new_address->addr = address; 

	new_address->next = NULL;
	new_address->prev = NULL;
	new_address->interval = 0;
	
	if ( fd->singsing_first_addr_to_excl == NULL ) {
		fd->singsing_first_addr_to_excl = new_address;
		fd->singsing_last_addr_to_excl = new_address;
	}
	else {
		
		if ( new_address->addr > fd->singsing_last_addr_to_excl->addr )
			cur = NULL;
		else {

			cur = fd->singsing_first_addr_to_excl;		

			while ( (cur != NULL) && (cur->addr < new_address->addr) ) 
				cur = cur->next;

		}
		
		if ( ( cur != NULL &&(  (cur->addr == new_address->addr) || (cur->prev!=NULL && ( new_address->addr <= (cur->prev->addr + cur->prev->interval) ) ) ) ) || ( cur==NULL && ( new_address->addr <= (fd->singsing_last_addr_to_excl->addr + fd->singsing_last_addr_to_excl->interval ) ) ) ) {
			singsing_print_ip_from_value( address, "Warning! Duplicated address");
			return 1;
		}

		if ( cur == fd->singsing_first_addr_to_excl ) {
			//Insert at init
			if ( fd->singsing_first_addr_to_excl->addr - 1 == new_address->addr ) {
				fd->singsing_first_addr_to_excl->addr = new_address->addr;
				fd->singsing_first_addr_to_excl->interval++;
				fd->singsing_excluded_addresses_nodes--;
				free(new_address);
			} 
			else {
				new_address->next = fd->singsing_first_addr_to_excl;
				fd->singsing_first_addr_to_excl->prev = new_address;
				fd->singsing_first_addr_to_excl = new_address;
			}
		}
		else if ( cur == NULL ) {
				
			if ( new_address->addr <= ( fd->singsing_last_addr_to_excl->addr + fd->singsing_last_addr_to_excl->interval + 1) ) {
				fd->singsing_last_addr_to_excl->interval++;	
				fd->singsing_excluded_addresses_nodes--;
				free(new_address);
			}
			else {
				//Insert at end
				new_address->prev = fd->singsing_last_addr_to_excl;
				fd->singsing_last_addr_to_excl->next = new_address;
				fd->singsing_last_addr_to_excl = new_address;
			}
		}
		else {
			if ( new_address->addr == ( cur->addr - 1) ) {  
				cur->interval++;
				cur->addr = new_address->addr;
				fd->singsing_excluded_addresses_nodes--;
				
				if ( cur->addr == cur->prev->addr + cur->prev->interval + 1 ) {
					
					cur->prev->interval += cur->interval+1;

					if (cur->next == NULL) {
						fd->singsing_last_addr_to_excl = cur->prev;
						cur->prev->next = NULL;
					} 
					else {
						cur->prev->next = cur->next;
						cur->next->prev = cur->prev;
					}

					free(cur);
					fd->singsing_excluded_addresses_nodes--;

				}
			}
			else if ( new_address->addr <= ( cur->prev->addr + cur->prev->interval + 1 ) ) {
				cur->next->addr = new_address->addr;
				cur->next->interval++;
				fd->singsing_excluded_addresses_nodes--;
	
			}
			else {
				//Insert in the middle
				tmp = cur->prev;
				new_address->next=cur;
				cur->prev=new_address;
				tmp->next=new_address;
				new_address->prev=tmp;
			}
		}
	}

	fd->singsing_excluded_addresses_nodes++;
	fd->singsing_addresses_excluded_total++;

	return 0;
}

// Add port to scan
int singsing_add_port( struct singsing_descriptor * fd, unsigned int port )
{
	struct singsing_port_list * new_port;

	// XXX fix malloc error code
	new_port = (struct singsing_port_list *)malloc(sizeof(struct singsing_port_list));

	new_port->port = port;
	new_port->next = NULL;

	if( fd->singsing_first_port == NULL ) {
		fd->singsing_first_port = new_port;
		fd->singsing_last_port = fd->singsing_first_port;
	} else {
		fd->singsing_last_port->next = new_port;
		fd->singsing_last_port = new_port;
	}

	fd->singsing_ports++;

	return 0;
}


/* Receive packet and allocate the needed memory */
void singsing_packet_rec(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
        struct singsing_packet_queue * new_packet_queue; 
        u_char * new_packet;

	struct singsing_descriptor * fd = (struct singsing_descriptor *)args;

        new_packet_queue = malloc( sizeof(struct singsing_packet_queue) );

        new_packet_queue->next = NULL;
        new_packet_queue->len = pkthdr->caplen;

        new_packet = malloc( pkthdr->caplen );

        new_packet_queue->packet = new_packet;

        memcpy( new_packet, packet, pkthdr->caplen);

        pthread_mutex_lock(&fd->packet_queue_lock);

        if( fd->singsing_last_packet != NULL ) {
                fd->singsing_last_packet -> next = new_packet_queue;
                fd->singsing_last_packet = new_packet_queue;
        } else {
                fd->singsing_last_packet = new_packet_queue;
                fd->singsing_first_packet = new_packet_queue;
        }

        pthread_mutex_unlock(&fd->packet_queue_lock);
}

/* Thread processing received packet */
void * singsing_processing_thread(void *parm)
{

	struct singsing_packet_queue * tmp_queue = NULL;
	struct singsing_result_queue * singsing_result_tmp = NULL;
	struct singsing_result_queue * singsing_result_scan = NULL;
	int lltype;

	struct singsing_descriptor * fd = parm;

	struct ip ip_p;
	struct tcphdr tcp_p;

// Decrease thread priority, receiving packet thread must be the faster
//        set_thread_priority( 99 );

        while (1) {
                if( tmp_queue != NULL ) {
                        free( (char *)tmp_queue->packet );
                        free( tmp_queue );
                        tmp_queue = NULL;
                }
                pthread_mutex_lock(&fd->packet_queue_lock);

                if( fd->singsing_first_packet == NULL ) {
                        pthread_mutex_unlock(&fd->packet_queue_lock);
                        usleep( 10000 );
                        if( fd->singsing_finished == 1 ) {
				fd->singsing_finished = 2;
                                return NULL;
                        }
                        continue;
                } 

                tmp_queue = fd->singsing_first_packet;

                fd->singsing_first_packet = fd->singsing_first_packet->next;

                if( fd->singsing_first_packet == NULL )
                        fd->singsing_last_packet = NULL;

                pthread_mutex_unlock(&fd->packet_queue_lock);

                lltype = pcap_datalink(fd->singsing_descr);

                switch(lltype) {
                        case DLT_EN10MB:
				memcpy( &ip_p, (tmp_queue->packet + sizeof(struct ether_header)), \
					sizeof(ip_p) );
				memcpy( &tcp_p , (tmp_queue->packet + sizeof(struct ether_header) \
					 + sizeof( struct ip )), sizeof(tcp_p) );
                                break;
                        case DLT_LINUX_SLL:
                                memcpy( &ip_p, (tmp_queue->packet + sizeof(struct ether_header) ) + 2, \
					sizeof(ip_p)  );
                                memcpy( &tcp_p , (tmp_queue->packet + sizeof(struct ether_header) + \
					sizeof( struct ip )) +2, sizeof(tcp_p) );
                                break;

                        default: 
                                fprintf(stderr, "error: unsupported link-layer type: %s\n", \
					pcap_datalink_val_to_name(lltype));
                                break;
                }
                /* Not an ethernet packet */
                if( tmp_queue->len < 14 )
                        continue;

                 /* IPv4 check */
		if( ip_p.ip_v != 4 )
                        return NULL;

                // Try to fix with PUSH FLASG?
		// If the packet it's an ACK we fill the result queue
		if( ((tcp_p.th_flags & TH_RST) && (fd->singsing_scan_mode & SINGSING_SHOW_CLOSED)) || 
			( (tcp_p.th_flags & TH_ACK) && !(tcp_p.th_flags & TH_RST) )){

#ifdef DEBUG
if( tcp_p.th_flags & TH_RST )
	fprintf(stderr, " close %s:%u\n",inet_ntoa(ip_p.ip_src),ntohs( tcp_p.th_sport ));
else
	fprintf(stderr, " open %s:%u\n",inet_ntoa(ip_p.ip_src),ntohs( tcp_p.th_sport ));
#endif

			singsing_result_tmp = malloc( sizeof( struct singsing_result_queue) );
			// XXX FIX MALLOC ERROR
			singsing_result_tmp->next = NULL;
			//singsing_result_tmp->port = ntohs( tcp_pack->th_sport );
			singsing_result_tmp->port = ntohs( tcp_p.th_sport );
			singsing_result_tmp->rec_time = time( NULL );
			// XXX SET IP
			//singsing_result_tmp->ip = htonl( ip_pack->ip_src.s_addr );
			singsing_result_tmp->ip = htonl( ip_p.ip_src.s_addr );

			if( (tcp_p.th_flags & TH_RST) )
				singsing_result_tmp->type = SINGSING_CLOSE;
			else
				singsing_result_tmp->type = SINGSING_OPEN;
			
			pthread_mutex_lock(&fd->singsing_result_queue_lock);


			if( fd->singsing_scan_mode & SINGSING_NODUP_SCAN ) {
				singsing_result_scan = fd->singsing_first_result;

#ifdef DEBUG
fprintf(stderr, " scanning for dups\n");
#endif

				while( singsing_result_scan != NULL ) {

					if( singsing_result_scan->ip == singsing_result_tmp->ip 
						&& singsing_result_scan->port == singsing_result_tmp->port) {
#ifdef DEBUG
fprintf(stderr, " dup found\n");
#endif
						free( singsing_result_tmp );
						singsing_result_tmp = NULL;
						break;
					} else 
						singsing_result_scan = singsing_result_scan->next;
				}
			}

			// Adding result structure to the queue
			if( singsing_result_tmp != NULL ) {

				if( fd->singsing_last_result != NULL ) 
					fd->singsing_last_result->next = singsing_result_tmp;
				else
					fd->singsing_first_result = singsing_result_tmp;

				fd->singsing_last_result = singsing_result_tmp;

#ifdef DEBUG
fprintf(stderr, " packet insered in result queue\n");
#endif


			} 

			pthread_mutex_unlock(&fd->singsing_result_queue_lock);

                }

                fflush(stdout);

        }
}


int singsing_init( struct singsing_descriptor * fd )
{
	int on = 1;
	
	struct timeval first,second;
	unsigned long k;

	singsing_bind_port(fd, 1);

	#ifdef SOLARIS
	pthread_setconcurrency( 4 );
	#endif 

	if(fd->singsing_start_ip == 0 || fd->singsing_end_ip == 0 )
		return -1;

	if( fd->singsing_device == NULL )
		return -3;

	/* Create exclusion list from file*/

	singsing_create_address_to_exclude_list(fd);

	#ifdef DEBUG
	singsing_print_avl(fd->singsing_address_excluded_root);
	#endif

	srand( time(NULL) );

	if( (fd->singsing_raw_socket = socket( AF_INET, SOCK_RAW, IPPROTO_RAW )) < 0 ) {
		fprintf( stderr, "error in creating raw sockets\n");
		exit( EXIT_FAILURE );
	}
	

        if (setsockopt(fd->singsing_raw_socket,IPPROTO_IP,IP_HDRINCL,(char *)&on,sizeof(on)) < 0) 
        {
                perror("setsockopt: IP_HDRINCL");
                exit(1);
        }


	/* create sniffing thread */
	if( pthread_create( &fd->singsing_thread_id[0], NULL, &singsing_sniff_thread, fd) != 0 ) {
		fprintf(stderr, "Can't create sniffing thread\n");
		exit( EXIT_FAILURE );
        }

	/* create processin thread */
        if( pthread_create( &fd->singsing_thread_id[1], NULL, &singsing_processing_thread, fd) != 0 ) {
                fprintf(stderr, "Can't create processing thread\n");
                exit( EXIT_FAILURE );
        }

	// Waiting for thread creation
	sleep(1);

	fd->singsing_source_ip = singsing_get_ip( fd, fd->singsing_device );

	fd->singsing_synps = (fd->singsing_band * 1024) / SYN_SIZE;

	fd->singsing_cur_status.synps = fd->singsing_synps;

	// Testing sending syn timing

#ifdef DEBUG	
	fprintf(stderr, " SYN: %lu host to scan on %u ports. AVG= %lu syn/s\n", fd->singsing_end_ip \
		- fd->singsing_start_ip + 1, fd->singsing_ports, fd->singsing_synps);
	fprintf(stderr, " SYN: min port: %u max port: %u\n", fd->singsing_min_port, fd->singsing_max_port);
#endif
	
	gettimeofday( &first, NULL);

	for( k=0 ; k<fd->singsing_synps ;k++ ) {
                singsing_send_syn( fd->singsing_raw_socket,  fd->singsing_source_ip, fd->singsing_source_ip , 22, fd);
	}	

	gettimeofday( &second, NULL);

	fd->singsing_sleep_band = (second.tv_sec * 1000000 + second.tv_usec) - (first.tv_sec * 1000000 + first.tv_usec); 
	
	fd->singsing_sleep_band = (1000000 - fd->singsing_sleep_band) / (fd->singsing_synps/10);

#ifdef DEBUG
 	fprintf(stderr, "Sleep of every 10 packets: %lu\n", fd->singsing_sleep_band);
#endif
	
        // fill status struct
        fd->singsing_cur_status.total_port = fd->singsing_ports * (fd->singsing_end_ip + 1 - fd->singsing_start_ip);
        fd->singsing_cur_status.current_port = 0;
        fd->singsing_cur_status.init_time = time(NULL);
        fd->singsing_cur_status.synps = fd->singsing_synps;

	/* create send syn thread */
        if( pthread_create( &fd->singsing_thread_id[2], NULL, &singsing_send_syn_thread, fd) != 0 ) {
                fprintf(stderr, "Can't create send_syn thread\n");
                exit( EXIT_FAILURE );
        }
	
	return 0;
}

void singsing_print_avl( struct singsing_addresses_excluded_tree * root) 
{

	if ( root == NULL)
		return;
	
	if ( root->leftChild != NULL )
		singsing_print_avl(root->leftChild);

	if ( root->rightChild != NULL)
		singsing_print_avl(root->rightChild);
}

void singsing_print_ip_from_value(unsigned long ip, char * text) 
{
        struct in_addr addr;
        addr.s_addr = ntohl(ip);
        char *str_ip = inet_ntoa(addr);

		if ( text != NULL )
        	fprintf(stderr,"%s: %s\n",text,str_ip);
}
void singsing_destroy_avl( struct singsing_addresses_excluded_tree * root ) 
{
	if ( root == NULL )
		return;

	if ( root->leftChild != NULL ) 
		singsing_destroy_avl( root->leftChild );

	if ( root->rightChild != NULL )
		singsing_destroy_avl( root->rightChild );

	#ifdef DEBUG
	singsing_print_ip_from_value( root->value, "Freeing AVL");	
	#endif
	free(root);
	return;
}


unsigned long singsing_get_min_avl_node( struct singsing_descriptor * fd ) 
{
	int count = 0;
	struct singsing_addresses_excluded_tree * node = fd->singsing_address_excluded_root;

	while ( node != NULL && node->leftChild != NULL ) {
		node = node->leftChild;
		count++;
	}

	#ifdef DEBUG
	singsing_print_ip_from_value(node->value, "Min Avl Value");	
	fprintf(stderr, "Cost search min %d\n", count);
	#endif
	return node->value;
}


unsigned long singsing_get_max_avl_node( struct singsing_descriptor * fd ) 
{
	int count = 0;
	struct singsing_addresses_excluded_tree * node = fd->singsing_address_excluded_root;

	while ( node != NULL && node->rightChild != NULL ) {
		node = node->rightChild;
		count++;
	}

	#ifdef DEBUG
	singsing_print_ip_from_value(node->value + node->interval, "Max Avl Value");	
	fprintf(stderr, "Cost max search %d\n", count);
	#endif
	return node->value + node->interval;

}


struct singsing_addresses_excluded_tree * singsing_create_avl_node( unsigned long value, unsigned long interval) {



	struct singsing_addresses_excluded_tree * node = ( struct singsing_addresses_excluded_tree * ) malloc (sizeof(struct singsing_addresses_excluded_tree));
	
	node->value = value;
	node->leftChild = NULL;
	node->rightChild = NULL;
	node->interval = interval;
	
	return node;

}

struct singsing_addresses_excluded_tree * singsing_create_avl( struct singsing_address_to_exclude_list * list_start,  int length) 
{

	struct singsing_addresses_excluded_tree * root = NULL;
	root = singsing_create_avl_worker(list_start, length );
	return root;
	
}


struct singsing_addresses_excluded_tree * singsing_create_avl_worker(  struct singsing_address_to_exclude_list * start_node, int length) 
{

	int mid = 0, index = 1;
	struct singsing_address_to_exclude_list * tmp = NULL;
	struct singsing_addresses_excluded_tree * root = NULL;

	if ( length <= 0 )
		return NULL;

	if ( length%2 != 0)
		mid = length/2 + 1;
	else
		mid = length/2;
	
	tmp = start_node;

	while ( index < mid ) {
		tmp = tmp->next;
		index++;
	}

	root = singsing_create_avl_node( tmp->addr, tmp->interval );

	root->leftChild = singsing_create_avl_worker(start_node, mid -1 );
	root->rightChild = singsing_create_avl_worker( tmp->next, length - mid );

	return root;

}


void singsing_create_address_to_exclude_list(struct singsing_descriptor * fd) 
{
	

	// Exclusion list not present or single ip to scan
	if (!fd->singsing_excluded_addresses_nodes || fd->singsing_input_address_type == IP_FOUND )
		return; 

	if ( fd->singsing_addresses_excluded_total == fd->singsing_end_ip - fd->singsing_start_ip + 1 ) {
		fprintf(stderr, "Nothing to scan! All addresses in list excluded\n");
		exit(EXIT_FAILURE);
	}

	if ( ( fd->singsing_first_addr_to_excl->addr < fd->singsing_start_ip ) || ( fd->singsing_last_addr_to_excl->addr +  fd->singsing_last_addr_to_excl->interval > fd->singsing_end_ip )  ) {
		
		fprintf(stderr, "Error! Trying to exclude addresses not in range\n");	
		exit(EXIT_FAILURE);
	}


	if ( fd->singsing_excluded_addresses_nodes ) {

		//  Build AVL
		fd->singsing_address_excluded_root = singsing_create_avl(fd->singsing_first_addr_to_excl, fd->singsing_excluded_addresses_nodes);

		// Set minimum AVL value
		fd->singsing_min_addr_excluded = singsing_get_min_avl_node(fd);

		// Set maximum AVL value
		fd->singsing_max_addr_excluded = singsing_get_max_avl_node(fd);

	}
	//build AVL tree (create recursive function)
	singsing_destroy_address_to_exclude_list(fd);

}

int address_not_excluded(struct singsing_descriptor * fd, unsigned long ip) 
{
	
	struct singsing_addresses_excluded_tree * addr = NULL;

	if ( ( ! fd->singsing_excluded_addresses_nodes ) || ( ip < fd->singsing_min_addr_excluded ) || ( ip > fd->singsing_max_addr_excluded ) ) {
		return 1;
	}

	addr = fd->singsing_address_excluded_root;
	
	//AVL binary tree search alghoritm
	while (addr!= NULL) {
		
		if ( ip >= addr->value && ip <= ( addr->value + addr->interval ) ) {
			return 0;
		}

		if ( ip < addr->value )
			addr = addr->leftChild;
		else
			addr = addr->rightChild;
			
	}

	return 1;
}

void * singsing_send_syn_thread(void *parm)
{
	unsigned long c =0 ;
	struct singsing_port_list * tmp_port = NULL;
	unsigned long tmp_ip = 0;
	unsigned long passo = 1;
	unsigned long start_count = 0;

	struct timeval first;
	struct timeval second;

	struct singsing_descriptor * fd = parm;


#ifdef DEBUG
	time_t start_time;
	time_t end_time;
	unsigned long singsing_sleep_band_init = singsing_sleep_band_init;

	start_time = time(NULL);

#endif

	if( fd->singsing_scan_mode & SINGSING_SEGMENT_SCAN )
		passo = (fd->singsing_end_ip - fd->singsing_start_ip) / fd->singsing_synps;

	if( passo == 0) 
		passo = 1;

#ifdef DEBUG
	if( fd->singsing_scan_mode & SINGSING_SEGMENT_SCAN )
		fprintf(stderr, "passo scan as been set to: %lu\n",passo);
#endif 


	fd->singsing_cur_status.init_time = time( NULL );
	
	tmp_port = fd->singsing_first_port;

	gettimeofday( &first, NULL);
	usleep( fd->singsing_sleep_band );

	while( tmp_port != NULL ) {

		tmp_ip = fd->singsing_start_ip;

		start_count = 1;

		while( tmp_ip <= fd->singsing_end_ip ) {

			if ( address_not_excluded(fd,tmp_ip)) { 
				singsing_send_syn( fd->singsing_raw_socket,  htonl(tmp_ip), fd->singsing_source_ip, \
					tmp_port->port, fd);
					
			}
			else {
				tmp_ip+=passo;
				continue;
			}

			fd->singsing_cur_status.current_port++;

			if( c >= 10 ) {
				//sleep time auto correction
				long messo, sleepb;
				sleepb = fd->singsing_sleep_band;
				gettimeofday( &second, NULL);

				messo = (second.tv_sec * 1000000 + second.tv_usec) - (first.tv_sec * 1000000 + first.tv_usec);
#ifdef DEBUG

// This debug feature as been disabled, too many output
//printf("done in %lu, teor in %lu\n",messo,1000000/(singsing_synps/10));
//sleep(1);

#endif
				if( sleepb - (messo-1000000/((long)fd->singsing_synps/10)) < 0 ){
					fd->singsing_sleep_band = 10;
				 } else {
					fd->singsing_sleep_band -= messo-1000000/(fd->singsing_synps/10);
				}

				gettimeofday( &first, NULL);
				usleep( fd->singsing_sleep_band );
				c = 0;
				
			} else
				c++;

			tmp_ip += passo;

			if( fd->singsing_scan_mode & SINGSING_SEGMENT_SCAN && tmp_ip > fd->singsing_end_ip) {
	
				tmp_ip = fd->singsing_start_ip + start_count;

				start_count ++;
				// in this case we have scanned all ip
				if( tmp_ip == fd->singsing_start_ip + passo )
					tmp_ip = fd->singsing_end_ip + 1;
			}
		
		}
	        tmp_port = tmp_port->next;

        }


#ifdef DEBUG
        end_time = time(NULL);

	fprintf( stderr, "\n SYN: %lu syn sent in %.0lf seconds, AVG= %.0lf syn/s\n\n", \
		(fd->singsing_end_ip - fd->singsing_start_ip + 1)*fd->singsing_ports,difftime(end_time, start_time), \
		(fd->singsing_end_ip - fd->singsing_start_ip)*fd->singsing_ports/difftime(end_time, start_time));
#endif

	sleep( SINGSING_TIMEOUT + 15 );	

	fd->singsing_finished = 1;
	// End sniffing thread

	return NULL;

}


/* Send syn packet */
int singsing_send_syn( int sock, long dest_ip , long source_ip, long port, struct singsing_descriptor * fd) 
{
        char * packet;

        struct ip * pkt_ip;
        struct tcphdr * pkt_tcp;
        struct sockaddr_in sin;

        packet = malloc( sizeof( struct ip ) + sizeof( struct tcphdr) );

        if( packet == NULL ) {
		fprintf(stderr, "Error in allocating memory\n");
                exit( EXIT_FAILURE );
        }


        memset( packet, 0, sizeof( struct ip ) + sizeof( struct tcphdr) );

        pkt_ip = (struct ip *) packet;
        pkt_tcp = (struct tcphdr *) (packet + sizeof( struct ip ));
	
	pkt_tcp->th_sport = htons( fd->singsing_min_port + (498.0*rand()/(RAND_MAX+1.0)) );

        pkt_tcp->th_dport = htons( port );
	pkt_tcp->th_seq = htons( 1+(int) (65000.0*rand()/(RAND_MAX+1.0)) );
	pkt_tcp->th_ack = htons( 0 );
	pkt_tcp->th_off =  sizeof( struct tcphdr) /4;
	pkt_tcp->th_flags = TH_SYN;
	pkt_tcp->th_win	= htons(32768);
	pkt_tcp->th_sum = 0;

	#if BYTE_ORDER == LITTLE_ENDIAN
	pkt_tcp->mss = 0x78050402;
	#endif

	#if BYTE_ORDER == BIG_ENDIAN
	pkt_tcp->mss = 0x02040578;
	#endif


	pkt_ip->ip_v = 4;
	pkt_ip->ip_hl = sizeof( struct ip ) >> 2;
	pkt_ip->ip_tos = 0;

	//MAC FIX
	//mac vuole senza htons, sun lo vuole, mo vediamo linux..
	#ifdef MAC
	pkt_ip->ip_len = sizeof( struct ip ) + sizeof( struct tcphdr);
	#else
	pkt_ip->ip_len = htons( sizeof( struct ip ) + sizeof( struct tcphdr) );
	#endif
	//pkt_ip->ip_len = sizeof( struct ip ) + sizeof( struct tcphdr);

	if( fd->singsing_ipid > 65000 )
		fd->singsing_ipid = 0;
	fd->singsing_ipid++;
	pkt_ip->ip_id = fd->singsing_ipid;
	pkt_ip->ip_off = 0;
	pkt_ip->ip_ttl = 100;
	pkt_ip->ip_p = IPPROTO_TCP ;
        pkt_ip->ip_sum = 0;
        pkt_ip->ip_src.s_addr = source_ip;
        pkt_ip->ip_dst.s_addr = dest_ip;


        pkt_ip->ip_sum = singsing_checksum((unsigned short*)pkt_ip, sizeof( struct ip) );

        pkt_tcp->th_sum = singsing_in_cksum_tcp(  pkt_ip->ip_src.s_addr, pkt_ip->ip_dst.s_addr, \
		(unsigned short *)pkt_tcp, sizeof(struct tcphdr));


	memcpy( packet, pkt_ip, sizeof(struct ip));
	memcpy( packet + sizeof(struct ip), pkt_tcp, sizeof(struct tcphdr));
	
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = pkt_ip->ip_dst.s_addr;

        if(sendto(sock,packet,sizeof( struct ip ) + sizeof( struct tcphdr),0,(struct sockaddr*)&sin,sizeof(sin)) < 0)
        {
		//XXX should print an error?
           	//     perror("sendto");
	        free( packet );

		return -1;
        }


	free( packet );

	return 0;
}

/* The sniffing thread */
void * singsing_sniff_thread(void *parm)
{
	struct bpf_program fp;
	bpf_u_int32 netp;
	bpf_u_int32 maskp;
	char errbuf[PCAP_ERRBUF_SIZE] = {0};
	char src[200] = {0};
	char accur[32] = {0};
	long source_ip = 0;
	struct in_addr t_in;

	struct singsing_descriptor * fd = parm;

	// XXX aumentare la priorità del processo in modo da non perdersi nulla
// 	singsing_set_thread_priority( 99 );

        if( pcap_lookupnet(fd->singsing_device,&netp,&maskp,errbuf) < 0 ) {
                fprintf(stderr, "%s\n", errbuf);
                exit( EXIT_FAILURE );
        }

        if( (fd->singsing_descr = pcap_open_live(fd->singsing_device,BUFSIZ,1,1000,errbuf)) == NULL) {
        	fprintf(stderr, "%s\n", errbuf);
                exit( EXIT_FAILURE );

        }

        source_ip = singsing_get_ip( fd, fd->singsing_device );
        t_in.s_addr = source_ip;

	// get REST packet only is necessary
	if( fd->singsing_scan_mode & SINGSING_SHOW_CLOSED ) 
		sprintf(src,"dst host %s and (tcp[2:2] >= %u and tcp[2:2] <= %u)", inet_ntoa( t_in ), fd->singsing_min_port, fd->singsing_max_port);
	else
		sprintf(src,"dst host %s and (tcp[2:2] >= %u and tcp[2:2] <= %u) and tcp[13] = 18", inet_ntoa( t_in ), fd->singsing_min_port, fd->singsing_max_port);

	if ( fd->singsing_accurate_scan_mode ) {
		
		switch ( fd	-> singsing_input_address_type ) {

			case IP_FOUND:
							sprintf(accur," and src host %s", fd->singsing_input_addresses);
							break;

			
			case NETMASK_FOUND: 

							sprintf(accur," and src net %s", fd->singsing_input_addresses);
							break;

			default:
							fprintf(stderr, "Something went wrong!\n");
							exit( EXIT_FAILURE );
							break;
		}

		memcpy(src+strlen(src), accur, strlen(accur) );
	}


	if(pcap_compile(fd->singsing_descr,&fp, src,0,netp) == -1) {

		fprintf(stderr,"Error calling pcap_compile\n");
		exit( EXIT_FAILURE ); 
	}

        if(pcap_setfilter(fd->singsing_descr,&fp) == -1) {
		fprintf(stderr,"Error setting filter\n");
		exit( EXIT_FAILURE );
	}

	while( pcap_dispatch(fd->singsing_descr, 1 , singsing_packet_rec , (void *)fd) >= 0 );

	return NULL;
}



/* Set thread priority */
void singsing_set_thread_priority( int priority )
{
	int policy;
	pthread_t tid;
	struct sched_param param;

	tid = pthread_self();

	if( pthread_getschedparam (tid, &policy, &param) != 0 ) {
		fprintf(stderr, "Error getting thread priority\n");
		exit( EXIT_FAILURE );
	}

// 	#ifdef DEBUG
//         printf("Thread id: %d priority: %d policy: %d\n", (int)tid, param.sched_priority, policy);
// 	#endif

	param.sched_priority = priority;
	policy = SCHED_RR;

        if( pthread_setschedparam (tid, policy, &param) != 0 ) {
                fprintf(stderr, "Error setting thread priority\n");
                exit( EXIT_FAILURE );
        }

// 	#ifdef DEBUG
//         if( pthread_getschedparam (tid, &policy, &param) != 0 ) {
//                 fprintf(stderr, "Error getting thread priority\n");
//                 exit( EXIT_FAILURE );
//         }
// 	printf("Thread id: %d priority: %d policy: %d\n", (int)tid, param.sched_priority, policy);
// 	#endif



}

/* Get ip address from an interface */
unsigned long singsing_get_ip( struct singsing_descriptor * fd, char* interface ) 
{
	int s;
	struct ifreq  ifr;

	s = socket(AF_INET,SOCK_DGRAM,0);
	if ( s < 0 ) 
		return 0;
	

	memset( &ifr.ifr_name, 0, sizeof(ifr.ifr_name));

	strncpy(ifr.ifr_name,interface,sizeof(ifr.ifr_name));

	if ( ioctl(s,SIOCGIFADDR,&ifr) != 0 ) {
		close(s);
		return 0;
	}
	close(s);

	return (unsigned long) (*(struct sockaddr_in *)&ifr.ifr_addr).sin_addr.s_addr;
}



int singsing_bind_port( struct singsing_descriptor * fd, unsigned long ip )
{
	int i = 0;
         struct sockaddr_in addr;
	int j=0;
	int l;
	int port = 2000;

	do {
		port ++;
		
		if( i == 0 )
			fd->singsing_min_port = port;

		fd->singsing_socket[i] = socket(AF_INET, SOCK_STREAM, 0);
		if( fd->singsing_socket[i] < 0 ) {		
			perror("open socket");
			return -1;
		}	

		memset(&addr, 0, sizeof(struct sockaddr_in));
        	//addr.sin_family = AF_UNIX; //used for local
        	addr.sin_family = AF_INET;
        	addr.sin_port = htons( port );
		//setsockopt(fd->singsing_socket[i],SOL_SOCKET,SO_REUSEADDR,&j,sizeof(int));
		if(bind(fd->singsing_socket[i], (struct sockaddr *) &addr, sizeof(addr))<0) {
		
			perror("bind failed. Error");
		
		setsockopt(fd->singsing_socket[i],SOL_SOCKET,SO_REUSEADDR,&j,sizeof(int));
			for( l = 0; l<=i; l++)
				close( fd->singsing_socket[l] );
				i = 0;
		}
		else {
			i++;	
		}

	} while( i != 500 );

	fd->singsing_max_port = port;

	return 0;
}

//  PUBLIC FUNCTIONS

void singsing_destroy( struct singsing_descriptor * fd )
{
	int i = 0;
	struct singsing_port_list * cur_port;
	struct singsing_address_to_exclude_list * cur_addr_excl = NULL;

	// Close open sockets
	for( i=0; i<500;i++ )
		close(fd->singsing_socket[i]);
	
	close( fd->singsing_raw_socket );

	// Free port structure
	while( fd->singsing_first_port != NULL ) {
		cur_port = fd->singsing_first_port->next;
		free( fd->singsing_first_port);
		fd->singsing_first_port = cur_port;
	}	

	//Free excluded addresses candidates structure
	while( fd->singsing_first_addr_to_excl != NULL ) {
		cur_addr_excl = fd->singsing_first_addr_to_excl->next;
		free( fd->singsing_first_addr_to_excl);
		fd->singsing_first_addr_to_excl = cur_addr_excl;
	}	


	
	//free AVL binary tree addresses excluded
	singsing_destroy_avl( fd->singsing_address_excluded_root );

	free(fd->singsing_input_addresses);
}

int singsing_set_scan_host( struct singsing_descriptor * fd, char * host )
{
	char * work_host;
	char * maskarg = (char *)NULL;
	unsigned long mask = 0;

#ifdef DEBUG
struct in_addr t_in;
#endif

	if ( ( fd->singsing_input_address_type = singsing_validate_ipv4( host ) ) ) {
		fd->singsing_input_addresses = (char *) malloc(ADDR_MASK_MAX_SIZE);
		memcpy(fd->singsing_input_addresses,host,strlen(host));
	}
	else {
		fprintf( stderr, "Address %s not correct\n",host);
		exit( EXIT_FAILURE );
	}
	
	
	//fprintf( stderr, "Address %s found\n",fd->singsing_input_addresses);

	// Fix for 64bit processors
	mask --;

	work_host = strdup( host );

        if( (maskarg = (char *)strchr(work_host,'/')) ) {
                *maskarg = 0;
                maskarg++;
        }

        if( maskarg ) {
                mask = (mask << ((unsigned long)(32 - atol(maskarg))));
        } else {
                mask = mask;
        }

        fd->singsing_start_ip = ntohl((unsigned long)inet_addr(work_host)) & mask;

	fd->singsing_end_ip = fd->singsing_start_ip | ~mask;

#ifdef DEBUG
t_in.s_addr = ntohl( fd->singsing_start_ip );
fprintf(stderr," Start IP: %s\n",inet_ntoa(t_in));
t_in.s_addr = ntohl( fd->singsing_end_ip );
fprintf(stderr," End   IP: %s\n",inet_ntoa(t_in)); 
#endif

	//AAS
	free(work_host);
	return 0;
}



int singsing_set_scan_interface( struct singsing_descriptor * fd, char * interface )
{
	fd->singsing_device = interface;
	return 0;
}

void singsing_set_bandwidth( struct singsing_descriptor * fd, int a)
{
	fd->singsing_band = a;
}

int singsing_scanisfinished( struct singsing_descriptor * fd ) 
{
	return fd->singsing_finished;
} 


void singsing_get_status( struct singsing_descriptor * fd, struct singsing_status_struct * cur )
{
	memcpy( cur, &fd->singsing_cur_status, sizeof( struct singsing_status_struct ) );

	cur->current_time = time(NULL);

	return;
}


void singsing_set_accurate_scan_mode( struct singsing_descriptor * fd )
{

	fd->singsing_accurate_scan_mode = 1;

}

void singsing_set_scanmode( struct singsing_descriptor * fd, int a )
{
	fd->singsing_scan_mode |= a;
}

void singsing_create( struct singsing_descriptor * fd )
{
	fd->singsing_band = 5;
	fd->singsing_device = NULL;
	fd->singsing_start_ip = 0;
	fd->singsing_end_ip = 0;
	fd->singsing_min_port = 0;
	fd->singsing_max_port = 0;

	fd->singsing_descr	= NULL;
	fd->singsing_ipid	= 0;
	fd->singsing_finished 	= 0;
	fd->singsing_ports = 0;
	fd->singsing_addresses_excluded_total = 0;
	fd->singsing_excluded_addresses_nodes = 0;
	fd->singsing_sleep_band = 0;
	fd->singsing_cur_port = 0;
	fd->singsing_scan_mode = SINGSING_BASIC_SCAN;
	fd->singsing_accurate_scan_mode = 0;
	fd->singsing_input_addresses = NULL;
	fd->singsing_input_address_type = 0;

	// Data lists
	fd->singsing_first_port = NULL;
	fd->singsing_last_port = NULL;

	fd->singsing_first_addr_to_excl = NULL;
	fd->singsing_last_addr_to_excl = NULL;

	fd->singsing_address_excluded_root = NULL;
	fd->singsing_min_addr_excluded = 0;
	fd->singsing_max_addr_excluded = 0;

	fd->singsing_first_result = NULL;
	fd->singsing_last_result = NULL;

	pthread_mutex_init(&fd->singsing_result_queue_lock, NULL);

	pthread_mutex_init(&fd->packet_queue_lock, NULL);

	fd->singsing_first_packet = NULL;
	fd->singsing_last_packet = NULL;
	
}

void singsing_destroy_address_to_exclude_list( struct singsing_descriptor * fd )
{

	struct singsing_address_to_exclude_list * addr = fd->singsing_first_addr_to_excl;

	while ( addr != NULL ) {
		addr = fd->singsing_first_addr_to_excl->next;
		free(fd->singsing_first_addr_to_excl);
		fd->singsing_first_addr_to_excl = addr;

	}
		
}
