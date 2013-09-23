/*****************************************************************************
 * filippo.c is a part of singsing project                                   *
 *                                                                           *
 * $Id:: filippo.c 28 2008-01-27 22:25:49Z inode_                         $: *
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
#include "appscan.h"

#define NAME "socks"
#define VERSION "0.2"

#define SOCKS_PORT	1080
#define READ_TIMEOUT    30
#define CONNECT_TIMEOUT 30


void usage( char * argv );

unsigned int port = SOCKS_PORT;


int main(int argc, char ** argv)
{
	char * target = NULL;
	char * device = NULL;
	char * ip = NULL;
	char opt;
	struct in_addr result;
	time_t start_time;
	time_t end_time;
	int band = 5;
	unsigned int nodup = 1;
	int thread_num = 0;

	struct singsing_result_queue * cur_res;
	
	struct singsing_descriptor fd;

	appscan_descriptor ad;

	singsing_create(&fd);

	appscan_create(&ad);

	while((opt = getopt(argc, argv, "i:h:b:c:p:Nt:")) != -1)
	{
		switch (opt)
		{
			case 'i':
				device = optarg;
				break;
			case 'h':
				target = optarg;
				break;
			case 'b':
				band = atoi( optarg );
				break;
			case 'c':
				ip = optarg;
				break;
			case 'p':
				port = atoi( optarg );
				break;
			case 'N':
				nodup = 0;
				break;
			case 't':
				thread_num = atoi(optarg);
				break;
			default:
				usage( argv[0] );
		}
	}

	if( target == NULL || device == NULL || ip == NULL )
		usage( argv[0] );

	if (thread_num)
		appscan_set_thread_num( &ad, thread_num );

	//Set ip:port to connect to through SOCKS
	if ( ! appscan_set_socks_connect_ip_and_port( &ad, ip) )
		usage(argv[0]);

	singsing_set_scan_interface( &fd, device );

	singsing_set_bandwidth( &fd, band );

	singsing_set_scan_host( &fd, target );

	singsing_add_port( &fd, port );

	if ( nodup )
		singsing_set_scanmode( &fd, SINGSING_NODUP_SCAN );

	singsing_set_scanmode( &fd, SINGSING_SEGMENT_SCAN );

	fprintf( stderr, "Starting scan...\n");

	start_time = time(NULL);

	singsing_init(&fd);

	do {
		cur_res = singsing_get_result(&fd);
		if( cur_res != NULL ) {
			result.s_addr = ntohl(cur_res->ip);

			#ifdef DEBUG
			fprintf(stderr, "\nreceived result for host %s\n",inet_ntoa( result ));
			#endif
			if ( appscan_run_scan( SOCKS, &ad, inet_ntoa( result ), SOCKS_PORT , CONNECT_TIMEOUT, READ_TIMEOUT ) ) {
				fprintf( stderr, "Warning! Cannot create appscan thread for host %s port %u\n", inet_ntoa(result), SOCKS_PORT );
			}
			
			fflush(stderr);
			fflush(stdout);
			
			free(cur_res);
		} else
                	usleep(300000);
 
	} while( singsing_scanisfinished(&fd) != 2 || cur_res != NULL);


		appscan_wait_scans_results( &ad );

        end_time = time(NULL);

        fprintf( stderr, "\n Scan end in %.0lf seconds\n\n", difftime(end_time, start_time));

		appscan_destroy( &ad );

        singsing_destroy(&fd);

	return 0;
}


void usage( char * argv )
{
	fprintf(stderr, "\n Usage: %s -i <arg> -h <arg> -c <arg> [-b <arg> -p <arg>] [-N]\n", argv);
	fprintf(stderr, "\t-i Interface\n");
	fprintf(stderr, "\t-h Target (CIDR format)\n");
	fprintf(stderr, "\t-b Bandwidth (Default 5KB/s)\n");
	fprintf(stderr, "\t-p Port (Default 1080)\n");
	fprintf(stderr, "\t-c Try connect to (ip:port)\n");
	fprintf(stderr, "\t-N Disable NODUP scan\n");
	fprintf(stderr, "\t-t Max number of threads used to process singsing results (DEFAULT=16,MAX=64)\n\n");
	exit(0);
} 

