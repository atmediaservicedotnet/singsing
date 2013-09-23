#  * $Id:: Makefile 27 2007-11-27 21:13:05Z inode_                          $: *
all:
	@echo "Please use one of the following make choice:"
	@echo "make linux"
	@echo "make solaris"
	@echo "make mac"

linux: zucca.c filippo.c ssh_scan.c zuccorale.c telnet_grabber.c ../singsing.c ../appscan.c ../singsing.h ../singsing_p.h ../appscan.h
	gcc  -o zucca zucca.c ../singsing.c -I../ -lpcap -lpthread -Wall 
	gcc  -o ssh_scan ssh_scan.c ../singsing.c -I../ -lpcap -lpthread -Wall
	gcc  -o filippo filippo.c ../singsing.c ../appscan.c -I../ -lpcap -lpthread -Wall
	gcc  -o telnet_grabber telnet_grabber.c ../singsing.c ../appscan.c -I../ -lpcap -lpthread -Wall 
	gcc  -o zuccorale zuccorale.c ../singsing.c ../appscan.c -I../ -lpcap -lpthread -Wall

solaris: zucca.c filippo.c ssh_scan.c zuccorale.c telnet_grabber.c ../singsing.c ../appscan.c ../singsing.h ../singsing_p.h ../appscan.h
	gcc -o zucca zucca.c ../singsing.c ../appscan.c -I../ -DSOLARIS -lpcap -lpthread -lxnet -lsocket -Wall
	gcc -o ssh_scan ssh_scan.c ../singsing.c ../appscan.c -I../ -DSOLARIS -lpcap -lpthread -lxnet -lsocket -Wall
	gcc -o filippo filippo.c ../singsing.c ../appscan.c -I../ -DSOLARIS -lpcap -lpthread -lxnet -lsocket -Wall
	gcc -o telnet_grabber telnet_grabber.c ../singsing.c ../appscan.c -I../ -DSOLARIS -lpcap -lpthread -lxnet -lsocket -Wall
	gcc -o zuccorale zuccorale.c ../singsing.c ../appscan.c -I../ -DSOLARIS -lpcap -lpthread -lxnet -lsocket -Wall
	gcc -o psp psp.c ../singsing.c ../appscan.c -I../ -DSOLARIS -lpcap -lpthread -lxnet -lsocket -Wall


mac: zucca.c filippo.c ssh_scan.c zuccorale.c telnet_grabber.c ../singsing.c ../appscan.c ../singsing.h ../singsing_p.h ../appscan.h
	gcc -o zucca zucca.c ../singsing.c ../appscan.c -I../ -DMAC -lpcap -lpthread -Wall
	gcc -o ssh_scan ssh_scan.c ../singsing.c ../appscan.c -I../ -DMAC -lpcap -lpthread -Wall
	gcc -o filippo filippo.c ../singsing.c ../appscan.c -I../ -DMAC -lpcap -lpthread -Wall
	gcc -o telnet_grabber telnet_grabber.c ../singsing.c ../appscan.c -I../ -DMAC -lpcap -lpthread -Wall
	gcc -o zuccorale zuccorale.c ../singsing.c ../appscan.c -I../ -DMAC -lpcap -lpthread -Wall
	gcc -o psp psp.c ../singsing.c ../appscan.c -I../ -DMAC -lpcap -lpthread -Wall

clean:
	rm -rf zucca ssh_scan filippo telnet_grabber zuccorale psp
