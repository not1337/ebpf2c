/*
 * This file is part of the ebpf2c project
 *
 * (C) 2019 Andreas Steinmetz, ast@domdv.de
 * The contents of this file is licensed under the GPL version 2 or, at
 * your choice, any later version of this license.
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>
#include <string.h>
#include <stddef.h>
#include <stdio.h>
#include "../ebpf.h"
#include "udp-sport.h"

static void usage(void)
{
	fprintf(stderr,"Usage: udp-sport <listen-port> <source-port-low> "
		"<source-port-high>\n");
	fprintf(stderr,"Accept only packets with source port within specified "
		"range.\n");
	exit(1);
}

int main(int argc,char *argv[])
{
	int udp;
	int ebpf;
	int port;
	int low;
	int high;
	int i;
	struct pollfd p;
	struct sockaddr_in6 s;
	unsigned char bfr[2048];

	if(argc!=4)usage();

	port=atoi(argv[1]);
	low=atoi(argv[2]);
	high=atoi(argv[3]);

	if(port<1||port>65535||low<1||low>65535||high<1||high>65535||low>high)
		usage();

	bpf_udp_sport[BPF_SPORT_LOW].imm=low;
	bpf_udp_sport[BPF_SPORT_HIGH].imm=high;

	if((ebpf=bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER,bpf_udp_sport,
		BPF_UDP_SPORT_SIZE,"GPL",65536))==-1)
	{
		perror("bpf_prog_load");
		return 1;
	}

	memset(&s,0,sizeof(s));
	s.sin6_family=AF_INET6;
	s.sin6_port=htobe16(port);
	s.sin6_addr=in6addr_any;

	if((udp=socket(AF_INET6,SOCK_DGRAM|SOCK_CLOEXEC,0))==-1)
	{
		perror("socket");
		return 1;
	}

	if(setsockopt(udp,SOL_SOCKET,SO_ATTACH_BPF,&ebpf,sizeof(ebpf)))
	{
		perror("setsockopt SO_ATTACH_BPF");
		return 1;
	}

	i=1;
	if(setsockopt(udp,SOL_SOCKET,SO_REUSEADDR,&i,sizeof(i)))
	{
		perror("setsockopt SO_REUSEADDR");
		return 1;
	}

	if(bind(udp,(struct sockaddr *)(&s),sizeof(s)))
	{
		perror("bind");
		return 1;
	}

	p.fd=udp;
	p.events=POLLIN;

	while(1)
	{
		if(poll(&p,1,-1)<1||!(p.revents&POLLIN))continue;

		if((i=recv(udp,&bfr,sizeof(bfr),0))<=0)continue;

		printf("received packet of %d bytes\n",i);
	}

	return 0;
}
