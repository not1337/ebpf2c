/*
 * This file is part of the ebpf2c project
 *
 * (C) 2019 Andreas Steinmetz, ast@domdv.de
 * The contents of this file is licensed under the GPL version 2 or, at
 * your choice, any later version of this license.
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <poll.h>
#include <string.h>
#include <stddef.h>
#include <stdio.h>
#include "../ebpf.h"
#include "tcp-udp-count.h"

static void usage(void)
{
	fprintf(stderr,"Usage: tcp-udp-count <netdevice>\n");
	fprintf(stderr,"Count tcp and udp packets received (must be root).\n");
	exit(1);
}

int main(int argc,char *argv[])
{
	int raw;
	int mapfd;
	int ebpf;
	u_int32_t key;
	u_int64_t count[2];
	struct sockaddr_ll addr;

	if(argc!=2)usage();

	if((mapfd=bpf_create_map(BPF_MAP_TYPE_ARRAY,sizeof(u_int32_t),
		sizeof(u_int64_t),2))==-1)
	{
		perror("bpf_create_map");
		return 1;
	}

	ebpf_counter[BPFMAPFD_L].imm=mapfd;

	if((ebpf=bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER,ebpf_counter,
		EBPF_COUNTER_SIZE,"GPL",65536))==-1)
	{
		perror("bpf_prog_load");
		return 1;
	}

	memset(&addr,0,sizeof(addr));
	if(!(addr.sll_ifindex=if_nametoindex(argv[1])))
	{
		perror("if_nametoindex");
		return 1;
	}
	addr.sll_family=AF_PACKET;
	addr.sll_protocol=htobe16(ETH_P_ALL);

	if((raw=socket(PF_PACKET,SOCK_RAW|SOCK_NONBLOCK|SOCK_CLOEXEC,
		htobe16(ETH_P_ALL)))==-1)
	{
		perror("socket");
		return 1;
	}

	if(setsockopt(raw,SOL_SOCKET,SO_ATTACH_BPF,&ebpf,sizeof(ebpf)))
	{
		perror("setsockopt SO_ATTACH_BPF");
		return 1;
	}

	if(bind(raw,(struct sockaddr *)&addr,sizeof(addr)))
	{
		perror("bind");
		return 1;
	}

	while(1)
	{
		sleep(1);

		for(key=0;key<2;key++)
			if(bpf_lookup_elem(mapfd,&key,&count[key]))
		{
			perror("bpf_lookup_elem");
			return 1;
		}

		printf("udp: %ld     tcp: %ld\n",count[0],count[1]);
	}

	return 0;
}
