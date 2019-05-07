/*
 * This file is part of the ebpf2c project
 *
 * (C) 2019 Andreas Steinmetz, ast@domdv.de
 * The contents of this file is licensed under the GPL version 2 or, at
 * your choice, any later version of this license.
 */

#include <linux/bpf.h>
#include <stdlib.h>
#include <stdio.h>
#include "sanitized_filter.h"

#include "reference.h"
#include "test.h"

#if cmp_size != 108
#error "unexpected array size"
#endif

#if l1!=77 || l2!=78 || l3!=79 || l25_l!=103 || l25_h!=104 || l26_l!=105 || \
	l26_h!=106
#error "missing or invalid exports"
#endif

int main()
{
	int i;
	int err=0;

	for(i=0;i<cmp_size;i++)
	{
		if(ref[i].code!=cmp[i].code)
		{
			printf("code err @ %d\n",i+1);
			err=1;
		}
		if(ref[i].dst_reg!=cmp[i].dst_reg)
		{
			printf("dst err @ %d\n",i+1);
			err=1;
		}
		if(ref[i].src_reg!=cmp[i].src_reg)
		{
			printf("src err @ %d\n",i+1);
			err=1;
		}
		if(ref[i].off!=cmp[i].off)
		{
			printf("off err @ %d\n",i+1);
			err=1;
		}
		if(ref[i].imm!=cmp[i].imm)
		{
			printf("imm err @ %d\n",i+1);
			err=1;
		}
	}

	return err;
}
