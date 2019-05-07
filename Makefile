# This file is part of the ebpf2c project
# 
# (C) 2019 Andreas Steinmetz, ast@domdv.de
# The contents of this file is licensed under the GPL version 2 or, at
# your choice, any later version of this license.
#
all:	ebpf2c

ebpf2c: ebpf2c.c
	gcc -Wall -O3 -s -o ebpf2c ebpf2c.c

check: ebpf2c
	make -C test

samples: ebpf2c
	make -C samples

clean:
	rm -f ebpf2c
	make -C test clean
	make -C samples clean
