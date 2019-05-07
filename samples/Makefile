# This file is part of the ebpf2c project
# 
# (C) 2019 Andreas Steinmetz, ast@domdv.de
# The contents of this file is licensed under the GPL version 2 or, at
# your choice, any later version of this license.
#
CC=gcc
CFLAGS=-O3
EBPF2C=../ebpf2c

all: udp-sport tcp-udp-count

udp-sport: udp-sport.c udp-sport.h
	$(CC) $(CFLAGS) -o $@ $<

tcp-udp-count: tcp-udp-count.c tcp-udp-count.h
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f udp-sport udp-sport.h tcp-udp-count tcp-udp-count.h

%.h : %.ebpf
	$(EBPF2C) $< $@
