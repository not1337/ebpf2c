# This file is part of the ebpf2c project
# 
# (C) 2019 Andreas Steinmetz, ast@domdv.de
# The contents of this file is licensed under the GPL version 2 or, at
# your choice, any later version of this license.
#
check:	../ebpf2c test.ebpf reference.h sanitized_filter.h
	../ebpf2c test.ebpf test.h
	gcc -Wall -O3 -s -o verifier verifier.c
	@echo "code generation verified, success."
	../ebpf2c test.ebpf test2.h
	cmp -s test.h test2.h
	@echo "include statement verified, success."

clean:
	rm -f verifier test.h test2.h
