    ebpf2c, a simple symbolic eBPF assembler producing C source output
                        (c) 2019 Andreas Steinmetz

--------------------------------------------------------------------------


  An alternative way to include eBPF assembly directly in your sources.
==========================================================================

Well, yes, yet another way to work with eBPF, though somewhat different.
No LLVM required, no ELF objects you can't include in your source and
no clumsy preprocessor macros with manual jump offset reordering.

This is just a tiny symbolic assembler that produces a "struct bpf\_insn"
and some "#define" output that can be included in a C source.

As for the language, see how "test.ebpf" compares to "reference.h".
You will most probably find the language lightweight and easy to use
if you do have some assembly language experience. Note that immediate
data must be prefixed by '#' (the '#' is removed during processing).

The symbolic label processing spares you some grey hair. And as the
assembler is really dumb you can include nearly any kind of data
as immediate values which then can be processed by the C compiler.

The integrated label export allows easy run time modification of
the generated eBPF code, as you just know where the interesting
statements are positioned in the created data array.

The code is simple, as are the rudimentary error messages. This is a
single afternoon project born from internal need and it looks like
that. Don't worry or complain, it works, that's the important thing.

Hints:
======

1. You do have 11 registers, named r0 to r10 (fp is an alias for r10).
r10 is the frame pointer, a stack of 512 bytes can be used.

2. Preserved registers are r6 to r10 and, to an extend, r0. r1 to r5
are so volatile that the in kernel verifier loses track after every
branching so these are not of any real use.

3. A socket filter program gets a context on start in r1 that is to
be saved in r6. You need this context to access a dummy skb structure of
type "struct \_\_sk\_buff" that contains u32 values of interest, e.g. the
the packet length (see linux/bpf.h for details). You can access
this data with e.g. "ldxw r0,r6,#offsetof(struct \_\_sk\_buff,len)".
And, well, yes, you need the context in r6 to access the packet data
using the lda and ldi instructions.

4. No loops, don't try. You won't get past the in kernel verifier.

Opcode Syntax:
==============
```
	General:
	--------

	reg1|reg2 = r0|r1|r2|r3|r4|r5|r6|r7|r8|r9|r10|fp (r10=fp)
	b         = 8bit
	h         = 16bit
	w         = 32bit
	d         = 64bit
	imm16     = 16bit immediate
	imm32     = 32bit immediate
	imm64     = 64bit immediate
	value16   = 16bit constant

	Label targets start at the beginning of the line and are delimited
	by a colon character. A line containing a label target must contain
	an opcode.

	Packet Data:
	------------

	ldaX #imm32			X=b|h|w|d    r0=*(packet+imm32)
	ldiX reg1,#imm32		X=b|h|w|d    r0=*(packet+reg1+imm32)

	Memory:
	-------

	ldxX  reg1,reg2,#imm16		X=b|h|w|d    reg1=*(reg2+imm16)
	stxX  reg1,reg2,#imm16		X=b|h|w|d    *(reg1+imm16)=reg2
	stiX  reg1,value16,#imm16	X=b|h|w|d    *(reg1+value16)=imm32
	xaddX reg1,reg2,#imm16		X=b|h|w|d    atomic *(reg1+imm16)+=reg2

	Register:
	---------

	movX  reg1,reg2			X=w|d	     reg1=reg2
	movX  reg1,#imm32		X=w|d	     reg1=imm32
	ldi64 reg1,#imm64			     reg1=imm64

	ALU:
	----

	op=add|sub|mul|div|or|and|lsh|rsh|neg|mod|arsh

	opX reg1,reg2			X=w|d	     reg1=reg1 op reg2
	opX reg2,#imm32			X=w|d	     reg1=reg1 op imm32

	Endian:
	-------

	hxbe reg1,#imm		convert imm bits of reg1 to/from big endian
	hxle reg1,#imm		convert imm bits of reg1 to/from little endian

	Conditional:
	------------

	COND=eq,gt,ge,set,ne,lt,le,sgt,sge,slt,sle

	jCOND reg1,reg2,label16		if reg1 COND reg2 goto label16

	Unconditional:
	--------------

	ja    label16			goto label16
	lcall label32			call label32
	fcall kernel-helper		call kernell-helper
	exit				return

	Other:
	------
	ldmap reg1,#imm64		reg1=imm64 (must be a map fd)
```