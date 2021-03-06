/*
 * This file is part of the ebpf2c project
 *
 * (C) 2019 Andreas Steinmetz, ast@domdv.de
 * The contents of this file is licensed under the GPL version 2 or, at
 * your choice, any later version of this license.
 */

struct bpf_insn ref[]=
{
BPF_ALU64_REG(BPF_ADD,BPF_REG_0,BPF_REG_1),
BPF_ALU64_REG(BPF_SUB,BPF_REG_1,BPF_REG_2),
BPF_ALU64_REG(BPF_MUL,BPF_REG_2,BPF_REG_3),
BPF_ALU64_REG(BPF_DIV,BPF_REG_3,BPF_REG_4),
BPF_ALU64_REG(BPF_OR,BPF_REG_4,BPF_REG_5),
BPF_ALU64_REG(BPF_AND,BPF_REG_5,BPF_REG_6),
BPF_ALU64_REG(BPF_LSH,BPF_REG_6,BPF_REG_7),
BPF_ALU64_REG(BPF_RSH,BPF_REG_7,BPF_REG_8),
BPF_ALU64_REG(BPF_MOD,BPF_REG_9,BPF_REG_10),
BPF_ALU64_REG(BPF_XOR,BPF_REG_10,BPF_REG_0),
BPF_ALU64_REG(BPF_ARSH,BPF_REG_0,BPF_REG_1),
BPF_ALU32_REG(BPF_ADD,BPF_REG_0,BPF_REG_1),
BPF_ALU32_REG(BPF_SUB,BPF_REG_1,BPF_REG_2),
BPF_ALU32_REG(BPF_MUL,BPF_REG_2,BPF_REG_3),
BPF_ALU32_REG(BPF_DIV,BPF_REG_3,BPF_REG_4),
BPF_ALU32_REG(BPF_OR,BPF_REG_4,BPF_REG_5),
BPF_ALU32_REG(BPF_AND,BPF_REG_5,BPF_REG_6),
BPF_ALU32_REG(BPF_LSH,BPF_REG_6,BPF_REG_7),
BPF_ALU32_REG(BPF_RSH,BPF_REG_7,BPF_REG_8),
BPF_ALU32_REG(BPF_MOD,BPF_REG_9,BPF_REG_10),
BPF_ALU32_REG(BPF_XOR,BPF_REG_10,BPF_REG_0),
BPF_ALU32_REG(BPF_ARSH,BPF_REG_0,BPF_REG_1),
BPF_ALU64_IMM(BPF_ADD,BPF_REG_0,1),
BPF_ALU64_IMM(BPF_SUB,BPF_REG_1,2),
BPF_ALU64_IMM(BPF_MUL,BPF_REG_2,3),
BPF_ALU64_IMM(BPF_DIV,BPF_REG_3,4),
BPF_ALU64_IMM(BPF_OR,BPF_REG_4,5),
BPF_ALU64_IMM(BPF_AND,BPF_REG_5,6),
BPF_ALU64_IMM(BPF_LSH,BPF_REG_6,7),
BPF_ALU64_IMM(BPF_RSH,BPF_REG_7,8),
BPF_ALU64_IMM(BPF_NEG,BPF_REG_8,0),
BPF_ALU64_IMM(BPF_MOD,BPF_REG_9,10),
BPF_ALU64_IMM(BPF_XOR,BPF_REG_10,11),
BPF_ALU64_IMM(BPF_ARSH,BPF_REG_0,12),
BPF_ALU32_IMM(BPF_ADD,BPF_REG_0,1),
BPF_ALU32_IMM(BPF_SUB,BPF_REG_1,2),
BPF_ALU32_IMM(BPF_MUL,BPF_REG_2,3),
BPF_ALU32_IMM(BPF_DIV,BPF_REG_3,4),
BPF_ALU32_IMM(BPF_OR,BPF_REG_4,5),
BPF_ALU32_IMM(BPF_AND,BPF_REG_5,6),
BPF_ALU32_IMM(BPF_LSH,BPF_REG_6,7),
BPF_ALU32_IMM(BPF_RSH,BPF_REG_7,8),
BPF_ALU32_IMM(BPF_NEG,BPF_REG_8,0),
BPF_ALU32_IMM(BPF_MOD,BPF_REG_9,10),
BPF_ALU32_IMM(BPF_XOR,BPF_REG_10,11),
BPF_ALU32_IMM(BPF_ARSH,BPF_REG_0,12),
BPF_MOV64_REG(BPF_REG_1,BPF_REG_2),
BPF_MOV32_REG(BPF_REG_3,BPF_REG_4),
BPF_MOV64_IMM(BPF_REG_5,12),
BPF_MOV32_IMM(BPF_REG_6,13),
BPF_LD_ABS(BPF_B,14),
BPF_LD_ABS(BPF_H,15),
BPF_LD_ABS(BPF_W,16),
BPF_LD_IND(BPF_B,BPF_REG_7,18),
BPF_LD_IND(BPF_H,BPF_REG_8,19),
BPF_LD_IND(BPF_W,BPF_REG_9,20),
BPF_LDX_MEM(BPF_B,BPF_REG_0,BPF_REG_1,22),
BPF_LDX_MEM(BPF_H,BPF_REG_2,BPF_REG_3,23),
BPF_LDX_MEM(BPF_W,BPF_REG_4,BPF_REG_5,24),
BPF_LDX_MEM(BPF_DW,BPF_REG_6,BPF_REG_7,25),
BPF_STX_MEM(BPF_B,BPF_REG_0,BPF_REG_1,26),
BPF_STX_MEM(BPF_H,BPF_REG_2,BPF_REG_3,27),
BPF_STX_MEM(BPF_W,BPF_REG_4,BPF_REG_5,28),
BPF_STX_MEM(BPF_DW,BPF_REG_6,BPF_REG_7,29),
BPF_STX_XADD(BPF_B,BPF_REG_0,BPF_REG_1,30),
BPF_STX_XADD(BPF_H,BPF_REG_2,BPF_REG_3,31),
BPF_STX_XADD(BPF_W,BPF_REG_4,BPF_REG_5,32),
BPF_STX_XADD(BPF_DW,BPF_REG_6,BPF_REG_7,33),
BPF_ST_MEM(BPF_B,BPF_REG_0,34,35),
BPF_ST_MEM(BPF_H,BPF_REG_1,36,37),
BPF_ST_MEM(BPF_W,BPF_REG_2,38,39),
BPF_ST_MEM(BPF_DW,BPF_REG_3,40,41),
BPF_JMP_REG(BPF_JEQ,BPF_REG_0,BPF_REG_1,0),
BPF_JMP_REG(BPF_JGT,BPF_REG_1,BPF_REG_2,0),
BPF_JMP_REG(BPF_JGE,BPF_REG_2,BPF_REG_3,0),
BPF_JMP_REG(BPF_JSET,BPF_REG_3,BPF_REG_4,0),
BPF_JMP_REG(BPF_JNE,BPF_REG_4,BPF_REG_5,0),
BPF_JMP_REG(BPF_JLT,BPF_REG_5,BPF_REG_6,0),
BPF_JMP_REG(BPF_JLE,BPF_REG_6,BPF_REG_7,0),
BPF_JMP_REG(BPF_JSGT,BPF_REG_7,BPF_REG_8,0),
BPF_JMP_REG(BPF_JSGE,BPF_REG_8,BPF_REG_9,0),
BPF_JMP_REG(BPF_JSLT,BPF_REG_9,BPF_REG_10,0),
BPF_JMP_REG(BPF_JSLE,BPF_REG_10,BPF_REG_0,0),
BPF_JMP_IMM(BPF_JEQ,BPF_REG_0,1,0),
BPF_JMP_IMM(BPF_JGT,BPF_REG_1,2,0),
BPF_JMP_IMM(BPF_JGE,BPF_REG_2,3,0),
BPF_JMP_IMM(BPF_JSET,BPF_REG_3,4,0),
BPF_JMP_IMM(BPF_JNE,BPF_REG_4,5,0),
BPF_JMP_IMM(BPF_JLT,BPF_REG_5,6,0),
BPF_JMP_IMM(BPF_JLE,BPF_REG_6,7,0),
BPF_JMP_IMM(BPF_JSGT,BPF_REG_7,8,0),
BPF_JMP_IMM(BPF_JSGE,BPF_REG_8,9,0),
BPF_JMP_IMM(BPF_JSLT,BPF_REG_9,10,0),
BPF_JMP_IMM(BPF_JSLE,BPF_REG_10,11,0),
BPF_JMP_A(0),
BPF_CALL_REL(0),
BPF_EMIT_CALL(99),
BPF_ENDIAN(BPF_TO_LE,BPF_REG_2,16),
BPF_ENDIAN(BPF_TO_BE,BPF_REG_3,32),
BPF_LD_IMM64(BPF_REG_4,69),
BPF_LD_MAP_FD(BPF_REG_5,71),
BPF_EXIT_INSN(),
};
