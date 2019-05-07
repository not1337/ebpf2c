/*
 * This file is part of the ebpf2c project
 *
 * (C) 2019 Andreas Steinmetz, ast@domdv.de
 * The contents of this file is licensed under the GPL version 2 or, at
 * your choice, any later version of this license.
 */

#include <linux/bpf.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>

#define MAX_INSNS	4096
#define MAX_EXPORT	1024
#define MAX_NESTING	20

enum
{
	e_size,
	e_static,
	e_const,
	e_upcase,
	e_code,
	e_name,
	e_export,
	e_max,
};

static struct
{
	char *name;
	int type;
	union
	{
		char *string;
		int value;
	};
} hdr[e_max+1]=
{
	[e_size]={"size",0},
	[e_static]={"static",0},
	[e_const]={"const",0},
	[e_upcase]={"upcase",0},
	[e_code]={"code",0},
	[e_name]={"name",1},
	[e_export]={"export",2},
	[e_max]={NULL},
};

static const struct cvt
{
	char *opcode;
	int sizes;
	int code;
	int args;
	int xk;
	int immpos;
	int label;
	int len;
	int regs;
	int emit;
} cvt[]=
{
	{"lda",  15,BPF_LD|BPF_ABS,           1,0,1,0,1,0,0},
	{"ldi",  15,BPF_LD|BPF_IND,           2,0,2,0,1,1,3},
	{"ldx",  15,BPF_LDX|BPF_MEM,          3,0,3,0,1,2,4},
	{"stx",  15,BPF_STX|BPF_MEM,          3,0,3,0,1,2,4},
	{"sti",  15,BPF_ST|BPF_MEM,           3,0,3,0,1,1,5},
	{"xadd", 15,BPF_STX|BPF_XADD,         3,0,3,0,1,2,4},
	{"mov",  12,BPF_MOV,                  2,1,2,0,1,2,6},
	{"add",  12,BPF_ADD,                  2,1,2,0,1,2,6},
	{"sub",  12,BPF_SUB,                  2,1,2,0,1,2,6},
	{"mul",  12,BPF_MUL,                  2,1,2,0,1,2,6},
	{"div",  12,BPF_DIV,                  2,1,2,0,1,2,6},
	{"or",   12,BPF_OR,                   2,1,2,0,1,2,6},
	{"and",  12,BPF_AND,                  2,1,2,0,1,2,6},
	{"lsh",  12,BPF_LSH,                  2,1,2,0,1,2,6},
	{"rsh",  12,BPF_RSH,                  2,1,2,0,1,2,6},
	{"neg",  12,BPF_NEG,                  2,1,2,0,1,2,6},
	{"mod",  12,BPF_MOD,                  2,1,2,0,1,2,6},
	{"xor",  12,BPF_XOR,                  2,1,2,0,1,2,6},
	{"arsh", 12,BPF_ARSH,                 2,1,2,0,1,2,6},
	{"ja",   0, BPF_JA|BPF_JMP,           1,0,0,1,1,0,8},
	{"jeq",  0, BPF_JEQ|BPF_JMP,          3,1,2,3,1,2,7},
	{"jgt",  0, BPF_JGT|BPF_JMP,          3,1,2,3,1,2,7},
	{"jge",  0, BPF_JGE|BPF_JMP,          3,1,2,3,1,2,7},
	{"jset", 0, BPF_JSET|BPF_JMP,         3,1,2,3,1,2,7},
	{"jne",  0, BPF_JNE|BPF_JMP,          3,1,2,3,1,2,7},
	{"jlt",  0, BPF_JLT|BPF_JMP,          3,1,2,3,1,2,7},
	{"jle",  0, BPF_JLE|BPF_JMP,          3,1,2,3,1,2,7},
	{"jsgt", 0, BPF_JSGT|BPF_JMP,         3,1,2,3,1,2,7},
	{"jsge", 0, BPF_JSGE|BPF_JMP,         3,1,2,3,1,2,7},
	{"jslt", 0, BPF_JSLT|BPF_JMP,         3,1,2,3,1,2,7},
	{"jsle", 0, BPF_JSLE|BPF_JMP,         3,1,2,3,1,2,7},
	{"lcall",0, BPF_CALL|BPF_JMP,         1,0,0,1,1,0,2},
	{"fcall",0, BPF_CALL|BPF_JMP,         1,0,0,0,1,0,0},
	{"exit", 0, BPF_EXIT|BPF_JMP,         0,0,0,0,1,0,1},
	{"hxbe", 0, BPF_ALU|BPF_END|BPF_TO_BE,2,0,2,0,1,1,9},
	{"hxle", 0, BPF_ALU|BPF_END|BPF_TO_LE,2,0,2,0,1,1,9},
	{"ldi64",0, BPF_LD|BPF_DW|BPF_IMM,    2,0,2,0,2,1,10},
	{"ldmap",0, BPF_LD|BPF_DW|BPF_IMM,    2,0,2,0,2,1,11},
	{NULL}
};

static struct prog
{
	int srcline;
	int immediate;
	int index;
	int size;
	int args;
	int code;
	int dstidx;
	int reg0;
	int reg1;
	char *srcfile;
	char *label;
	char *opcode;
	char *target;
	const struct cvt *data;
	char *arg[3];
} prg[MAX_INSNS];

static int insns;

static struct label
{
	char *name;
	struct prog *data;
} labels[MAX_INSNS];

static int nlabels;

static struct export
{
	char *name;
	char *srcfile;
	int dstidx;
	int dstlen;
	int srcline;
} exp[MAX_EXPORT];

static int nexp;

static int emit(FILE *fp,int n)
{
	switch(prg[n].data->emit)
	{
	case 0:	fprintf(fp,"{0x%02x,0,0,0,%s},\n",prg[n].code,prg[n].arg[0]);
		break;
	case 1:	fprintf(fp,"{0x%02x,0,0,0,0},\n",prg[n].code);
		break;
	case 2:	fprintf(fp,"{0x%02x,0,%d,0,%d},\n",prg[n].code,BPF_PSEUDO_CALL,
			prg[n].dstidx-prg[n].index-1);
		break;
	case 3:	fprintf(fp,"{0x%02x,0,%d,0,%s},\n",prg[n].code,prg[n].reg0,
			prg[n].arg[1]);
		break;
	case 4:	fprintf(fp,"{0x%02x,%d,%d,%s,0},\n",prg[n].code,prg[n].reg0,
			prg[n].reg1,prg[n].arg[2]);
		break;
	case 5:	fprintf(fp,"{0x%02x,%d,0,%s,%s},\n",prg[n].code,prg[n].reg0,
			prg[n].arg[1],prg[n].arg[2]);
		break;
	case 6:	if(prg[n].immediate)fprintf(fp,"{0x%02x,%d,0,0,%s},\n",
			prg[n].code,prg[n].reg0,prg[n].arg[1]);
		else fprintf(fp,"{0x%02x,%d,%d,0,0},\n",prg[n].code,prg[n].reg0,
			prg[n].reg1);
		break;
	case 7:	if(prg[n].immediate)fprintf(fp,"{0x%02x,%d,0,%d,%s},\n",
			prg[n].code,prg[n].reg0,prg[n].dstidx-prg[n].index-1,
			prg[n].arg[1]);
		else fprintf(fp,"{0x%02x,%d,%d,%d,0},\n",
			prg[n].code,prg[n].reg0,prg[n].reg1,
			prg[n].dstidx-prg[n].index-1);
		break;
	case 8:	fprintf(fp,"{0x%02x,0,0,%d,0},\n",prg[n].code,
			prg[n].dstidx-prg[n].index-1);
		break;
	case 9:	fprintf(fp,"{0x%02x,%d,0,0,%s},\n",prg[n].code,prg[n].reg0,
			prg[n].arg[1]);
		break;
	case 10:fprintf(fp,"{0x%02x,%d,0,0,(u_int32_t)(%s)},\n",prg[n].code,
			prg[n].reg0,prg[n].arg[1]);
		fprintf(fp,"{0x00,0,0,0,((u_int64_t)(%s))>>32},\n",
			prg[n].arg[1]);
		break;
	case 11:fprintf(fp,"{0x%02x,%d,%d,0,(u_int32_t)(%s)},\n",prg[n].code,
			prg[n].reg0,BPF_PSEUDO_MAP_FD,prg[n].arg[1]);
		fprintf(fp,"{0x00,0,0,0,((u_int64_t)(%s))>>32},\n",
			prg[n].arg[1]);
		break;
	}

	return 0;
}

static int labelcmp(const void *p1,const void *p2)
{
	int r;
	const struct label *l1=p1;
	const struct label *l2=p2;

	if((r=strcmp(l1->name,l2->name))>0)return 1;
	else if(r<0)return -1;

	if(l1->data->srcline>l2->data->srcline)return 1;
	else if(l1->data->srcline<l2->data->srcline)return -1;

	return 0;
}

static int labelfind(char *item)
{
	int high=nlabels;
	int base=nlabels>>1;
	int i=nlabels>>2;
	int low=0;
	int r;

	for(;i;i>>=1)if(!(r=strcmp(item,labels[base].name)))return base;
	else if(r<0)
	{
		high=base;
		base-=i;
	}
	else
	{
		low=base+1;
		base+=i;
	}

	for(i=low;i<high;i++)if(!strcmp(item,labels[i].name))return i;
	return -1;
}

static int labelprocess(char **fn,int *n)
{
	int i;
	int j;

	for(i=0;i<insns;i++)if(prg[i].label)
	{
		labels[nlabels].name=prg[i].label;
		labels[nlabels++].data=&prg[i];
	}

	qsort(labels,nlabels,sizeof(labels[0]),labelcmp);

	for(i=0;i<nlabels-1;i++)if(!strcmp(labels[i].name,labels[i+1].name))
	{
		*n=labels[i+1].data->srcline;
		*fn=labels[i+1].data->srcfile;
		return -1;
	}

	for(i=0;i<nexp;i++)if((j=labelfind(exp[i].name))==-1)
	{
		*n=exp[i].srcline;
		*fn=exp[i].srcfile;
		return -2;
	}
	else
	{
		exp[i].dstidx=labels[j].data->index;
		exp[i].dstlen=labels[j].data->data->len;
	}

	for(i=0;i<insns;i++)if(prg[i].target)
	{
		if((j=labelfind(prg[i].target))==-1)
		{
			*n=prg[i].srcline;
			*fn=prg[i].srcfile;
			return -2;
		}
		else prg[i].dstidx=labels[j].data->index;
	}

	return 0;
}

static int regparse(char *name)
{
	if(name[0]=='r'&&name[1]&&!name[2])switch(name[1])
	{
	case '0':return BPF_REG_0;
	case '1':return BPF_REG_1;
	case '2':return BPF_REG_2;
	case '3':return BPF_REG_3;
	case '4':return BPF_REG_4;
	case '5':return BPF_REG_5;
	case '6':return BPF_REG_6;
	case '7':return BPF_REG_7;
	case '8':return BPF_REG_8;
	case '9':return BPF_REG_9;
	default: return -1;
	}
	else if(!strcmp(name,"r10"))return BPF_REG_10;
	else if(!strcmp(name,"fp"))return BPF_REG_10;
	else return -1;
}

static int preprocess(int n,int *idx)
{
	int i;
	int code;

	for(i=0;cvt[i].opcode;i++)
		if(!strcmp(prg[n].opcode,cvt[i].opcode))break;
	if(!cvt[i].opcode)return -1;

	if(cvt[i].args!=prg[n].args)return -1;

	code=cvt[i].code;

	switch(cvt[i].sizes)
	{
	case 12:
		if(!prg[n].size||(prg[n].size&3))return -1;
		if(prg[n].size&4)code|=BPF_ALU;
		else code|=BPF_ALU64;
		if(prg[n].immediate)code|=BPF_K;
		else code|=BPF_X;
		break;

	case 15:switch(prg[n].size)
		{
		case 1:	code|=BPF_B;
			break;
		case 2:	code|=BPF_H;
			break;
		case 4:	code|=BPF_W;
			break;
		case 8:	code|=BPF_DW;
			break;
		default:return -1;
		}
		break;

	default:if(prg[n].size)return -1;
		break;
	}

	if(cvt[i].xk)
	{
		if(prg[n].immediate)
		{
			if(cvt[i].immpos!=prg[n].immediate)return -1;
			code|=BPF_K;
		}
		else code|=BPF_X;
	}
	else if(cvt[i].immpos!=prg[n].immediate)return -1;

	switch(cvt[i].regs)
	{
	case 2: if(!(cvt[i].xk&&prg[n].immediate))
			if((prg[n].reg1=regparse(prg[n].arg[1]))==-1)return -1;
	case 1:	if((prg[n].reg0=regparse(prg[n].arg[0]))==-1)return -1;
		break;
	}

	if(cvt[i].label)prg[n].target=prg[n].arg[cvt[i].label-1];

	prg[n].code=code;
	prg[n].data=&cvt[i];
	prg[n].index=*idx;
	*idx+=cvt[i].len;

	return 0;
}

static int parse_line(char *line,int num,char *file,int nest,char **errfn,
	int *errline)
{
	int i;
	int n=0;
	int q=0;
	int l=0;
	int e=0;
	int size=0;
	char *ptr;
	char *clr;
	char *label=NULL;
	char *opcode=NULL;
	char *args[3];
	FILE *fp;

	*errfn=file;
	*errline=num;

	clr=line;
	for(ptr=line;*ptr&&*ptr!='\r'&&*ptr!='\n'&&*ptr!=';';ptr++);
	if(*ptr)*ptr=0;

	while(*line==' '||*line=='\t')line++;
	if(!*line)return 0;

	if(!strncmp(line,"include ",8))
	{
		if(nest==MAX_NESTING)return -1;

		line+=8;
		while(*line==' '||*line=='\t')line++;
		for(ptr=line;*ptr&&*ptr!=' '&&*ptr!='\t'&&*ptr!=';';ptr++);
		if(*ptr)*ptr=0;
		if(!*line)return -1;

		if(!(fp=fopen(line,"re")))return -1;

		if(!(ptr=strdup(ptr)))
		{
			fclose(fp);
			return -1;
		}
		i=0;

		while(fgets(clr,1024,fp))
			if(parse_line(clr,++i,line,nest+1,errfn,errline))
		{
			fclose(fp);
			return -1;
		}

		fclose(fp);
		return 0;
	}

	for(ptr=line;*ptr&&*ptr!=' '&&*ptr!='\t';ptr++);

	if(ptr!=line&&ptr[-1]==':')
	{
		label=line;
		ptr[-1]=0;

		if(*ptr)*ptr++=0;
		if(!*line)goto eol;
		line=ptr;
		while(*line==' '||*line=='\t')line++;
		if(!*line)goto eol;

		for(ptr=line;*ptr&&*ptr!=' '&&*ptr!='\t';ptr++);
	}

	opcode=line;

	if(ptr!=line)switch(ptr[-1])
	{
	case 'b':
		size=1;
		ptr[-1]=0;
		break;

	case 'h':
		size=2;
		ptr[-1]=0;
		break;

	case 'w':
		size=4;
		ptr[-1]=0;
		break;

	case 'd':
		size=8;
		ptr[-1]=0;
		break;
	}

	if(*ptr)*ptr++=0;
	if(!*line)goto eol;
	line=ptr;
	while(*line==' '||*line=='\t')line++;
	if(!*line)goto eol;

	for(i=0;i<3;i++)
	{
		for(ptr=line;*ptr;ptr++)
		{
			switch(*ptr)
			{
			case '"':
				if(!e)q=1-q;
				break;

			case '(':
				if(!e&&!q)l++;
				break;

			case ')':
				if(!e&&!q)l--;
				break;

			case '\\':
				if(!e)e=2;
				break;
			}

			if(e)e--;
			if(*ptr==','&&!e&&!q&&!l)break;
		}

		args[n++]=line;

		for(clr=ptr;clr!=line;clr--)if(clr[-1]!=' '&&clr[-1]!='\t')
		{
			if(clr!=ptr)*clr=0;
			break;
		}

		if(*ptr)*ptr++=0;
		if(!*line)goto eol;
		line=ptr;
		while(*line==' '||*line=='\t')line++;
		if(!*line)goto eol;
	}

	if(*line)return -1;

eol:	if(!label&&!opcode&&!n)return 0;

	if(label&&!opcode)return -1;
	if(label&&!*label)return -1;
	if(opcode&&!*opcode)return -1;
	for(i=0;i<n;i++)if(args[i]&&!*args[i])return -1;
	if(insns==MAX_INSNS)return -1;

	memset(&prg[insns],0,sizeof(struct prog));
	prg[insns].reg0=-1;
	prg[insns].reg1=-1;

	if(label)if(!(prg[insns].label=strdup(label)))return -1;

	if(!(prg[insns].opcode=strdup(opcode)))return -1;

	for(i=0;i<n;i++)if(args[i][0]=='#')
	{
		prg[insns].immediate=i+1;

		ptr=args[i]+1;
		while(*ptr==' '||*ptr=='\t')ptr++;
		if(!*ptr)return -1;
		args[i]=ptr;

		for(i++;i<n;i++)if(args[i][0]=='#')return -1;
		break;
	}

	for(i=0;i<n;i++)if(!(prg[insns].arg[i]=strdup(args[i])))return -1;

	prg[insns].size=size;
	prg[insns].args=n;
	prg[insns].srcfile=file;
	prg[insns++].srcline=num;

	return 0;
}

static int hdrline(char *line,int num,int *index)
{
	int i;
	char *item;

	*index=-1;

	while(*line==' '||*line=='\t')line++;
	if(!*line||*line==';')return 0;

	item=strtok(line," \t\r\n");
	if(!item||!*item)return 0;

	for(i=0;i<e_max;i++)if(!strcmp(item,hdr[i].name))
	{
		switch(hdr[i].type)
		{
		case 0:	if(hdr[i].value)
			{
				fprintf(stderr,"duplicate %s line %d\n",
					hdr[i].name,num);
				return -1;
			}
			hdr[i].value=1;
			break;

		case 1:	if(hdr[i].string)
			{
				fprintf(stderr,"duplicate %s line %d\n",
					hdr[i].name,num);
				return -1;
			}
		case 2:	item=strtok(NULL," \t\r\n");
			if(!item||!*item)
			{
				fprintf(stderr,"invalid %s line %d\n",
					hdr[i].name,num);
				return -1;
			}
			if(!(hdr[i].string=strdup(item)))
			{
				fprintf(stderr,"out of memory line %d\n",num);
				return -1;
			}
			break;
		}

		*index=i;
		return 1;
	}

	fprintf(stderr,"unknown command line %d\n",num);
	return -1;
}

static int fileworker(char *in,char *out)
{
	int n=0;
	int idx;
	int num;
	FILE *fp;
	char *ptr;
	char line[1024];

	if(!(fp=fopen(in,"re")))
	{
		fprintf(stderr,"cannot open %s\n",in);
		goto err1;
	}

	while(fgets(line,sizeof(line),fp))
	{
		switch(hdrline(line,++n,&idx))
		{
		case 1:	switch(idx)
			{
			case e_export:
				if(nexp==MAX_EXPORT)
				{
					fprintf(stderr,"export overflow "
						"line %d\n",n);
					goto err2;
				}
				exp[nexp].name=hdr[e_export].string;
				exp[nexp].srcline=n;
				exp[nexp].srcfile=in;
				exp[nexp++].dstidx=0;
				break;

			case e_code:
				if(!hdr[e_name].string)
				{
					fprintf(stderr,"name not defined "
						"line %d\n",n);
					goto err2;
				}
				goto code;
			}
			break;

		case -1:goto err2;
		}

	}

	fprintf(stderr,"unexpected eof line %d\n",n);
	goto err2;

code:	while(fgets(line,sizeof(line),fp))
		if(parse_line(line,++n,in,0,&ptr,&num))
	{
		fprintf(stderr,"parse error file %s line %d\n",ptr,num);
		goto err2;
	}
	fclose(fp);

	if(!insns)
	{
		fprintf(stderr,"no statements line %d\n",n);
		goto err1;
	}

	for(idx=0,n=0;n<insns;n++)if(preprocess(n,&idx))
	{
		fprintf(stderr,"syntax error file %s line %d\n",prg[n].srcfile,
			prg[n].srcline);
		goto err1;
	}

	switch(labelprocess(&ptr,&num))
	{
	case -1:fprintf(stderr,"duplicate label file %s line %d\n",ptr,num);
		goto err1;

	case -2:fprintf(stderr,"missing label file %s line %d\n",ptr,num);
		goto err1;
	}

	if(!out)fp=stdout;
	else if(!(fp=fopen(out,"we")))
	{
		fprintf(stderr,"cannot open %s\n",out);
		goto err1;
	}

	fprintf(fp,"%s%sstruct bpf_insn %s[]={\n",
		hdr[e_static].value?"static ":"",
		hdr[e_const].value?"const ":"",hdr[e_name].string);

	for(n=0;n<insns;n++)emit(fp,n);

	fprintf(fp,"};\n");

	if(hdr[e_upcase].value)for(ptr=hdr[e_name].string;*ptr;ptr++)
		*ptr=toupper(*ptr);

	if(hdr[e_size].value)fprintf(fp,"#define %s_%s %d\n",hdr[e_name].string,
		hdr[e_upcase].value?"SIZE":"size",idx);

	for(n=0;n<nexp;n++)
	{
		if(hdr[e_upcase].value)for(ptr=exp[n].name;*ptr;ptr++)
			*ptr=toupper(*ptr);

		if(exp[n].dstlen==1)
		{
			fprintf(fp,"#define %s %d\n",exp[n].name,
				exp[n].dstidx);
			continue;
		}

		fprintf(fp,"#define %s_%c %d\n",exp[n].name,
			hdr[e_upcase].value?'L':'l',exp[n].dstidx);
		fprintf(fp,"#define %s_%c %d\n",exp[n].name,
			hdr[e_upcase].value?'H':'h',exp[n].dstidx+1);
	}

	if(fp!=stdout)fclose(fp);

	return 0;

err2:	fclose(fp);
err1:	return -1;
}

int main(int argc,char *argv[])
{
	if(argc<2)
	{
		fprintf(stderr,"Usage: ebpf2c <source> [<destination>]\n");
		return 1;
	}

	if(fileworker(argv[1],argc==2?NULL:argv[2]))return 1;

	return 0;
}
