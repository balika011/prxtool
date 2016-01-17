/***************************************************************
 * PRXTool : Utility for PSP executables.
 * (c) TyRaNiD 2k6
 *
 * disasm.C - Implementation of a MIPS disassembler
 ***************************************************************/

#include <stdio.h>
#include <string.h>
#include "disasm.h"

#include <capstone.h>

static int g_hexints = 0;
static int g_mregs = 0;
static int g_symaddr = 0;
static int g_macroon = 0;
static int g_printreal = 0;
static int g_printregs = 0;
static int g_regmask = 0;
static int g_printswap = 0;
static int g_signedhex = 0;
static int g_xmloutput = 0;
static SymbolMap *g_syms = NULL;

struct DisasmOpt
{
	char opt;
	int *value;
	const char *name;
};

struct DisasmOpt g_disopts[DISASM_OPT_MAX] = {
	{ DISASM_OPT_HEXINTS, &g_hexints, "Hex Integers" },
	{ DISASM_OPT_MREGS, &g_mregs, "Mnemonic Registers" },
	{ DISASM_OPT_SYMADDR, &g_symaddr, "Symbol Address" },
	{ DISASM_OPT_MACRO, &g_macroon, "Macros" },
	{ DISASM_OPT_PRINTREAL, &g_printreal, "Print Real Address" },
	{ DISASM_OPT_PRINTREGS, &g_printregs, "Print Regs" },
	{ DISASM_OPT_PRINTSWAP, &g_printswap, "Print Swap" },
	{ DISASM_OPT_SIGNEDHEX, &g_signedhex, "Signed Hex" },
};

cs_mode disasm_mode = (cs_mode)(CS_MODE_ARM);

void SetThumbMode(bool mode)
{
	if(mode)
	{
		disasm_mode = (cs_mode)(CS_MODE_THUMB);
	}
}

SymbolType disasmResolveSymbol(unsigned int PC, char *name, int namelen)
{
	SymbolEntry *s;
	SymbolType type = SYMBOL_NOSYM;

	if(g_syms)
	{
		s = (*g_syms)[PC];
		if(s)
		{
			type = s->type;
			snprintf(name, namelen, "%s", s->name.c_str());
		}
	}

	return type;
}

SymbolType disasmResolveRef(unsigned int PC, char *name, int namelen)
{
	SymbolEntry *s;
	SymbolType type = SYMBOL_NOSYM;

	if(g_syms)
	{
		s = (*g_syms)[PC];
		if((s) && (s->imported.size() > 0))
		{
			unsigned int nid = 0;
			PspLibImport *pImp = s->imported[0];

			for(int i = 0; i < pImp->f_count; i++)
			{
				if(strcmp(s->name.c_str(), pImp->funcs[i].name) == 0)
				{
					nid = pImp->funcs[i].nid;
					break;
				}
			}
			type = s->type;
			snprintf(name, namelen, "/%s/%s/nid:0x%08X", pImp->file, pImp->name, nid);
		}
	}

	return type;
}

SymbolEntry* disasmFindSymbol(unsigned int PC)
{
	SymbolEntry *s = NULL;

	if(g_syms)
	{
		s = (*g_syms)[PC];
	}

	return s;
}

int disasmIsBranch(unsigned int opcode, unsigned int *PC, unsigned int *dwTarget)
{
	u32 old_PC = *PC;

	int type = 0;

	static csh handle;
	cs_err err = cs_open(CS_ARCH_ARM, disasm_mode, &handle);
	if (err) {
		(*PC) += 4;
		return 0;
	}

	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	cs_insn *insn;
	size_t count = cs_disasm(handle, (unsigned char *)&opcode, 4, *PC, 0, &insn);
	size_t ori_count = count;
	if (count) {
		if (count == 1) {
			cs_insn *insn2;
			int count2 = cs_disasm(handle, (unsigned char *)&opcode, 2, *PC, 0, &insn2);
			if (count2 == 1) {
				if (strcmp(insn->mnemonic, insn2->mnemonic) == 0 && strcmp(insn->op_str, insn2->op_str) == 0) {
					count = 2;
				}
			}

			cs_free(insn2, count2);
		}

		if (disasm_mode == (cs_mode)(CS_MODE_THUMB)) {
			if (count == 2) {
				(*PC) += 2;
				opcode = opcode & 0xFFFF;
			} else {
				(*PC) += 4;
			}
		} else {
			(*PC) += 4;
		}

		cs_arm *arm = &(insn->detail->arm);

		int i;
		for (i = 0; i < arm->op_count; i++) {
			cs_arm_op *op = &(arm->operands[i]);
			switch((int)op->type) {
				default:
					break;
				case ARM_OP_IMM:
				{
					if(insn->mnemonic[0] == 'b')
					{
						if (strcmp(insn->mnemonic, "bfi") != 0 && strcmp(insn->mnemonic, "bkpt") != 0 && strcmp(insn->mnemonic, "bics") != 0) {
							type = INSTR_TYPE_LOCAL;
							
							if (strcmp(insn->mnemonic, "bl") == 0 || strcmp(insn->mnemonic, "blx") == 0) {
								type = INSTR_TYPE_FUNC;
							}

							if(dwTarget)
							{
								if (strcmp(insn->mnemonic, "blx") == 0) {
									if (old_PC & 0x2) {
										op->imm -= 4;
									}
								}

								*dwTarget = op->imm;
							}
						}
					}
					else if(insn->mnemonic[0] == 'c' && insn->mnemonic[1] == 'b')
					{
						type = INSTR_TYPE_LOCAL;
						
						if(dwTarget)
						{
							*dwTarget = op->imm;
						}
					}
					
					break;
				}
			}
		}
		
		// free memory allocated by cs_disasm()
		cs_free(insn, ori_count);
	} else {
		(*PC) += 4;
	}

	cs_close(&handle);

	return type;
}

void disasmAddBranchSymbols(unsigned int opcode, unsigned int *PC, SymbolMap &syms)
{
	SymbolType type;
	int insttype;
	unsigned int addr;
	SymbolEntry *s;
	char buf[128];

	u32 old_PC = *PC;
	insttype = disasmIsBranch(opcode, PC, &addr);
	if(insttype != 0)
	{
		if(insttype == INSTR_TYPE_LOCAL)
		{
			snprintf(buf, sizeof(buf), "loc_%08X", addr);
			type = SYMBOL_LOCAL;
		}
		else
		{
			snprintf(buf, sizeof(buf), "sub_%08X", addr);
			type = SYMBOL_FUNC;
		}

		s = syms[addr];
		if(s == NULL)
		{
			s = new SymbolEntry;
			s->addr = addr;
			s->type = type;
			s->size = 0;
			s->name = buf;
			s->refs.insert(s->refs.end(), old_PC);
			syms[addr] = s;
		}
		else
		{
			if((s->type != SYMBOL_FUNC) && (type == SYMBOL_FUNC))
			{
				s->type = SYMBOL_FUNC;
			}
			s->refs.insert(s->refs.end(), old_PC);
		}
	}
}

int movw[100];
int movt[100];

void resetMovwMovt() {
	memset(movw, 0, sizeof(movw));
	memset(movt, 0, sizeof(movt));
}

int disasmAddStringRef(unsigned int opcode, unsigned int base, unsigned int size, unsigned int PC, ImmMap &imms)
{
	int type = 0;

	static csh handle;
	cs_err err = cs_open(CS_ARCH_ARM, disasm_mode, &handle);
	if (err) {
		return 0;
	}

	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	cs_insn *insn;
	size_t count = cs_disasm(handle, (unsigned char *)&opcode, 4, PC, 0, &insn);
	size_t ori_count = count;
	if (count) {
		if (count == 1) {
			cs_insn *insn2;
			int count2 = cs_disasm(handle, (unsigned char *)&opcode, 2, PC, 0, &insn2);
			if (count2 == 1) {
				if (strcmp(insn->mnemonic, insn2->mnemonic) == 0 && strcmp(insn->op_str, insn2->op_str) == 0) {
					count = 2;
				}
			}

			cs_free(insn2, count2);
		}

		if (disasm_mode == (cs_mode)(CS_MODE_THUMB)) {
			if (count == 2) {
				opcode = opcode & 0xFFFF;
			}
		}

		cs_arm *arm = &(insn->detail->arm);

		if (strcmp(insn->mnemonic, "movw") == 0 || strcmp(insn->mnemonic, "movs.w") == 0) {
			int slot = ((cs_arm_op *)&(arm->operands[0]))->imm;
			int val = ((cs_arm_op *)&(arm->operands[1]))->imm;
			movw[slot] = val;

			if (movt[slot] != 0) {
				unsigned int addr = (movt[slot] << 16) | (movw[slot] & 0xFFFF);
				if (addr >= base && addr < base + size) {
					ImmEntry *imm = new ImmEntry;
					imm->addr = PC;
					imm->target = addr;
					imm->text = 0;
					imms[PC] = imm;
				}

				movw[slot] = 0;
				movt[slot] = 0;
			}
		} else if (strcmp(insn->mnemonic, "movt") == 0) {
			int slot = ((cs_arm_op *)&(arm->operands[0]))->imm;
			int val = ((cs_arm_op *)&(arm->operands[1]))->imm;
			movt[slot] = val;

			if (movw[slot] != 0) {
				unsigned int addr = (movt[slot] << 16) | (movw[slot] & 0xFFFF);
				if (addr >= base && addr < base + size) {					
					ImmEntry *imm = new ImmEntry;
					imm->addr = PC;
					imm->target = addr;
					imm->text = 0;
					imms[PC] = imm;
				}

				movw[slot] = 0;
				movt[slot] = 0;
			}
		}

		if (strcmp(insn->mnemonic, "bl") == 0 || strcmp(insn->mnemonic, "blx") == 0) {
			resetMovwMovt();
		}

		// free memory allocated by cs_disasm()
		cs_free(insn, ori_count);
	}

	cs_close(&handle);

	return type;
}

void disasmSetHexInts(int hexints)
{
	g_hexints = hexints;
}

void disasmSetMRegs(int mregs)
{
	g_mregs = mregs;
}

void disasmSetSymAddr(int symaddr)
{
	g_symaddr = symaddr;
}

void disasmSetMacro(int macro)
{
	g_macroon = macro;
}

void disasmSetPrintReal(int printreal)
{
	g_printreal = printreal;
}

void disasmSetSymbols(SymbolMap *syms)
{
	g_syms = syms;
}

void disasmSetOpts(const char *opts, int set)
{
	while(*opts)
	{
		char ch;
		int i;

		ch = *opts++;
		for(i = 0; i < DISASM_OPT_MAX; i++)
		{
			if(ch == g_disopts[i].opt)
			{
				*g_disopts[i].value = set;
				break;
			}
		}
		if(i == DISASM_OPT_MAX)
		{
			printf("Unknown disassembler option '%c'\n", ch);
		}
	}
}

void disasmPrintOpts(void)
{
	int i;

	printf("Disassembler Options:\n");
	for(i = 0; i < DISASM_OPT_MAX; i++)
	{
		printf("%c : %-3s - %s \n", g_disopts[i].opt, *g_disopts[i].value ? "on" : "off", 
				g_disopts[i].name);
	}
}

void format_line(char *code, int codelen, const char *addr, unsigned int opcode, const char *name, const char *args, int noaddr)
{
	char ascii[17];
	char *p;
	int i;

	if(name == NULL)
	{
		name = "Unknown";
		args = "";
	}

	p = ascii;
	for(i = 0; i < 4; i++)
	{
		unsigned char ch;

		ch = (unsigned char) ((opcode >> (i*8)) & 0xFF);
		if((ch < 32) || (ch > 126))
		{
			ch = '.';
		}
		if(g_xmloutput && (ch == '<'))
		{
			strcpy(p, "&lt;");
			p += strlen(p);
		}
		else
		{
			*p++ = ch;
		}
	}
	*p = 0;

	if(noaddr)
	{
		snprintf(code, codelen, "%-10s %s", name, args);
	}
	else
	{
		if(g_printswap)
		{
			if(g_xmloutput)
			{
				snprintf(code, codelen, "%-10s %-80s ; %s: 0x%08X '%s'", name, args, addr, opcode, ascii);
			}
			else
			{
				snprintf(code, codelen, "%-10s %-40s ; %s: 0x%08X '%s'", name, args, addr, opcode, ascii);
			}
		}
		else
		{
			snprintf(code, codelen, "%s: 0x%08X '%s' - %-10s %s", addr, opcode, ascii, name, args);
		}
	}
}

void format_line_xml(char *code, int codelen, const char *addr, unsigned int opcode, const char *name, const char *args)
{
	char ascii[17];
	char *p;
	int i;

	if(name == NULL)
	{
		name = "Unknown";
		args = "";
	}

	p = ascii;
	for(i = 0; i < 4; i++)
	{
		unsigned char ch;

		ch = (unsigned char) ((opcode >> (i*8)) & 0xFF);
		if((ch < 32) || (ch > 126))
		{
			ch = '.';
		}
		if(g_xmloutput && (ch == '<'))
		{
			strcpy(p, "&lt;");
			p += strlen(p);
		}
		else
		{
			*p++ = ch;
		}
	}
	*p = 0;

	snprintf(code, codelen, "<name>%s</name><opcode>0x%08X</opcode>%s", name, opcode, args);
}

typedef struct {
	const char *old_reg;
	const char *new_reg;
} Register;

Register registers[] = {
	{ "r0", "a1" },
	{ "r1", "a2" },
	{ "r2", "a3" },
	{ "r3", "a4" },

	{ "r4", "v1" },
	{ "r5", "v2" },
	{ "r6", "v3" },
	{ "r7", "v4" },
	{ "r8", "v5" },

	{ "sb", "v6" },
	{ "sl", "v7" },
	{ "fp", "v8" },
};

const char *disasmInstruction(unsigned int opcode, unsigned int *PC, unsigned int *realregs, unsigned int *regmask, int nothumb)
{
	static char code[1024];
	const char *name = NULL;
	char mnemonic[1024];
	char args[1024];
	char addr[1024];
	int size;
	int i;
	
	sprintf(addr, "0x%08X", *PC);
	if((g_syms) && (g_symaddr))
	{
		char addrtemp[128];
		/* Symbol resolver shouldn't touch addr unless it finds symbol */
		if(disasmResolveSymbol(*PC, addrtemp, sizeof(addrtemp)))
		{
			snprintf(addr, sizeof(addr), "%-20s", addrtemp);
		}
	}

	cs_mode old_disasm_mode = disasm_mode;
/*
	if (nothumb) {
		
		disasm_mode = (cs_mode)(CS_MODE_ARM);
	}
*/
	static csh handle;
	cs_err err = cs_open(CS_ARCH_ARM, disasm_mode, &handle);
	if (err) {
		(*PC) += 4;
		disasm_mode = old_disasm_mode;
		return NULL;
	}

	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	cs_insn *insn;
	size_t count = cs_disasm(handle, (unsigned char *)&opcode, 4, *PC, 0, &insn);
	size_t ori_count = count;
	if (count) {
		if (count == 1) {
			cs_insn *insn2;
			int count2 = cs_disasm(handle, (unsigned char *)&opcode, 2, *PC, 0, &insn2);
			if (count2 == 1) {
				if (strcmp(insn->mnemonic, insn2->mnemonic) == 0 && strcmp(insn->op_str, insn2->op_str) == 0) {
					count = 2;
				}
			}
			
			cs_free(insn2, count2);
		}

		strcpy(mnemonic, insn->mnemonic);
		strcpy(args, insn->op_str);
		
		name = mnemonic;

		// Replace registers
		int i;
		for(i = 0; i < strlen(insn->op_str); i++)
		{
			int j;
			for(j = 0; j < sizeof(registers) / sizeof(Register); j++)
			{
				if(strncmp(args + i, registers[j].old_reg, 2) == 0)
				{
					memcpy(args + i, registers[j].new_reg, 2);
					break;
				}
			}
		}

		// Branch names
		unsigned int addr;
		u32 lol = *PC;
		int insttype = disasmIsBranch(opcode, &lol, &addr);
		if(insttype != 0)
		{
			if(g_syms)
			{
				char args_resolved[1024];
				disasmResolveSymbol(addr, args_resolved, sizeof(args_resolved));
				if(insn->mnemonic[0] == 'c' && insn->mnemonic[1] == 'b') {
					char temp[1024];
					strcpy(temp, args);
					char *p = strchr(temp, '#');
					if (p) {
						strcpy(p, args_resolved);
					}

					strcpy(args, temp);
				} else {
					strcpy(args, args_resolved);
				}
			}
		}

		if (disasm_mode == (cs_mode)(CS_MODE_THUMB)) {
			if (count == 2) {
				(*PC) += 2;
				opcode = opcode & 0xFFFF;
			} else {
				(*PC) += 4;
			}
		} else {
			(*PC) += 4;
		}

		// free memory allocated by cs_disasm()
		cs_free(insn, ori_count);
	} else {
		(*PC) += 4;
	}

	cs_close(&handle);

	format_line(code, sizeof(code), addr, opcode, name, args, 0);

	disasm_mode = old_disasm_mode;
	return code;
}

//TODO
const char *disasmInstructionXML(unsigned int opcode, unsigned int PC)
{
}

void disasmSetXmlOutput()
{
	g_xmloutput = 1;
}
