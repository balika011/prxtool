/***************************************************************
 * PRXTool : Utility for PSP executables.
 * (c) TyRaNiD 2k5
 *
 * elftypes.h - Definitions for the different ELF types.
 ***************************************************************/

#ifndef __ELF_TYPES_H__
#define __ELF_TYPES_H__

#include "types.h"

#define ELF_SECT_MAX_NAME 128

/* Structure defining a single elf section */
struct ElfSection
{
	/* Name index */
	u32 iName;
	/* Type of section */
	u32 iType;
	/* Section flags */
	u32 iFlags;
	/* Addr of section when loaded */
	u32 iAddr;
	/* Offset of the section in the elf */
	u32 iOffset;
	/* Size of the sections data */
	u32 iSize;
	/* Link info */
	u32 iLink;
	/* Info */
	u32 iInfo;
	/* Address alignment */
	u32 iAddralign;
	/* Entry size */
	u32 iEntsize;

	/* Aliased pointer to the data (in the original Elf) */
	u8 *pData;
	/* Name of the section */
	char szName[ELF_SECT_MAX_NAME];
	/* Pointer to the head of the relocs (if any) */
	struct ElfReloc *pRelocs;
	/* Number of relocs for this section */
	u32 iRelocCount;
};

struct ElfProgram
{
	u32 iType;
	u32 iOffset;
	u32 iVaddr;
	u32 iPaddr;
	u32 iFilesz;
	u32 iMemsz;
	u32 iFlags;
	u32 iAlign;

	/* Aliased pointer to the data (in the original Elf)*/
	u8  *pData;
};

/* Structure to hold elf header data, in native format */
struct ElfHeader
{
	u32 iMagic;
	u32 iClass;
	u32 iData;
	u32 iIdver;
	u32 iType; 
	u32 iMachine; 
	u32 iVersion; 
	u32 iEntry; 
	u32 iPhoff; 
	u32 iShoff; 
	u32 iFlags; 
	u32 iEhsize;
	u32 iPhentsize; 
	u32 iPhnum; 
	u32 iShentsize; 
	u32 iShnum; 
	u32 iShstrndx; 
};

struct ElfReloc
{
	/* Pointer to the section name */
	const char* secname;
	/* Base address */
	u32 base;
	/* Type */
	u32 type;
	/* Symbol (if known) */
	u32 symbol;
	/* Offset into the file */
	u32 offset;
	/* New Address for the relocation (to do with what you will) */
	u32 info;
	u32 addr;
};

struct ElfSymbol
{
	const char *symname;
	u32 name;
	u32 value;
	u32 size;
	u32 info;
	u32 other;
	u32 shndx;
};

/* Define ELF types */
typedef u32 Elf32_Addr; 
typedef u16 Elf32_Half;
typedef u32 Elf32_Off;
typedef s32 Elf32_Sword;
typedef u32 Elf32_Word;

#define ELF_MAGIC	0x464C457F

#define ELF_MIPS_TYPE 0x0002
#define ELF_PRX_TYPE  0xFE04

#define SHT_NULL 0 
#define SHT_PROGBITS 1 
#define SHT_SYMTAB 2 
#define SHT_STRTAB 3 
#define SHT_RELA 4 
#define SHT_HASH 5 
#define SHT_DYNAMIC 6 
#define SHT_NOTE 7 
#define SHT_NOBITS 8 
#define SHT_REL 9 
#define SHT_SHLIB 10 
#define SHT_DYNSYM 11 
#define SHT_LOPROC 0x70000000 
#define SHT_HIPROC 0x7fffffff 
#define SHT_LOUSER 0x80000000 
#define SHT_HIUSER 0xffffffff

#define SHF_WRITE 		1
#define SHF_ALLOC 		2
#define SHF_EXECINSTR 	4

#define PT_NULL 		0
#define PT_LOAD 		1
#define PT_DYNAMIC 		2
#define PT_INTERP 		3
#define PT_NOTE 		4
#define PT_SHLIB 		5
#define PT_PHDR 		6
#define PT_LOPROC 		0x70000000
#define PT_HIPROC 		0x7fffffff

#define PT_SCE_RELA 0x60000000

/** \name SCE Relocation
 *  @{
 */
typedef union sce_reloc
{
    u32       r_type;
    struct
    {
        u32   r_opt1;
        u32   r_opt2;
    } r_short;
    struct
    {
        u32   r_type;
        u32   r_addend;
        u32   r_offset;
    } r_long;
} sce_reloc_t;
/** @}*/

/** \name Macros to get SCE reloc values
 *  @{
 */
#define SCE_RELOC_SHORT_OFFSET(x) (((x).r_opt1 >> 20) | ((x).r_opt2 & 0xFFFFF) << 12)
#define SCE_RELOC_SHORT_ADDEND(x) ((x).r_opt2 >> 20)
#define SCE_RELOC_LONG_OFFSET(x) ((x).r_offset)
#define SCE_RELOC_LONG_ADDEND(x) ((x).r_addend)
#define SCE_RELOC_LONG_CODE2(x) (((x).r_type >> 20) & 0xFF)
#define SCE_RELOC_LONG_DIST2(x) (((x).r_type >> 28) & 0xF)
#define SCE_RELOC_IS_SHORT(x) (((x).r_type) & 0xF)
#define SCE_RELOC_CODE(x) (((x).r_type >> 8) & 0xFF)
#define SCE_RELOC_SYMSEG(x) (((x).r_type >> 4) & 0xF)
#define SCE_RELOC_DATSEG(x) (((x).r_type >> 16) & 0xF)
/** @}*/

/** \name Vita supported relocations
 *  @{
 */
#define R_ARM_NONE              0
#define R_ARM_ABS32             2
#define R_ARM_REL32             3
#define R_ARM_THM_CALL          10
#define R_ARM_CALL              28
#define R_ARM_JUMP24            29
#define R_ARM_TARGET1           38
#define R_ARM_V4BX              40
#define R_ARM_TARGET2           41
#define R_ARM_PREL31            42
#define R_ARM_MOVW_ABS_NC       43
#define R_ARM_MOVT_ABS          44
#define R_ARM_THM_MOVW_ABS_NC   47
#define R_ARM_THM_MOVT_ABS      48
/** @}*/

/* ELF file header */
typedef struct { 
	Elf32_Word e_magic;
	u8 e_class;
	u8 e_data;
	u8 e_idver;
	u8 e_pad[9];
	Elf32_Half e_type; 
	Elf32_Half e_machine; 
	Elf32_Word e_version; 
	Elf32_Addr e_entry; 
	Elf32_Off e_phoff; 
	Elf32_Off e_shoff; 
	Elf32_Word e_flags; 
	Elf32_Half e_ehsize; 
	Elf32_Half e_phentsize; 
	Elf32_Half e_phnum; 
	Elf32_Half e_shentsize; 
	Elf32_Half e_shnum; 
	Elf32_Half e_shstrndx; 
} __attribute__((packed)) Elf32_Ehdr;

/* ELF section header */
typedef struct { 
	Elf32_Word sh_name; 
	Elf32_Word sh_type; 
	Elf32_Word sh_flags; 
	Elf32_Addr sh_addr; 
	Elf32_Off sh_offset; 
	Elf32_Word sh_size; 
	Elf32_Word sh_link; 
	Elf32_Word sh_info; 
	Elf32_Word sh_addralign; 
	Elf32_Word sh_entsize; 
} __attribute__((packed)) Elf32_Shdr;

typedef struct { 
	Elf32_Word p_type; 
	Elf32_Off p_offset; 
	Elf32_Addr p_vaddr; 
	Elf32_Addr p_paddr; 
	Elf32_Word p_filesz; 
	Elf32_Word p_memsz; 
	Elf32_Word p_flags; 
	Elf32_Word p_align; 
} Elf32_Phdr;

#define ELF32_R_SYM(i) ((i)>>8) 
#define ELF32_R_TYPE(i) ((u8)(i&0xFF))

typedef struct { 
	Elf32_Addr r_offset; 
	Elf32_Word r_info; 
} Elf32_Rel;

#define ELF32_ST_BIND(i) ((i)>>4)
#define ELF32_ST_TYPE(i) ((i)&0xf)
#define ELF32_ST_INFO(b,t) (((b)<<4)+((t)&0xf))

#define STT_NOTYPE 0
#define STT_OBJECT 1
#define STT_FUNC 2
#define STT_SECTION 3
#define STT_FILE 4
#define STT_LOPROC 13
#define STT_HIPROC 15

typedef struct { 
	Elf32_Word st_name; 
	Elf32_Addr st_value; 
	Elf32_Word st_size; 
	unsigned char st_info; 
	unsigned char st_other; 
	Elf32_Half st_shndx; 
} __attribute__((packed)) Elf32_Sym;

#endif
