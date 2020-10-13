#!/usr/bin/env python3
#-*- encoding: Utf-8 -*-
from typing import Dict, Union, Sequence, Set, Tuple, List
from re import search, findall, finditer, DOTALL
from collections import Counter
from argparse import Namespace
from enum import IntEnum
from io import BytesIO
from time import time
import logging

"""
    Guess the architecture of a given binary.
    
    For this, scan it for simple function prologues.
    Inspiration: https://github.com/ReFirmLabs/binwalk/blob/master/src/binwalk/magic/binarch
    
    Also, return a sequence of the spacing in bytes
    between each detected function prologue, so that
    it can be matched with function symbols from the
    kallsys table and the base address at the offset
    0 of the binary can be guessed.
"""

class ArchitectureGuessError(Exception):
    pass

class ArchitectureName(IntEnum):
    mipsle = 1
    mipsbe = 2
    mips64le = 3
    mips64be = 4
    x86 = 5
    x86_64 = 6
    powerpcbe = 7
    powerpcle = 8
    armle = 9
    armbe = 10
    aarch64 = 11
    mips16e = 12
    superhle = 13
    superhbe = 14
    sparc = 15
    arcompact = 16

# Prologues taken from the binwalk file linked above
architecture_to_prologue_regex : Dict[ArchitectureName, bytes] = {
    ArchitectureName.mipsle: br'.\xFF\xBD\x27..[\xA0-\xBF]\xAF',
    ArchitectureName.mipsbe: br'\x27\xBD\xFF.\xAF[\xA0-\xBF]..',
    ArchitectureName.mips64le: br'.\xFF\xBD\x67..[\xA0-\xBF]\xFF',
    ArchitectureName.mips64be: br'\x67\xBD\xFF.\xFF[\xA0-\xBF]..',
    ArchitectureName.x86: br'\x55\x89\xE5(?:\x83\xEC|\x57\x56)',
    ArchitectureName.x86_64: br'(?:\xe8....)?\x55\x48\x89\xE5', # Assume that a "call __fentry__" instruction may be present at the beginning of the prologue in recent x86_64 kernels
    ArchitectureName.powerpcbe: br'\x7C\x08\x02\xA6',
    ArchitectureName.powerpcle: br'\xA6\x02\x08\x7C',
    ArchitectureName.armbe: br'(?:\xE1\xA0\xC0\x0D)?\xE9\x2D..(?:[\xE0-\xEF]...){2}',
    ArchitectureName.armle: br'(?:\x0D\xC0\xA0\xE1)?..\x2D\xE9(?:...[\xE0-\xEF]){2}',
    ArchitectureName.mips16e: br'\xf0\x08\x64.\x01.',
    ArchitectureName.superhle: br'\xF6\x69\x0B\x00\xF6\x68', # This is an epilogue
    ArchitectureName.superhbe: br'\x69\xF6\x00\x0B\x68\xF6', # This is an epilogue
    ArchitectureName.aarch64: br'\xc0\x03\x5f\xd6', # This is an epilogue
    ArchitectureName.sparc: br'\x81\xC7\xE0\x08\x81\xE8', # This is an epilogue
    ArchitectureName.arcompact: b'\xF1\xC0.\x1C\x48[\xB0-\xBF]' # push_s blink; st.a r??, [sp, -??]
}


# From https://github.com/torvalds/linux/blob/master/include/uapi/linux/elf-em.h

# These constants define the various ELF target machines
EM_NONE = 0
EM_M32 = 1
EM_SPARC = 2
EM_386 = 3
EM_68K = 4
EM_88K = 5
EM_486 = 6 # Perhaps disused
EM_860 = 7
EM_MIPS = 8 # MIPS R3000 (officially, big-endian only)
# Next two are historical and binaries and
# modules of these types will be rejected by
# Linux. 
EM_MIPS_RS3_LE = 10 # MIPS R3000 little-endian
EM_MIPS_RS4_BE = 10 # MIPS R4000 big-endian

EM_PARISC = 15 # HPPA
EM_SPARC32PLUS = 18 # Sun's "v8plus"
EM_PPC = 20 # PowerPC
EM_PPC64 = 21 # PowerPC64
EM_SPU = 23 # Cell BE SPU
EM_ARM = 40 # ARM 32 bit
EM_SH = 42 # SuperH
EM_SPARCV9 = 43 # SPARC v9 64-bit
EM_H8_300 = 46 # Renesas H8/300
EM_IA_64 = 50 # HP/Intel IA-64
EM_X86_64 = 62 # AMD x86-64
EM_S390 = 22 # IBM S/390
EM_CRIS = 76 # Axis Communications 32-bit embedded processor
EM_M32R = 88 # Renesas M32R
EM_MN10300 = 89 # Panasonic/MEI MN10300, AM33
EM_OPENRISC = 92 # OpenRISC 32-bit embedded processor
EM_ARCOMPACT = 93 # ARCompact processor
EM_XTENSA = 94 # Tensilica Xtensa Architecture
EM_BLACKFIN = 106 # ADI Blackfin Processor
EM_UNICORE = 110 # UniCore-32
EM_ALTERA_NIOS2 = 113 # Altera Nios II soft-core processor
EM_TI_C6000 = 140 # TI C6X DSPs
EM_HEXAGON = 164 # QUALCOMM Hexagon
EM_NDS32 = 167 # Andes Technology compact code size embedded RISC processor family
EM_AARCH64 = 183 # ARM 64 bit
EM_TILEPRO = 188 # Tilera TILEPro
EM_MICROBLAZE = 189 # Xilinx MicroBlaze
EM_TILEGX = 191 # Tilera TILE-Gx
EM_ARCV2 = 195 # ARCv2 Cores
EM_RISCV = 243 # RISC-V
EM_BPF = 247 # Linux BPF - in-kernel virtual machine
EM_CSKY = 252 # C-SKY
EM_FRV = 0x5441 # Fujitsu FR-V

# This is an interim value that we will use until the committee comes
# up with a final number.
EM_ALPHA = 0x9026

# Bogus old m32r magic number, used by old tools.
EM_CYGNUS_M32R = 0x9041
# This is the old interim value for S/390 architecture
EM_S390_OLD = 0xA390
# Also Panasonic/MEI MN10300, AM33
EM_CYGNUS_MN10300 = 0xbeef


architecture_name_to_elf_machine_and_is64bits_and_isbigendian : Dict[ArchitectureName, Tuple[int, bool, bool]] = {
    ArchitectureName.mipsle: (EM_MIPS, False, False),
    ArchitectureName.mipsbe: (EM_MIPS, False, True),
    ArchitectureName.mips64le: (EM_MIPS, True, False),
    ArchitectureName.mips64be: (EM_MIPS, True, True),
    ArchitectureName.x86: (EM_386, False, False),
    ArchitectureName.x86_64: (EM_X86_64, True, False),
    ArchitectureName.powerpcbe: (EM_PPC, False, True),
    ArchitectureName.powerpcle: (EM_PPC, False, False),
    ArchitectureName.armbe: (EM_ARM, False, True),
    ArchitectureName.armle: (EM_ARM, False, False),
    ArchitectureName.mips16e: (EM_MIPS, False, True),
    ArchitectureName.superhle: (EM_SH, False, False),
    ArchitectureName.superhbe: (EM_SH, False, True),
    ArchitectureName.aarch64: (EM_AARCH64, True, False),
    ArchitectureName.sparc: (EM_SPARC, False, True),
    ArchitectureName.arcompact: (EM_ARCOMPACT, False, False),
}

"""
    Guess the architecture based on special knowledge, like custom signatures or binary format
"""
def guess_architecture_special(binary : bytes) -> ArchitectureName:

    if binary[:2] == b'MZ':

        # Maybe UEFI boot stub ?
        if binary[0x38:0x3C] == b'ARMd':
            return ArchitectureName.aarch64

    return None

"""
    Guess the architecture based on common patterns
"""
def guess_architecture_common(binary : bytes) -> ArchitectureName:

    architecture_to_number_of_prologues :  Dict[ArchitectureName, int] = Counter()

    for architecture, prologue in architecture_to_prologue_regex.items():
        
        architecture_to_number_of_prologues[architecture] = len(findall(prologue, binary,  flags = DOTALL))
    
    best_architecture_guess, number_of_prologues = architecture_to_number_of_prologues.most_common(1)[0]

    return None if number_of_prologues < 100 else best_architecture_guess

"""
    Main architecture guess function
"""
def guess_architecture(binary : bytes) -> ArchitectureName:
        
    begin_time = time()

    architecture_guess = guess_architecture_special(binary)
    if not architecture_guess:
        architecture_guess = guess_architecture_common(binary)

    if not architecture_guess:
        raise ArchitectureGuessError('The architecture could not be guessed successfully')

    logging.info('[+] Guessed architecture: %s successfully in %.2f seconds' % (architecture_guess.name, time() - begin_time))

    return architecture_guess
