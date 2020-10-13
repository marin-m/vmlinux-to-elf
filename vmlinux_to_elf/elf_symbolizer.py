#!/usr/bin/env python3
#-*- encoding: Utf-8 -*-
from re import search, IGNORECASE
from argparse import Namespace
from io import BytesIO
import logging

"""
    The ElfSymbolizer class, defined in this file, gathers information from
    the other modules (such as kallsyms_finder, which extracts the kernel's
    runtime symbol table, or vmlinuz_decompressor, which processes possible
    kernel compressions), in order to generate the output ELF file.
"""

try:
    from kallsyms_finder import KallsymsFinder, KallsymsSymbolType

    from utils.elf import ElfFile, ElfSymtab, ElfRel, Elf32LittleEndianSymbolTableEntry, Elf32BigEndianSymbolTableEntry, Elf64LittleEndianSymbolTableEntry, Elf64BigEndianSymbolTableEntry, SPECIAL_SECTION_INDEX, ST_INFO_TYPE, ST_INFO_BINDING, ElfStrtab, ElfProgbits, ElfNullSection, ElfNoBits, SH_FLAGS

except ImportError:
    from vmlinux_to_elf.kallsyms_finder import KallsymsFinder, KallsymsSymbolType

    from vmlinux_to_elf.utils.elf import ElfFile, ElfSymtab, ElfRel, Elf32LittleEndianSymbolTableEntry, Elf32BigEndianSymbolTableEntry, Elf64LittleEndianSymbolTableEntry, Elf64BigEndianSymbolTableEntry, SPECIAL_SECTION_INDEX, ST_INFO_TYPE, ST_INFO_BINDING, ElfStrtab, ElfProgbits, ElfNullSection, ElfNoBits, SH_FLAGS


class ElfSymbolizer():
    
    def __init__(self, file_contents : bytes, output_file : str,
        elf_machine : int = None, bit_size : int = None,
        base_address : int = None, file_offset : int = None):
        
        if file_contents.startswith(b'\x27\x05\x19\x56'): # uImage header magic (always big-endian)
            
            if file_offset is None:
                file_offset = 64 # uImage header size (image_header_t from u-boot/image.h)
            
            if base_address is None:
                base_address = int.from_bytes(file_contents[4 * 4:4 * 5], 'big')
            
            
        if file_offset:
            file_contents = file_contents[file_offset:]
        
        kallsyms_finder = KallsymsFinder(file_contents, bit_size)
        
        
        if file_contents.startswith(b'\x7fELF'):
            
            kernel = ElfFile.from_bytes(BytesIO(file_contents))
        
        else:
            
            kernel = ElfFile(kallsyms_finder.is_big_endian, kallsyms_finder.is_64_bits)
            
            #  Previsouly the register size was based on the kernel version string:       bool(kallsyms_finder.offset_table_element_size >= 8 or search('itanium|(?:amd|aarch|ia|arm|x86_|\D-)64', kallsyms_finder.version_string, flags = IGNORECASE))
            
            if elf_machine is not None:
                kernel.file_header.e_machine = elf_machine
            else:
                kernel.file_header.e_machine = kallsyms_finder.elf_machine
            
            ET_EXEC = 2
            kernel.file_header.e_type = ET_EXEC
            
            null = ElfNullSection(kernel)
            null.section_name = ''
            
            progbits = ElfProgbits(kernel)
            progbits.section_name = '.kernel'
            progbits.section_header.sh_flags = SH_FLAGS.SHF_ALLOC | SH_FLAGS.SHF_EXECINSTR | SH_FLAGS.SHF_WRITE
            progbits.section_header.sh_size = len(file_contents)
            
            first_symbol_virtual_address = next((symbol.virtual_address for symbol in kallsyms_finder.symbols if symbol.symbol_type == KallsymsSymbolType.TEXT), None)
            
            if kallsyms_finder.has_base_relative:
                first_symbol_virtual_address = min(first_symbol_virtual_address, kallsyms_finder.relative_base_address)
            
            if base_address is not None:
                progbits.section_header.sh_addr = base_address
            elif kallsyms_finder.kernel_text_candidate:
                progbits.section_header.sh_addr = kallsyms_finder.kernel_text_candidate
            else:
                progbits.section_header.sh_addr = first_symbol_virtual_address & 0xfffffffffffff000
            
            progbits.section_contents = file_contents
            
            
            bss = ElfNoBits(kernel)
            bss.section_name = '.bss'
            bss.section_header.sh_flags = SH_FLAGS.SHF_ALLOC | SH_FLAGS.SHF_EXECINSTR | SH_FLAGS.SHF_WRITE
            bss.section_header.sh_size = 0x100000
            bss.section_header.sh_addr = progbits.section_header.sh_addr + len(file_contents)
            
            kernel.sections += [null, progbits, bss]
            

        
        """
            Find the entry point symbol. Based on executing this command
            on the Linux tree source:
            
            for i in $(find -iname 'vmlinux.lds.S' -o -iname 'dyn.lds.S' -o -iname 'vmlinux-std.lds');
                do echo "$i:"$(grep -P '^ENTRY\(' $i);
            done | grep -Po 'ENTRY\((.+?)\)' | sort -u

            You can find the possible symbols that are used as an entry
            point for the kernel, here sorted from the most specific to
            the less specific
        """
        
        POSSIBLE_ENTRY_POINT_SYMBOLS = [
            'kernel_entry', 'microblaze_start', 'parisc_kernel_start',
            'phys_startup_32', 'phys_startup_64', 'phys_start', '_stext_lma',
            'res_service', '_c_int00',
            'startup_32', 'startup_64', 'startup_continue', 'startup',
            '__start', '_start', 'start_kernel',
            'stext', '_stext', '_text'
        ]
        
        entry_point_address : int = None
        
        for symbol_name in POSSIBLE_ENTRY_POINT_SYMBOLS:
            
            symbol = kallsyms_finder.name_to_symbol.get(symbol_name)
            
            if symbol:
                entry_point_address = symbol.virtual_address
                
                break
        
        if entry_point_address is None:
            
            raise ValueError('No entry point symbol found in the kallsyms')
        
        kernel.file_header.e_entry = entry_point_address
    
        # Add symbols
        
        symtab = next((i for i in kernel.sections if i.section_name == '.symtab'), None)
        
        if not symtab:
            symtab = ElfSymtab(kernel)
            symtab.section_name = '.symtab'
            
            strtab = ElfStrtab(kernel)
            strtab.section_name = '.strtab'
            symtab.string_table = strtab
            
            shstrtab = ElfStrtab(kernel)
            shstrtab.section_name = '.shstrtab'
            
            kernel.section_string_table = shstrtab
            kernel.sections += [symtab, strtab, shstrtab]
                
        # symtab.symbol_table = [symtab.symbol_table[0]]
        
        for symbol in kallsyms_finder.symbols:
            
            elf_symbol_class = {
                (False, False): Elf32LittleEndianSymbolTableEntry,
                (True, False): Elf32BigEndianSymbolTableEntry,
                (False, True): Elf64LittleEndianSymbolTableEntry,
                (True, True): Elf64BigEndianSymbolTableEntry,
            }[(kernel.is_big_endian, kernel.is_64_bits)]

            elf_symbol = elf_symbol_class(kernel.is_big_endian, kernel.is_64_bits)
            
            elf_symbol.symbol_name = symbol.name
            elf_symbol.st_value = symbol.virtual_address
            
            if symbol.symbol_type not in (KallsymsSymbolType.TEXT, KallsymsSymbolType.WEAK_SYMBOL_WITH_DEFAULT):
                elf_symbol.st_info_type = ST_INFO_TYPE.STT_OBJECT
            
            else:
                elf_symbol.st_info_type = ST_INFO_TYPE.STT_FUNC
            
            if symbol.symbol_type in (KallsymsSymbolType.WEAK_OBJECT_WITH_DEFAULT, KallsymsSymbolType.WEAK_SYMBOL_WITH_DEFAULT):
                elf_symbol.st_info_binding = ST_INFO_BINDING.STB_WEAK
            
            elif symbol.is_global:
                elf_symbol.st_info_binding = ST_INFO_BINDING.STB_GLOBAL
            
            else:
                elf_symbol.st_info_binding = ST_INFO_BINDING.STB_LOCAL

            if symbol.symbol_type == KallsymsSymbolType.ABSOLUTE:
                elf_symbol.st_shndx = SPECIAL_SECTION_INDEX.SHN_ABS
            
            else:
                elf_symbol.associated_section = next((i for i in kernel.sections
                    if i.section_header.sh_addr <= symbol.virtual_address <= i.section_header.sh_addr + i.section_header.sh_size), None)

            symtab.symbol_table.append(elf_symbol)
        
        # Save the modified ELF
        
        with open(output_file, 'wb') as fd:
            
            kernel.serialize(fd)
        
        logging.info('[+] Successfully wrote the new ELF kernel to %s' % output_file)
    
    




        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
