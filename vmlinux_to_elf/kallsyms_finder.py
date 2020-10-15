#!/usr/bin/env python3
#-*- encoding: Utf-8 -*-

from re import search, findall, IGNORECASE, match
from struct import pack, unpack_from
from typing import List, Dict, Tuple
from argparse import ArgumentParser
from io import BytesIO
from enum import Enum
from sys import argv, stdout
import logging

try:
    from architecture_detecter import guess_architecture, ArchitectureName, architecture_name_to_elf_machine_and_is64bits_and_isbigendian, ArchitectureGuessError
    from vmlinuz_decompressor import obtain_raw_kernel_from_file
    
except ImportError:
    from vmlinux_to_elf.architecture_detecter import guess_architecture, ArchitectureName, architecture_name_to_elf_machine_and_is64bits_and_isbigendian, ArchitectureGuessError
    from vmlinux_to_elf.vmlinuz_decompressor import obtain_raw_kernel_from_file

"""
    This class will take a raw kernel image (.IMG), and return the file
    offsets for all kernel symbols, as well as the kallsyms_* structs and
    base addresses, etc.
    
    It is used as an import by "vmlinuz_extractor.py" and "elf_symbolizer.py".
    
    The kallsyms table's current layout was introduced in August 2004 (since
    kernel 2.6.10), its 2004+ implementation can be found here for parsing:
    https://github.com/torvalds/linux/blob/v2.6.32/kernel/kallsyms.c
    And here for generation:
    https://github.com/torvalds/linux/blob/v2.6.32/scripts/kallsyms.c
    
    ^ This format is fully supported.
    
    A major evolution is that since v4.6 (2016), by default on all architectures
    except IA64, a new label called "kallsyms_relative_base" was added and
    addresses are now offsets relative to this base, rather than relative
    addresses. Also, these offsets are stored as the GNU As ".long" type, which
    is 32-bits on x86_64.
    
    https://github.com/torvalds/linux/commit/2213e9a66bb87d8344a1256b4ef568220d9587fb
    
    ^ This format should be supported.
    
    In v4.20 (2018), more fields were shrunk down independently.
    
    https://github.com/torvalds/linux/commit/80ffbaa5b1bd98e80e3239a3b8cfda2da433009a
    
    ^ This format should be supported.
    
    Its 2002-2004 (versions 2.5.54-2.6.9) implementation code with basic "stem
    compression" can be found here for parsing:
    https://github.com/sarnobat/knoppix/blob/master/kernel/kallsyms.c
    Here for generation:
    https://github.com/sarnobat/knoppix/blob/master/scripts/kallsyms.c
    (patch https://lwn.net/Articles/18837/)
    
    In 2002 (versions 2.5.49-2.5.53) it shortly had a version of this code
    without compression:
    https://kernel.googlesource.com/pub/scm/linux/kernel/git/ralf/linux/+/refs/tags/linux-2.5.49/kernel/kallsyms.c
    https://kernel.googlesource.com/pub/scm/linux/kernel/git/ralf/linux/+/refs/tags/linux-2.5.49/scripts/kallsyms
    
    In earlier implementations (2000-2002), it was part of the modutils package
    and was more primitive (no real compression). Its implementation code can be found
    here for parsing:
    https://github.com/carlobar/uclinux_leon3_UD/blob/master/user/modutils-2.4.26/example/kallsyms.c
    Here for generation:
    https://github.com/carlobar/uclinux_leon3_UD/blob/master/user/modutils-2.4.26/obj/obj_kallsyms.c
    
    Kernels 2.5.39-2.5.48 (2002) also had a transitory parser at "kernel/kallsyms.c", but the generation
    was still in modutils:
    
    https://kernel.googlesource.com/pub/scm/linux/kernel/git/ralf/linux/+/refs/tags/linux-2.5.39/kernel/kallsyms.c
    (patch https://lwn.net/Articles/10796/)

    
"""


# Symbol types are the same as exposed by "man nm"

class KallsymsSymbolType(Enum):
    
    # Seen in actual kernels
    ABSOLUTE = 'A'
    BSS = 'B'
    DATA = 'D'
    RODATA = 'R'
    TEXT = 'T'
    WEAK_OBJECT_WITH_DEFAULT = 'V'
    WEAK_SYMBOL_WITH_DEFAULT = 'W'
    
    # Seen on nm's manpage
    SMALL_DATA = 'G'
    INDIRECT_FUNCTION = 'I'
    DEBUGGING = 'N'
    STACK_UNWIND = 'P'
    COMMON = 'C'
    SMALL_BSS = 'S'
    UNDEFINED = 'U'
    UNIQUE_GLOBAL = 'u'
    WEAK_OBJECT = 'v'
    WEAK_SYMBOL = 'w'
    STABS_DEBUG = '-'
    UNKNOWN = '?'



class KallsymsSymbol:
    
    name : str = None
    
    file_offset : int = None
    virtual_address : int = None
    
    symbol_type : KallsymsSymbolType = None
    is_global : bool = False
    

class KallsymsNotFoundException(ValueError):
    pass

class KallsymsFinder:

    # Structure offsets to find
        
    kallsyms_addresses_or_offsets__offset : int = None
    kallsyms_num_syms__offset : int = None
    
    kallsyms_names__offset : int = None  
    kallsyms_markers__offset : int = None
    
    kallsyms_token_table__offset : int = None
    kallsyms_token_index__offset : int = None

    elf64_rela : List[Tuple[int, int, int]] = None
    kernel_text_candidate : int = None
    
    # Inferred information
    
    is_big_endian : bool = None
    offset_table_element_size : int = None
    
    # Parsed information
    
    num_symbols : int = None
    symbol_names : list = None
    symbol_addresses : list = None
    
    symbols : List[KallsymsSymbol] = None
    name_to_symbol : Dict[str, KallsymsSymbol] = None
    

    """
        Symbols are output in this order:
    
        $ curl -sL https://github.com/torvalds/linux/raw/v2.6.32/scripts/kallsyms.c | grep output_label
        
            output_label("kallsyms_addresses");
            output_label("kallsyms_num_syms");
            output_label("kallsyms_names");
            output_label("kallsyms_markers");
            output_label("kallsyms_token_table");
            output_label("kallsyms_token_index");
            
        We'll find kallsyms_token_table and infer the rest
    """
    
    def __init__(self, kernel_img : bytes, bit_size : int = None):
        
        self.kernel_img = kernel_img
        
        # -
        
        self.find_linux_kernel_version()
        
        if not bit_size:
            self.guess_architecture()
        elif bit_size not in (64, 32):
            exit('[!] Please specify a register bit size of either 32 or 64 ' +
                'bits')
        else:
            self.is_64_bits = (bit_size == 64)

        if self.is_64_bits:
            self.find_elf64_rela()
            self.apply_elf64_rela()
        
        # -
        
        try:
            self.find_kallsyms_token_table()
            self.find_kallsyms_token_index()
            self.uncompressed_kallsyms = False
        
        except KallsymsNotFoundException as first_error: # Maybe an OpenWRT kernel with an uncompressed kallsyms
            
            try:
                self.find_kallsyms_names_uncompressed()
                self.find_kallsyms_markers_uncompressed()
                self.uncompressed_kallsyms =  True
            
            except KallsymsNotFoundException:
                raise first_error
        
        else:
            self.find_kallsyms_markers()
            self.find_kallsyms_names()
        
        self.find_kallsyms_num_syms()
        self.find_kallsyms_addresses_or_symbols()
        
        # -
        
        self.parse_symbol_table()
    
    def find_linux_kernel_version(self):
        
        regex_match = search(b'Linux version (\d+\.[\d.]*\d)[ -~]+', self.kernel_img)
        
        if not regex_match:
            
            raise ValueError('No version string found in this kernel')
        
        self.version_string = regex_match.group(0).decode('ascii')
        self.version_number = regex_match.group(1).decode('ascii')
        
        logging.info('[+] Version string: {0:s}'.format(self.version_string))
        #logging.info('[+] Other related strings containing the version number: {0:s}'.format(findall(b'[ -~]*%s[ -~]*' % regex_match.group(1), self.kernel_img)))
        #logging.info('[+] Architecture string: {0:s}'.format(search(b'mod_unload[ -~]+', self.kernel_img).group(0)))
    
    def guess_architecture(self):
        
        self.architecture : ArchitectureName = guess_architecture(self.kernel_img)
        # self.architecture  =  ArchitectureName.mipsle # DEBUG

        self.elf_machine,  self.is_64_bits,  self.is_big_endian = architecture_name_to_elf_machine_and_is64bits_and_isbigendian[self.architecture]

    def find_elf64_rela(self) -> bool:
        """
            Find relocations table, return True if success, False
            otherwise
        """
        if ArchitectureName.aarch64 != self.architecture:

            # I've tested this only for ARM64
            return False

        rela64_size = 24
        offset = len(self.kernel_img)
        offset -= (offset & 3) # align to pointer size
        R_AARCH64_RELATIVE = 0x403
        elf64_rela = []
        minimal_heuristic_count = 1000
        minimal_kernel_va = 0xFFFFFF8008080000
        maximal_kernel_va = 0xFFFFFFFFFFFFFFFF
        kernel_text_candidate = maximal_kernel_va

        # Relocations table located at 'init' part of kernel image
        # Thus reverse-search is more efficient

        while offset >= rela64_size:
            rela = unpack_from('<QQQ', self.kernel_img, offset - rela64_size)
            r_offset, r_info, r_addend = rela
            if (0 == r_offset) and (0 == r_info) and (0 == r_addend):

                # possible empty entry ?

                if elf64_rela:

                    # just skip empty entries inside relocation table

                    offset -= rela64_size   # move to one rela64 struct backward
                    continue

            if R_AARCH64_RELATIVE != r_info:

                # Relocations must be the same type

                if len(elf64_rela) >= minimal_heuristic_count:
                    break

                # reset current state

                elf64_rela = []
                kernel_text_candidate = maximal_kernel_va
                
                # move to the next candidate
                
                possible_offset = offset - 1

                while possible_offset % 8 != 0: # Find a pointer-aligned r_info entry
                    possible_offset = self.kernel_img.rfind(R_AARCH64_RELATIVE.to_bytes(8, 'little'), 8, possible_offset - rela64_size + 1)
                    if possible_offset == -1:
                        offset = 0
                        break

                if possible_offset != -1:
                    offset = possible_offset - 8

                continue

            elf64_rela.append(rela)
            if (0 == (r_addend & 0xFFF)) and (minimal_kernel_va <= r_addend < kernel_text_candidate):
                kernel_text_candidate = r_addend
            offset -= rela64_size   # move to one rela64 struct backward

        count = len(elf64_rela)
        
        if count < minimal_heuristic_count:
            return False

        self.kernel_text_candidate = kernel_text_candidate
        self.elf64_rela = elf64_rela
        logging.info('[+] Found relocations table at file offset 0x%04x (count=%d)' % (offset, count))
        logging.info('[+] Found kernel text candidate: 0x%08x' % (kernel_text_candidate))
        return True

    def apply_elf64_rela(self) -> bool:
        """
            Apply relocations table, return True if success, False
            otherwise
        """
        if self.elf64_rela is None or self.kernel_text_candidate is None:
            return False

        img = bytearray(self.kernel_img)
        offset_max = len(img) - 8 # size of ptr
        kernel_base = self.kernel_text_candidate

        # There is no guarantee that relocation addresses are monotonous

        count = 0
        for rela in self.elf64_rela:

            r_offset, r_info, r_addend = rela
            offset = (r_offset - kernel_base)

            if offset < 0 or offset >= offset_max:
                logging.warn('WARNING! bad rela offset %08x' % (r_offset))
                continue

            value, = unpack_from('<Q', self.kernel_img, offset)
            if value == r_addend:

                # don't know why, but some relocations already initialized

                continue

            # BUG: Sometimes 'r_addend' has pretty small value, and applied to 0.
            # BUG: Result much smaller that valid kernel address.
            # BUG: Probably 'r_addend' can represent offset from kernel_base. Need further investigation.

            value += r_addend
            value &= (1 << 64) - 1

            img[offset:offset+8] = pack('<Q', value)
            count += 1

        self.kernel_img = bytes(img)
        logging.info('[+] Successfully applied %d relocations.' % count)
        return True
        

    def find_kallsyms_token_table(self):
        
        """
            kallsyms_token_table is an array of 256 variable length null-
            terminated string fragments. Positions which correspond to
            an ASCII character which is used in at least one symbol 
            contain the corresponing character (1), other position contain 
            a string fragment chosen by the compression algorithm (2).
            
            Hence, characters [0-9] and [a-z] are always present at their 
            respective positions, but ":" (which comes after "9") never does.
            
            (1) See "insert_real_symbols_in_table" of "scripts/kallsyms.c"
            (2) See "optimize_result" of "scripts/kallsyms.c"
        """
        
        position = 0
        
        candidates_offsets = [] # offsets at which sequence_to_find was found
        
        sequence_to_find = b''.join(b'%c\0' % i for i in range(ord('0'), ord('9') + 1))
        
        sequences_to_avoid = [
            b':\0',
            b'\0\0',
        ]

        while True:
            
            position = self.kernel_img.find(sequence_to_find, position + 1)
            if position == -1:
                break
            
            for seq in sequences_to_avoid:
                pos = position + len(sequence_to_find)
                if self.kernel_img[pos:pos + len(seq)] == seq:
                    break
            else:
                candidates_offsets.append(position)
        
        if len(candidates_offsets) != 1:
            
            if len(candidates_offsets) == 0:
                raise KallsymsNotFoundException('%d candidates for kallsyms_token_table in kernel image' % len(candidates_offsets))
            else:
                raise ValueError('%d candidates for kallsyms_token_table in kernel image' % len(candidates_offsets))
        
        position = candidates_offsets[0]
        
        # Get back to the beginning of the table
        
        current_index_in_array = ord('0')
        
        position -= 1
        assert position >= 0 and self.kernel_img[position] == 0

        for tokens_backwards in range(current_index_in_array):
                        
            for chars_in_token_backwards in range(50):
                
                position -= 1
                assert position >= 0
                
                # (caveat: we may overlap on "kallsyms_markers" for the
                # last entry, so also check for high-range characters)
                
                if (self.kernel_img[position] == 0 or
                    self.kernel_img[position] > ord('z')):
                    break
                
                if chars_in_token_backwards >= 50 - 1:
                    
                    raise ValueError('This structure is not a kallsyms_token_table')
        
        position += 1
        position += -position % 4
        
        self.kallsyms_token_table__offset = position
        
        logging.info('[+] Found kallsyms_token_table at file offset 0x%08x' % self.kallsyms_token_table__offset)
    
    
    def find_kallsyms_token_index(self):
        
        # Get to the end of the kallsyms_token_table
        
        current_index_in_array = 0
        
        position = self.kallsyms_token_table__offset
        
        all_token_offsets = []
        
        position -= 1

        for tokens_forward in range(256):
                
            position += 1
            
            all_token_offsets.append(position - self.kallsyms_token_table__offset)
                        
            for chars_in_token_forward in range(24):
                
                position += 1
                
                if self.kernel_img[position] == 0:
                    break
                
                if chars_in_token_forward >= 24 - 1:
                    
                    raise ValueError('This structure is not a kallsyms_token_table')
        
        
        # Find kallsyms_token_index through the offset through searching
        # the reconstructed structure, also use this to guess endianness
        
        MAX_ALIGNMENT = 256
        KALLSYMS_TOKEN_INDEX__SIZE = 256 * 2
        
        memory_to_search = bytes(self.kernel_img[position:
            position + KALLSYMS_TOKEN_INDEX__SIZE + MAX_ALIGNMENT])
        
        
        little_endian_offsets = pack('<%dH' % len(all_token_offsets), *all_token_offsets)
        big_endian_offsets = pack('>%dH' % len(all_token_offsets), *all_token_offsets)
        
        found_position_for_le_value = memory_to_search.find(little_endian_offsets)
        found_position_for_be_value = memory_to_search.find(big_endian_offsets)
        
        if found_position_for_le_value == found_position_for_be_value == -1:
            
            raise ValueError('The value of kallsyms_token_index was not found')
        
        elif found_position_for_le_value > found_position_for_be_value:
            
            self.is_big_endian = False
        
            self.kallsyms_token_index__offset = position + found_position_for_le_value
        
        elif found_position_for_be_value > found_position_for_le_value:
            
            self.is_big_endian = True
        
            self.kallsyms_token_index__offset = position + found_position_for_be_value
        
        logging.info('[+] Found kallsyms_token_index at file offset 0x%08x' % self.kallsyms_token_index__offset)
    

    def find_kallsyms_names_uncompressed(self):
        
        """
            OpenWRT versions since 2013 may have an
            uncompressed kallsyms table built-in.
        """

        # Find the length byte-separated symbol names
        
        ksymtab_match = search(b'(?:[\x05-\x23][TWtbBrRAdD][a-z0-9_.]{4,34}){14}', self.kernel_img)
        
        if not ksymtab_match:
            
            raise KallsymsNotFoundException('No embedded symbol table found in this kernel')
        
        self.kallsyms_names__offset = ksymtab_match.start(0)
        
        # Count the number of symbol names
        
        position = self.kallsyms_names__offset
        self.number_of_symbols = 0
        
        self.symbol_names : List[str] = []
        
        while position + 1 < len(self.kernel_img):
            
            if self.kernel_img[position] < 2 or chr(self.kernel_img[position + 1]).lower() not in 'abdrtvwginpcsu-?':
                break
            
            symbol_name_and_type : bytes = self.kernel_img[
                position + 1:
                position + 1 + self.kernel_img[position]
            ]
            
            if not match(b'^[\x21-\x7e]+$', symbol_name_and_type):
                break
                        
            position += 1 + self.kernel_img[position]
            self.number_of_symbols += 1
        
        if self.number_of_symbols < 100:
            
            raise KallsymsNotFoundException('No embedded symbol table found in this kernel')
        
        logging.info('[+] Kernel symbol names found at file offset 0x%08x' % ksymtab_match.start(0))
        
        logging.info('[+] Found %d uncompressed kernel symbols (end at 0x%08x)' % (self.number_of_symbols, position))
        
        self.end_of_kallsyms_names_uncompressed = position

    def find_kallsyms_markers_uncompressed(self):
        
        """
            This is the OpenWRT-specific version of the
            "find_kallsyms_markers" method below. It works
            the same except that is tries to guess the integer
            size forward rather than backard.
        """
        
        position =  self.end_of_kallsyms_names_uncompressed
        position += -position % 4
        
        max_number_of_space_between_two_nulls = 0
        
        # Go just after the first chunk of non-null bytes
        
        while position + 1 < len(self.kernel_img) and self.kernel_img[position + 1] == 0:
            
            position += 1
        
        
        for null_separated_bytes_chunks in range(20):
            
            num_non_null_bytes = 1 # we always start at a non-null byte in this loop
            num_null_bytes = 1 # we will at least encounter one null byte before the end of this loop
            
            while True:
                position += 1
                assert position >= 0
                
                if self.kernel_img[position] == 0:
                    break
                num_non_null_bytes += 1
            
            while True:
                position += 1
                assert position >= 0
                
                if self.kernel_img[position] != 0:
                    break
                num_null_bytes += 1
            
            max_number_of_space_between_two_nulls = max(
                max_number_of_space_between_two_nulls,
                num_non_null_bytes + num_null_bytes)
        
        if max_number_of_space_between_two_nulls % 2 == 1: # There may be a leap to a shorter offset in the latest processed entries
            max_number_of_space_between_two_nulls -= 1
        
        if max_number_of_space_between_two_nulls not in (2, 4, 8):
            
            raise ValueError('Could not guess the architecture register ' +
                'size for kernel')
        

        self.offset_table_element_size = max_number_of_space_between_two_nulls

        # Once the size of a long has been guessed, use it to find
        # the first offset (0)
        
        position =  self.end_of_kallsyms_names_uncompressed
        position += -position % 4

        # Go just at the first non-null byte
        
        while position < len(self.kernel_img) and self.kernel_img[position] == 0:
            
            position += 1
        
        
        likely_is_big_endian = (position % self.offset_table_element_size > 1)
        if self.is_big_endian is None: # Manual architecture specification
            self.is_big_endian = likely_is_big_endian
        
        if position % self.offset_table_element_size == 0:
            position += self.offset_table_element_size
        else:
            position += -position + self.offset_table_element_size
        
        position -= self.offset_table_element_size
        position -= self.offset_table_element_size
        
        position -= position % self.offset_table_element_size
        
        
        self.kallsyms_markers__offset = position
        
        logging.info('[+] Found kallsyms_markers at file offset 0x%08x' % position)
        
    
    def find_kallsyms_markers(self):
        
        """
            kallsyms_markers contains one offset in kallsyms_names for each
            1 in 256 entries of it. Offsets are stored as either ".long"
            (a Gnu AS type that corresponds for example to 4 bytes in
            x86_64) since kernel v4.20, either as the maximum register
            byte of the system (the C "long" type) on older kernels.
            Remember about the size of this field for later.
        """
        
        max_number_of_space_between_two_nulls = 0
        
        position = self.kallsyms_token_table__offset
        
        # Go just before the first chunk of non-null bytes
        
        while position > 0 and self.kernel_img[position - 1] == 0:
            
            position -= 1
        
        
        for null_separated_bytes_chunks in range(20):
            
            num_non_null_bytes = 1 # we always start at a non-null byte in this loop
            num_null_bytes = 1 # we will at least encounter one null byte before the end of this loop
            
            while True:
                position -= 1
                assert position >= 0
                
                if self.kernel_img[position] == 0:
                    break
                num_non_null_bytes += 1
            
            while True:
                position -= 1
                assert position >= 0
                
                if self.kernel_img[position] != 0:
                    break
                num_null_bytes += 1
            
            max_number_of_space_between_two_nulls = max(
                max_number_of_space_between_two_nulls,
                num_non_null_bytes + num_null_bytes)
        
        if max_number_of_space_between_two_nulls % 2 == 1: # There may be a leap to a shorter offset in the latest processed entries
            max_number_of_space_between_two_nulls -= 1
        
        if max_number_of_space_between_two_nulls not in (2, 4, 8):
            
            raise ValueError('Could not guess the architecture register ' +
                'size for kernel')
        

        self.offset_table_element_size = max_number_of_space_between_two_nulls
        
        
        # Once the size of a long has been guessed, use it to find
        # the first offset (0)
        
        position = self.kallsyms_token_table__offset
        
        MAX_ARRAY_SIZE = 3000 * self.offset_table_element_size

        position -= 1
        while position > 0 and self.kernel_img[position] == 0:
            position -= 1
        
        memory_to_search = bytes(self.kernel_img[position - MAX_ARRAY_SIZE:
            position])
        
        needle = memory_to_search.rfind(b'\x00' * self.offset_table_element_size)
        
        if needle == -1:
            
            raise ValueError('Could not find kallsyms_markers')
        
        position = (position - MAX_ARRAY_SIZE) + needle
        
        position -= position % self.offset_table_element_size
        
        
        self.kallsyms_markers__offset = position
        
        logging.info('[+] Found kallsyms_markers at file offset 0x%08x' % position)
    
    def find_kallsyms_names(self):
        
        position = self.kallsyms_markers__offset
        
        
        # Approximate the position of kallsyms_names based on the
        # last entry of "kallsyms_markers" - we'll determine the
        # precise position in the next method
        
        endianness_marker = '>' if self.is_big_endian else '<'
            
        long_size_marker = {2: 'H', 4: 'I', 8: 'Q'}[self.offset_table_element_size]
        
        num_of_kallsyms_numbers_entries = (self.kallsyms_token_table__offset -  self.kallsyms_markers__offset)  // self.offset_table_element_size
        
        kallsyms_markers_entries = unpack_from(endianness_marker + str(num_of_kallsyms_numbers_entries) + long_size_marker, self.kernel_img, self.kallsyms_markers__offset)
        
        last_kallsyms_markers_entry = list(filter(None, kallsyms_markers_entries))[-1]
        
        position -= last_kallsyms_markers_entry
        
        position += -position % self.offset_table_element_size
        
        assert position > 0
        
        
        self.kallsyms_names__offset = position
        
        # Guessing continues in the function below (in order to handle the
        # absence of padding)
        
    def find_kallsyms_num_syms(self):
        
        needle = -1
        
        while needle == -1:
            
            position =  self.kallsyms_names__offset
            
            # Count the number of symbols
            
            num_symbols = 0
            
            symbol_counting_position = position
            
            while True:
            
                symbol_size = self.kernel_img[symbol_counting_position]
                
                if not symbol_size:
                    break
                
                symbol_counting_position += symbol_size + 1
                num_symbols += 1
                
                if not (0 <= symbol_counting_position < self.kallsyms_markers__offset):
                    break
            
            if num_symbols < 256 or symbol_counting_position > self.kallsyms_markers__offset:
                if 0 <= self.kallsyms_names__offset - 4 < self.kallsyms_markers__offset:
                    self.kallsyms_names__offset -= 4
                else:
                    raise ValueError('Could not find kallsyms_names')
                continue
            
            self.num_symbols = num_symbols
            
            # Find the long or PTR (it should be the same size as a kallsyms_marker
            # entry) encoding the number of symbols right before kallsyms_names
            
            endianness_marker = '>' if self.is_big_endian else '<'
            
            long_size_marker = {2: 'H', 4: 'I', 8: 'Q'}[self.offset_table_element_size]
            
            
            MAX_ALIGNMENT = 256
            
            encoded_num_symbols = pack(endianness_marker + long_size_marker, num_symbols)
            
            memory_to_search = bytes(self.kernel_img[self.kallsyms_names__offset - MAX_ALIGNMENT - 20:
                self.kallsyms_names__offset])
            
            needle = memory_to_search.rfind(encoded_num_symbols)
            
            if needle == -1: # There may be no padding between kallsyms_names and kallsyms_num_syms, if the alignment is already correct: in this case: try other offsets for "kallsyms_names"
                if 0 <= self.kallsyms_names__offset - 4 < self.kallsyms_markers__offset:
                    self.kallsyms_names__offset -= 4
                else:
                    raise ValueError('Could not find kallsyms_names')
        
        logging.info('[+] Found kallsyms_names at file offset 0x%08x' % self.kallsyms_names__offset)
        
        position = (self.kallsyms_names__offset - MAX_ALIGNMENT - 20) + needle
        
        
        self.kallsyms_num_syms__offset = position
        
        logging.info('[+] Found kallsyms_num_syms at file offset 0x%08x' % position)
    
    """
        This method defines self.kallsyms_addresses_or_offsets__offset,
        self.has_base_relative, self.has_absolute_percpu, self.relative_base_address (may be None)
        and the "self.kernel_addresses" list (the only one variable that shoud le
        externally used, it contains the decoded addresses for items, calculated
        from offsets relative to the specified base for recent kernels with
        CONFIG_KALLSYMS_BASE_RELATIVE)
    """
    
    def find_kallsyms_addresses_or_symbols(self):
        
        # --- New checks here
        
        kernel_major = int(self.version_number.split('.')[0])
        kernel_minor = int(self.version_number.split('.')[1])
        
        # Is CONFIG_KALLSYMS_BASE_RELATIVE (https://github.com/torvalds/linux/blob/v5.4/init/Kconfig#L1609) likely enabled?
        
        likely_has_base_relative = False
        
        if (kernel_major > 4 or (kernel_major == 4 and kernel_minor >= 6)
            and 'ia64' not in self.version_string.lower()
            and 'itanium' not in self.version_string.lower()):
            
            likely_has_base_relative = True
        
        # Does the system seem to be 64-bits?
        
        # Previously: inference from kernel version string
        # likely_is_64_bits = bool(self.offset_table_element_size >= 8 or search('itanium|(?:amd|aarch|ia|arm|x86_|\D-)64', self.version_string, flags = IGNORECASE))
        
        # Now: inference from ISA prologues signature detection
        likely_is_64_bits = self.is_64_bits
        
        # Is CONFIG_KALLSYMS_ABSOLUTE_PERCPU (https://github.com/torvalds/linux/blob/v5.4/init/Kconfig#L1604) likely enabled?
        
        # ==> We'll guess through looking for negative symbol values
        
        # Try different possibilities heuristically:
        
        for (has_base_relative, can_skip) in (
            [(True, True), (False, False)]
            if likely_has_base_relative else
            [(False, True), (False, False)]
        ):
            
            position = self.kallsyms_num_syms__offset
            
            address_byte_size = 8 if likely_is_64_bits else self.offset_table_element_size
            offset_byte_size = min(4, self.offset_table_element_size) # Size of an assembly ".long"
            
            
            # Go right after the previous address
            
            while True:
                assert position > 0  # >= self.offset_table_element_size # Needed?
                
                previous_word = self.kernel_img[position - address_byte_size:position]
                
                if previous_word != address_byte_size * b'\x00':
                    break
                position -= address_byte_size
            
            if has_base_relative:
                
                self.has_base_relative = True
                
                position -= address_byte_size
                
                # Parse the base_relative value
                
                self.relative_base_address :  int  =  int.from_bytes(self.kernel_img[position:position + address_byte_size], 'big' if self.is_big_endian else 'little')
            
                # Go right after the previous offset
                
                while True:
                    assert position > 0  # >= self.offset_table_element_size # Needed?
                    
                    previous_word = self.kernel_img[position - offset_byte_size:position]
                    
                    if previous_word != offset_byte_size * b'\x00':
                        break
                    position -= offset_byte_size
                
                position -= self.num_symbols * offset_byte_size
                
            else:
                
                self.has_base_relative = False
            
                position -= self.num_symbols * address_byte_size
            
            
            self.kallsyms_addresses_or_offsets__offset = position
            
            # Check the obtained values
            
            endianness_marker = '>' if self.is_big_endian else '<'
            
            if self.has_base_relative:
                long_size_marker = {2: 'h', 4: 'i'}[offset_byte_size] # offsets may be negative, contrary to addresses
            else:
                long_size_marker = {2: 'H', 4: 'I', 8: 'Q'}[address_byte_size]
            
            # Parse symbols addresses
                
            tentative_addresses_or_offsets = list(unpack_from(
                endianness_marker + str(self.num_symbols) + long_size_marker,
                self.kernel_img,
                self.kallsyms_addresses_or_offsets__offset))

            if self.has_base_relative:
                number_of_negative_items = len([offset for offset in tentative_addresses_or_offsets if offset < 0])
                
                logging.info('[i] Negative offsets overall: %g %%' % (number_of_negative_items / len(tentative_addresses_or_offsets) * 100))
            
                if number_of_negative_items / len(tentative_addresses_or_offsets) >= 0.5: # Non-absolute symbols are negative with CONFIG_KALLSYMS_ABSOLUTE_PERCPU
                    self.has_absolute_percpu = True
                    
                    tentative_addresses_or_offsets = [((self.relative_base_address - 1 - offset) if offset < 0 else offset) for offset in tentative_addresses_or_offsets] # https://github.com/torvalds/linux/blob/v5.4/kernel/kallsyms.c#L159
                else:
                    self.has_absolute_percpu = False
                    tentative_addresses_or_offsets = [offset + self.relative_base_address for offset in tentative_addresses_or_offsets]
            
            else:
                self.has_absolute_percpu = False

            number_of_null_items = len([address for address in tentative_addresses_or_offsets if address == 0])
            
            logging.info('[i] Null addresses overall: %g %%' % (number_of_null_items / len(tentative_addresses_or_offsets) * 100))
        
            if number_of_null_items / len(tentative_addresses_or_offsets) >= 0.2: # If there are too much null symbols we have likely tried to parse the wrong integer size
                
                if can_skip:
                    continue
                
            
            logging.info('[+] Found %s at file offset 0x%08x' % ('kallsyms_offsets' if self.has_base_relative else 'kallsyms_addresses', position))
            
            self.kernel_addresses = tentative_addresses_or_offsets
            
            break # DEBUG
        
    def parse_symbol_table(self):
        
        if not self.uncompressed_kallsyms:
            
            # Parse symbol name tokens
            
            tokens = []
            
            position = self.kallsyms_token_table__offset
            
            for num_token in range(256):
                
                token = ''
                
                while self.kernel_img[position]:
                    
                    token += chr(self.kernel_img[position])
                    position += 1
                
                position += 1
                
                tokens.append(token)
        
        else:
            tokens = [chr(i) for i in range(256)]
        
        # Parse symbol names
        
        self.symbol_names = []
        
        position = self.kallsyms_names__offset
        
        for num_symbol in range(self.num_symbols):
        
            symbol_name = ''
            
            length = self.kernel_img[position]
            position += 1
            
            for i in range(length):
                
                symbol_token_index = self.kernel_img[position]
                symbol_token = tokens[symbol_token_index]
                position += 1
            
                symbol_name += symbol_token
        
            self.symbol_names.append(symbol_name)
        
        # Build consistent objects
        
        self.symbols = []
        self.name_to_symbol = {}
        
        for symbol_address, symbol_name in zip(self.kernel_addresses, self.symbol_names):
            
            symbol = KallsymsSymbol()
        
            symbol.name = symbol_name[1:] # Exclude the type letter
            
            symbol.virtual_address = symbol_address
            # symbol.file_offset = 
            
            if symbol_name[0].lower() in 'uvw':
                
                symbol.symbol_type = KallsymsSymbolType(symbol_name[0])
                symbol.is_global = True
            
            else:
                
                symbol.symbol_type = KallsymsSymbolType(symbol_name[0].upper())
                symbol.is_global = symbol_name[0].isupper()
            
        
            self.symbols.append(symbol)
            
            self.name_to_symbol[symbol.name] = symbol
    
    
    def print_symbols_debug(self):
        
        # Print symbol types (debug)
        
        symbol_types = set()
        
        for symbol_name in self.symbol_names:
            
            symbol_types.add(symbol_name[0])
        
        logging.info('Symbol types => %r' % sorted(symbol_types))
        logging.info('')
        
        
        # Print symbols, in a fashion similar to /proc/kallsyms
        
        for symbol_address, symbol_name in zip(self.kernel_addresses, self.symbol_names):
            
            logging.info( "{0:s} {1:s} {2:s}".format(
                '%016x' % symbol_address if self.is_64_bits else '%08x' % symbol_address,
                symbol_name[0], # The symbol type
                symbol_name[1:] # The symbol name itself
            ))
        
        
if __name__ == '__main__':

    logging.basicConfig(stream=stdout, level=logging.INFO, format='%(message)s')

    args = ArgumentParser(description = "Find the kernel's embedded symbol table from a raw " +
        "or stripped ELF kernel file, and print these to the standard output with their " +
        "addresses")
    
    args.add_argument('input_file', help = "Path to the kernel file to extract symbols from")
    args.add_argument('--bit-size', help = 'Force overriding the input kernel ' +
        'bit size, providing 32 or 64 bit (rather than auto-detect)', type = int)
    
    args = args.parse_args()


    with open(args.input_file, 'rb') as kernel_bin:
        
        try:
            kallsyms = KallsymsFinder(obtain_raw_kernel_from_file(kernel_bin.read()), args.bit_size)
        
        except ArchitectureGuessError:
           exit('[!] The architecture of your kernel could not be guessed ' +
                'successfully. Please specify the --bit-size argument manually ' +
                '(use --help for its precise specification).')
        
        kallsyms.print_symbols_debug()
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
