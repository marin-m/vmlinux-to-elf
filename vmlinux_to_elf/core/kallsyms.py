#!/usr/bin/env python3
# -*- encoding: Utf-8 -*-

import logging
import math
from enum import Enum
from re import match, search
from struct import pack, unpack_from

from vmlinux_to_elf.core.architecture_detecter import (
    ArchitectureDetectionResult,
    ArchitectureDetector,
    ArchitectureGuessError,
    ArchitectureName,
)

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
    ABSOLUTE = "A"
    BSS = "B"
    DATA = "D"
    RODATA = "R"
    TEXT = "T"
    WEAK_OBJECT_WITH_DEFAULT = "V"
    WEAK_SYMBOL_WITH_DEFAULT = "W"

    # Seen on nm's manpage
    SMALL_DATA = "G"
    INDIRECT_FUNCTION = "I"
    DEBUGGING = "N"
    STACK_UNWIND = "P"
    COMMON = "C"
    SMALL_BSS = "S"
    UNDEFINED = "U"
    UNIQUE_GLOBAL = "u"
    WEAK_OBJECT = "v"
    WEAK_SYMBOL = "w"
    STABS_DEBUG = "-"
    UNKNOWN = "?"


class KallsymsSymbol:
    name: str = None

    file_offset: int = None
    virtual_address: int = None

    symbol_type: KallsymsSymbolType = None
    is_global: bool = False


class KallsymsNotFoundException(ValueError):
    pass


class KallsymsFinder:
    # Structure offsets to find

    kallsyms_addresses_or_offsets__offset: int = None
    kallsyms_num_syms__offset: int = None

    kallsyms_names__offset: int = None
    kallsyms_markers__offset: int = None

    kallsyms_token_table__offset: int = None
    kallsyms_token_index__offset: int = None
    kallsyms_token_index_end__offset: int = None

    elf64_rela: list[tuple[int, int, int]] = None
    elf64_rela_start: int = None
    elf64_rela_end_excl: int = None
    kernel_text_candidate: int = None

    # Inferred information

    architecture: ArchitectureName = None

    elf_machine: int = None
    is_64_bits: int = None  # Can be set manually
    is_big_endian: bool = None
    offset_table_element_size: int = None

    # Parsed information

    num_symbols: int = None
    symbol_names: list = None
    symbol_addresses: list = None

    has_relative_base: bool = None
    has_absolute_percpu: bool = None
    relative_base_address: int = None

    kernel_addresses: list[int] = None

    symbols: list[KallsymsSymbol] = None
    name_to_symbol: dict[str, KallsymsSymbol] = None

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

    def __init__(
        self,
        kernel_img: bytes,
        bit_size: int = None,
        override_relative_base: bool = False,
        base_address: int = None,
    ):
        self.override_relative_base = override_relative_base
        self.kernel_img = kernel_img

        # -

        self.find_linux_kernel_version()

        if bit_size:
            if bit_size not in (64, 32):
                exit("[!] Please specify a register bit size of either 32 or 64 bits")
            else:
                self.is_64_bits = bit_size == 64

        self.guess_architecture()

        if self.is_64_bits:
            self.find_elf64_rela(base_address)
            self.apply_elf64_rela()

        # -

        try:
            self.find_kallsyms_token_table()
            self.find_kallsyms_token_index()
            self.uncompressed_kallsyms = False

        except (
            KallsymsNotFoundException
        ) as first_error:  # Maybe an OpenWRT kernel with an uncompressed kallsyms
            try:
                self.find_kallsyms_names_uncompressed()
                self.find_kallsyms_markers_uncompressed()
                self.uncompressed_kallsyms = True

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
        regex_match = search(rb"Linux version (\d+\.[\d.]*\d)[ -~]+", self.kernel_img)

        if not regex_match:
            raise ValueError("No version string found in this kernel")

        self.version_string = regex_match.group(0).decode("ascii")
        self.version_number = regex_match.group(1).decode("ascii")

        logging.info("[+] Version string: {0:s}".format(self.version_string))
        # logging.info('[+] Other related strings containing the version number: {0:s}'.format(findall(b'[ -~]*%s[ -~]*' % regex_match.group(1), self.kernel_img)))
        # logging.info('[+] Architecture string: {0:s}'.format(search(b'mod_unload[ -~]+', self.kernel_img).group(0)))

    def guess_architecture(self):
        try:
            result: ArchitectureDetectionResult = ArchitectureDetector.guess(
                self.kernel_img
            )
        except ArchitectureGuessError:
            if self.is_64_bits is None:
                raise
        else:
            self.architecture: ArchitectureName = result.architecture_name

            self.elf_machine = int(result.elf_machine)
            if self.is_64_bits is None:
                self.is_64_bits = result.is_64_bit
            self.is_big_endian = result.is_big_endian

    def find_elf64_rela(self, base_address: int = None) -> bool:
        """
        Find relocations table, return True if success, False
        otherwise
        """

        # FIX: architecture is not set when guess_architecture() wasn't called
        if (
            not hasattr(self, "architecture")
            or ArchitectureName.aarch64 != self.architecture
        ):
            # I've tested this only for ARM64
            return False

        rela64_size = 24
        self.elf64_rela_start = len(self.kernel_img)
        self.elf64_rela_start -= self.elf64_rela_start & 3  # align to pointer size
        R_AARCH64_RELATIVE = 0x403
        elf64_rela = []
        minimal_heuristic_count = 1000
        minimal_kernel_va = 0xFFFFC00080000000
        maximal_kernel_va = 0xFFFFFFFFFFFFFFFF
        addend_candidate = None

        # Relocations table located at 'init' part of kernel image
        # Thus reverse-search is more efficient

        while self.elf64_rela_start >= rela64_size:
            rela = unpack_from(
                "<QQQ", self.kernel_img, self.elf64_rela_start - rela64_size
            )
            r_offset, r_info, r_addend = rela
            if (0 == r_offset) and (0 == r_info) and (0 == r_addend):
                # possible empty entry ?

                if elf64_rela:
                    # just skip empty entries inside relocation table

                    self.elf64_rela_start -= (
                        rela64_size  # move to one rela64 struct backward
                    )
                    continue

            if R_AARCH64_RELATIVE != r_info:
                # Relocations must be the same type
                # BUG: this is not true in practice, R_AARCH64_GLOB_DAT and maybe some other are between first few R_AARCH64_RELATIVE, which results in missing ~30 relocations

                if len(elf64_rela) >= minimal_heuristic_count:
                    break

                # reset current state

                elf64_rela = []
                kernel_text_candidate = maximal_kernel_va

                # move to the next candidate

                possible_offset = self.elf64_rela_start - 1

                while possible_offset % 8 != 0:  # Find a pointer-aligned r_info entry
                    possible_offset = self.kernel_img.rfind(
                        R_AARCH64_RELATIVE.to_bytes(8, "little"),
                        8,
                        possible_offset - rela64_size + 1,
                    )
                    if possible_offset == -1:
                        self.elf64_rela_start = 0
                        break

                if possible_offset != -1:
                    self.elf64_rela_start = possible_offset - 8

                continue

            elf64_rela.append(rela)
            if (0 == (r_addend & 0xFFF)) and (minimal_kernel_va <= r_addend):
                if addend_candidate is None or r_addend < addend_candidate:
                    addend_candidate = r_addend
            self.elf64_rela_start -= rela64_size  # move to one rela64 struct backward

        count = len(elf64_rela)

        if count < minimal_heuristic_count:
            return False

        self.elf64_rela = elf64_rela
        self.elf64_rela_end_excl = self.elf64_rela_start + count * rela64_size
        logging.info(
            "[+] Found relocations table at file offset 0x%04x (count=%d)"
            % (self.elf64_rela_start, count)
        )

        # Infer a sane base range from relocation offsets so that every
        # relocation offset maps somewhere inside the image.
        min_offset = min(r[0] for r in elf64_rela)
        max_offset = max(r[0] for r in elf64_rela)
        img_len = len(self.kernel_img)
        base_low = max_offset - (img_len - 8)
        base_high = min_offset

        def fits(base: int) -> bool:
            return base is not None and base_low <= base <= base_high

        if base_address is not None:
            self.kernel_text_candidate = base_address
            logging.info(
                "[+] Using supplied base address as kernel text candidate: 0x%08x"
                % (self.kernel_text_candidate)
            )
        elif addend_candidate is not None and fits(addend_candidate):
            self.kernel_text_candidate = addend_candidate
            logging.info(
                "[+] Found kernel text candidate from relocation addends: 0x%08x"
                % (self.kernel_text_candidate)
            )
        elif base_low <= base_high:
            # HACK: kernel might not be aligned to 0x10000?
            ALIGN = 0x10000
            candidate = (base_low + ALIGN - 1) & ~(ALIGN - 1)
            if candidate > base_high:
                candidate = base_high & ~(ALIGN - 1)
            self.kernel_text_candidate = candidate
            logging.info(
                "[+] Guessed kernel base from relocation offsets range 0x%08x-0x%08x -> 0x%08x"
                % (base_low, base_high, self.kernel_text_candidate)
            )
        else:
            self.kernel_text_candidate = (
                addend_candidate if addend_candidate is not None else base_address
            )
            logging.info(
                "[!] Could not derive a consistent base from relocations, keeping candidate 0x%08x"
                % (self.kernel_text_candidate)
            )

        logging.info(
            "[+] Found relocations table at file offset 0x%04x (count=%d)"
            % (self.elf64_rela_start, count)
        )
        return True

    def apply_elf64_rela(self) -> bool:
        """
        Apply relocations table, return True if success, False
        otherwise
        """
        if self.elf64_rela is None or self.kernel_text_candidate is None:
            return False

        img = bytearray(self.kernel_img)
        offset_max = len(img) - 8  # size of ptr
        kernel_base = self.kernel_text_candidate

        # There is no guarantee that relocation addresses are monotonous

        count = 0
        for rela in self.elf64_rela:
            r_offset, r_info, r_addend = rela
            offset = r_offset - kernel_base

            if offset < 0 or offset >= offset_max:
                logging.warning("WARNING! bad rela offset %08x" % (r_offset))

                self.kernel_text_candidate = None
                self.elf64_rela = None
                return False  # Don't try more to apply relocations

            (value,) = unpack_from("<Q", self.kernel_img, offset)
            if value == r_addend:
                # don't know why, but some relocations already initialized

                continue

            # BUG: Sometimes 'r_addend' has pretty small value, and applied to 0.
            # BUG: Result much smaller that valid kernel address.
            # BUG: Probably 'r_addend' can represent offset from kernel_base. Need further investigation.

            value += r_addend
            value &= (1 << 64) - 1

            img[offset : offset + 8] = pack("<Q", value)
            count += 1

        self.kernel_img = bytes(img)
        logging.info("[+] Successfully applied %d relocations." % count)
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

        candidates_offsets = []  # offsets at which sequence_to_find was found
        candidates_offsets_followed_with_ascii = []  # variant with an higher certainty

        sequence_to_find = b"".join(b"%c\0" % i for i in range(ord("0"), ord("9") + 1))

        sequences_to_avoid = [b":\0", b"\0\0", b"\0\1", b"\0\2", b"ASCII\0"]

        while True:
            position = self.kernel_img.find(sequence_to_find, position + 1)
            if position == -1:
                break

            for seq in sequences_to_avoid:
                pos = position + len(sequence_to_find)
                if self.kernel_img[pos : pos + len(seq)] == seq:
                    break
            else:
                candidates_offsets.append(position)

                if self.kernel_img[pos : pos + 1].isalnum():
                    candidates_offsets_followed_with_ascii.append(position)

        if len(candidates_offsets) != 1:
            if len(candidates_offsets_followed_with_ascii) == 1:
                candidates_offsets = candidates_offsets_followed_with_ascii
            elif len(candidates_offsets) == 0:
                raise KallsymsNotFoundException(
                    "%d candidates for kallsyms_token_table in kernel image"
                    % len(candidates_offsets)
                )
            else:
                raise ValueError(
                    "%d candidates for kallsyms_token_table in kernel image"
                    % len(candidates_offsets)
                )

        position = candidates_offsets[0]

        # Get back to the beginning of the table

        current_index_in_array = ord("0")

        position -= 1
        assert position >= 0 and self.kernel_img[position] == 0

        for tokens_backwards in range(current_index_in_array):
            for chars_in_token_backwards in range(50):
                position -= 1
                assert position >= 0

                # (caveat: we may overlap on "kallsyms_markers" for the
                # last entry, so also check for high-range characters)

                if self.kernel_img[position] == 0 or self.kernel_img[position] > ord(
                    "z"
                ):
                    break

                if chars_in_token_backwards >= 50 - 1:
                    raise ValueError("This structure is not a kallsyms_token_table")

        position += 1
        position += -position % 4

        self.kallsyms_token_table__offset = position

        logging.info(
            "[+] Found kallsyms_token_table at file offset 0x%08x"
            % self.kallsyms_token_table__offset
        )

    def find_kallsyms_token_index(self):
        # Get to the end of the kallsyms_token_table

        position = self.kallsyms_token_table__offset

        all_token_offsets = []

        position -= 1

        for tokens_forward in range(256):
            position += 1

            all_token_offsets.append(position - self.kallsyms_token_table__offset)

            for chars_in_token_forward in range(50):
                position += 1

                if self.kernel_img[position] == 0:
                    break

                if chars_in_token_forward >= 50 - 1:
                    raise ValueError("This structure is not a kallsyms_token_table")

        # Find kallsyms_token_index through the offset through searching
        # the reconstructed structure, also use this to guess endianness

        MAX_ALIGNMENT = 256
        KALLSYMS_TOKEN_INDEX__SIZE = 256 * 2

        memory_to_search = bytes(
            self.kernel_img[
                position : position + KALLSYMS_TOKEN_INDEX__SIZE + MAX_ALIGNMENT
            ]
        )

        little_endian_offsets = pack(
            "<%dH" % len(all_token_offsets), *all_token_offsets
        )
        big_endian_offsets = pack(">%dH" % len(all_token_offsets), *all_token_offsets)

        found_position_for_le_value = memory_to_search.find(little_endian_offsets)
        found_position_for_be_value = memory_to_search.find(big_endian_offsets)

        if found_position_for_le_value == found_position_for_be_value == -1:
            raise ValueError("The value of kallsyms_token_index was not found")

        elif found_position_for_le_value > found_position_for_be_value:
            self.is_big_endian = False

            self.kallsyms_token_index__offset = position + found_position_for_le_value

        elif found_position_for_be_value > found_position_for_le_value:
            self.is_big_endian = True

            self.kallsyms_token_index__offset = position + found_position_for_be_value

        self.kallsyms_token_index_end__offset = self.kallsyms_token_index__offset + len(
            little_endian_offsets
        )

        logging.info(
            "[+] Found kallsyms_token_index at file offset 0x%08x"
            % self.kallsyms_token_index__offset
        )

    def find_kallsyms_names_uncompressed(self):
        """
        OpenWRT versions since 2013 may have an
        uncompressed kallsyms table built-in.
        """

        # Find the length byte-separated symbol names

        ksymtab_match = search(
            rb"(?:[\x05-\x23][TWtbBrRAdD][a-z0-9_.]{4,34}){14}", self.kernel_img
        )

        if not ksymtab_match:
            raise KallsymsNotFoundException(
                "No embedded symbol table found in this kernel"
            )

        self.kallsyms_names__offset = ksymtab_match.start(0)

        # Count the number of symbol names

        position = self.kallsyms_names__offset
        self.number_of_symbols = 0

        self.symbol_names: list[str] = []

        while position + 1 < len(self.kernel_img):
            if (
                self.kernel_img[position] < 2
                or chr(self.kernel_img[position + 1]).lower() not in "abdrtvwginpcsu-?"
            ):
                break

            symbol_name_and_type: bytes = self.kernel_img[
                position + 1 : position + 1 + self.kernel_img[position]
            ]

            if not match(rb"^[\x21-\x7e]+$", symbol_name_and_type):
                break

            position += 1 + self.kernel_img[position]
            self.number_of_symbols += 1

        if self.number_of_symbols < 100:
            raise KallsymsNotFoundException(
                "No embedded symbol table found in this kernel"
            )

        logging.info(
            "[+] Kernel symbol names found at file offset 0x%08x"
            % ksymtab_match.start(0)
        )

        logging.info(
            "[+] Found %d uncompressed kernel symbols (end at 0x%08x)"
            % (self.number_of_symbols, position)
        )

        self.end_of_kallsyms_names_uncompressed = position

    def find_kallsyms_markers_uncompressed(self):
        """
        This is the OpenWRT-specific version of the
        "find_kallsyms_markers" method below. It works
        the same except that is tries to guess the integer
        size forward rather than backard.
        """

        position = self.end_of_kallsyms_names_uncompressed
        position += -position % 4

        max_number_of_space_between_two_nulls = 0

        # Go just after the first chunk of non-null bytes

        while (
            position + 1 < len(self.kernel_img) and self.kernel_img[position + 1] == 0
        ):
            position += 1

        for null_separated_bytes_chunks in range(20):
            num_non_null_bytes = 1  # we always start at a non-null byte in this loop
            num_null_bytes = 1  # we will at least encounter one null byte before the end of this loop

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
                num_non_null_bytes + num_null_bytes,
            )

        if (
            max_number_of_space_between_two_nulls % 2 == 1
        ):  # There may be a leap to a shorter offset in the latest processed entries
            max_number_of_space_between_two_nulls -= 1

        if max_number_of_space_between_two_nulls not in (2, 4, 8):
            raise ValueError(
                "Could not guess the architecture register " + "size for kernel"
            )

        self.offset_table_element_size = max_number_of_space_between_two_nulls

        # Once the size of a long has been guessed, use it to find
        # the first offset (0)

        position = self.end_of_kallsyms_names_uncompressed
        position += -position % 4

        # Go just at the first non-null byte

        while position < len(self.kernel_img) and self.kernel_img[position] == 0:
            position += 1

        likely_is_big_endian = position % self.offset_table_element_size > 1
        if self.is_big_endian is None:  # Manual architecture specification
            self.is_big_endian = likely_is_big_endian

        if position % self.offset_table_element_size == 0:
            position += self.offset_table_element_size
        else:
            position += -position + self.offset_table_element_size

        position -= self.offset_table_element_size
        position -= self.offset_table_element_size

        position -= position % self.offset_table_element_size

        self.kallsyms_markers__offset = position

        logging.info("[+] Found kallsyms_markers at file offset 0x%08x" % position)

    def find_kallsyms_markers(self):
        """
        kallsyms_markers contains one offset in kallsyms_names for each
        1 in 256 entries of it. Offsets are stored as either ".long"
        (a Gnu AS type that corresponds for example to 4 bytes in
        x86_64) since kernel v4.20, either as the maximum register
        byte of the system (the C "long" type) on older kernels.
        Remember about the size of this field for later.
        The first index is always 0, it is sorted, and it is aligned.
        """

        # Try possible sizes for the table element (long type)
        for table_element_size in (8, 4, 2):
            position = self.kallsyms_token_table__offset
            endianness_marker = ">" if self.is_big_endian else "<"
            long_size_marker = {2: "H", 4: "I", 8: "Q"}[table_element_size]

            # Search for start of kallsyms_markers given first element is 0 and it is sorted
            for _ in range(32):
                position = self.kernel_img.rfind(
                    b"\x00" * table_element_size, 0, position
                )
                position -= position % table_element_size
                entries = unpack_from(
                    endianness_marker + "4" + long_size_marker,
                    self.kernel_img,
                    position,
                )
                if entries[0] != 0:
                    continue

                for i in range(1, len(entries)):
                    # kallsyms_names entries are at least 2 bytes and at most 0x3FFF bytes long
                    if (
                        entries[i - 1] + 0x200 >= entries[i]
                        or entries[i - 1] + 0x40000 < entries[i]
                    ):
                        break
                else:
                    logging.info(
                        "[+] Found kallsyms_markers at file offset 0x%08x" % position
                    )
                    self.kallsyms_markers__offset = position
                    self.offset_table_element_size = table_element_size
                    return
        raise ValueError("Could not find kallsyms_markers")

    def find_kallsyms_names(self):
        position = self.kallsyms_markers__offset

        # Approximate the position of kallsyms_names based on the
        # last entry of "kallsyms_markers" - we'll determine the
        # precise position in the next method

        endianness_marker = ">" if self.is_big_endian else "<"

        long_size_marker = {2: "H", 4: "I", 8: "Q"}[self.offset_table_element_size]

        # Estimate kallsyms_markers length. Limit to 3000 for kernels with kallsyms_seqs_of_names
        num_of_kallsyms_markers_entries = (
            self.kallsyms_token_table__offset - self.kallsyms_markers__offset
        ) // self.offset_table_element_size

        kallsyms_markers_entries = unpack_from(
            endianness_marker
            + str(min(3000, num_of_kallsyms_markers_entries))
            + long_size_marker,
            self.kernel_img,
            self.kallsyms_markers__offset,
        )

        for i in range(1, len(kallsyms_markers_entries)):
            curr = kallsyms_markers_entries[i]
            last = kallsyms_markers_entries[i - 1]
            if last + 0x200 >= curr or last + 0x40000 < curr:
                kallsyms_markers_entries = kallsyms_markers_entries[:i]
                break

        last_kallsyms_markers_entry = list(filter(None, kallsyms_markers_entries))[-1]

        position -= last_kallsyms_markers_entry

        position += -position % self.offset_table_element_size

        assert position > 0

        self.kallsyms_names__offset = position
        # Guessing continues in the function below (in order to handle the
        # absence of padding)

    def find_kallsyms_num_syms(self):
        needle = -1

        token_table = self.get_token_table()
        possible_symbol_types = [i.value for i in KallsymsSymbolType]

        dp = []

        while needle == -1:
            position = self.kallsyms_names__offset

            # Check whether this looks like the correct symbol
            # table, first depending on the beginning of the
            # first symbol (as this is where an uncertain gap
            # of 4 padding bytes may be present depending on
            # versions or builds), then thorough the whole
            # table. Raise an issue further in the code (in
            # another function) if an exotic kind of symbol is
            # found somewhere else than in the first entry.

            first_token_index_of_first_name = self.kernel_img[position + 1]
            first_token_of_first_name = token_table[first_token_index_of_first_name]

            if (
                not (
                    first_token_of_first_name[0].lower() in "uvw"
                    and first_token_of_first_name[0] in possible_symbol_types
                )
                and first_token_of_first_name[0].upper() not in possible_symbol_types
            ):
                self.kallsyms_names__offset -= 4
                if self.kallsyms_names__offset < 0:
                    raise ValueError("Could not find kallsyms_names")
                continue

            # Each entry in the symbol table starts with a u8 size followed by the contents.
            # The table ends with an entry of size 0, and must lie before kallsyms_markers.
            # This for loop uses a bottom-up DP approach to calculate the numbers of symbols without recalculations.
            # dp[i] is the length of the symbol table given a starting position of "kallsyms_markers - i"
            # If the table position is invalid, i.e. it reaches out of bounds, the length is marked as -1.
            # The loop ends with the number of symbols for the current position in the last entry of dp.

            for i in range(len(dp), self.kallsyms_markers__offset - position + 1):
                curr = self.kernel_img[self.kallsyms_markers__offset - i]
                if curr & 0x80:
                    # "Big" symbol
                    symbol_size = (
                        curr & 0x7F
                        | (self.kernel_img[self.kallsyms_markers__offset - i + 1] << 7)
                    ) + 2
                else:
                    symbol_size = curr + 1
                next_i = i - symbol_size
                if curr == 0:  # Last entry of the symbol table
                    dp.append(0 if i <= 256 else -1)
                elif (
                    next_i < 0 or dp[next_i] == -1
                ):  # If table would exceed kallsyms_markers, mark as invalid
                    dp.append(-1)
                else:
                    dp.append(dp[next_i] + 1)
            num_symbols = dp[-1]

            if num_symbols < 256:
                self.kallsyms_names__offset -= 4
                if self.kallsyms_names__offset < 0:
                    raise ValueError("Could not find kallsyms_names")
                continue

            self.num_symbols = num_symbols

            # Find the long or PTR (it should be the same size as a kallsyms_marker
            # entry) encoding the number of symbols right before kallsyms_names

            endianness_marker = ">" if self.is_big_endian else "<"

            long_size_marker = {2: "H", 4: "I", 8: "Q"}[self.offset_table_element_size]

            MAX_ALIGNMENT = 256

            encoded_num_symbols = pack(
                endianness_marker + long_size_marker, num_symbols
            )

            needle = self.kernel_img.rfind(
                encoded_num_symbols,
                max(0, self.kallsyms_names__offset - MAX_ALIGNMENT - 20),
                self.kallsyms_names__offset,
            )

            if (
                needle == -1
            ):  # There may be no padding between kallsyms_names and kallsyms_num_syms, if the alignment is already correct: in this case: try other offsets for "kallsyms_names"
                self.kallsyms_names__offset -= 4
                if self.kallsyms_names__offset < 0:
                    raise ValueError("Could not find kallsyms_names")

        logging.info(
            "[+] Found kallsyms_names at file offset 0x%08x (%d symbols)"
            % (self.kallsyms_names__offset, self.num_symbols)
        )

        position = needle

        self.kallsyms_num_syms__offset = position

        logging.info("[+] Found kallsyms_num_syms at file offset 0x%08x" % position)

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

        kernel_major = int(self.version_number.split(".")[0])
        kernel_minor = int(self.version_number.split(".")[1])

        # Is CONFIG_KALLSYMS_BASE_RELATIVE (https://github.com/torvalds/linux/blob/v5.4/init/Kconfig#L1609) likely enabled?

        likely_has_base_relative = False

        if (
            kernel_major > 4
            or (kernel_major == 4 and kernel_minor >= 6)
            and "ia64" not in self.version_string.lower()
            and "itanium" not in self.version_string.lower()
        ):
            likely_has_base_relative = True

        # Does the system seem to be 64-bits?

        # Previously: inference from kernel version string
        # likely_is_64_bits = bool(self.offset_table_element_size >= 8 or search('itanium|(?:amd|aarch|ia|arm|x86_|\D-)64', self.version_string, flags = IGNORECASE))

        # Now: inference from ISA prologues signature detection
        likely_is_64_bits = self.is_64_bits

        # Is CONFIG_KALLSYMS_ABSOLUTE_PERCPU (https://github.com/torvalds/linux/blob/v5.4/init/Kconfig#L1604) likely enabled?

        # ==> We'll guess through looking for negative symbol values

        # Try different possibilities heuristically:

        heuristic_search_parameters = (
            [(True, True), (False, False)]
            if likely_has_base_relative
            else [(False, True), (False, False)]
        )
        if self.override_relative_base:
            heuristic_search_parameters = [(False, False)]
        for has_base_relative, can_skip in heuristic_search_parameters:
            address_byte_size = (
                8 if likely_is_64_bits else self.offset_table_element_size
            )
            offset_byte_size = min(
                4, self.offset_table_element_size
            )  # Size of an assembly ".long"

            if kernel_major > 6 or (kernel_major == 6 and kernel_minor >= 4):
                # Linux 6.4 or later place (kallsyms_addresses)/(kallsyms_offsets+kallsyms_relative_base) after kallsyms_token_index.

                # The align_size is defined at (https://github.com/torvalds/linux/blob/v6.4/scripts/kallsyms.c#L390).
                align_size = 8 if likely_is_64_bits else 4

                position = self.kallsyms_token_index_end__offset
                position += -position % align_size

                if has_base_relative:
                    position += self.num_symbols * offset_byte_size
                    position += -position % align_size
                    position += address_byte_size

                else:
                    position += self.num_symbols * address_byte_size

            else:
                position = self.kallsyms_num_syms__offset

            # Now, position should point to some address immediately following the kallsyms_addresses or kallsyms_relative_base
            # Go right after the previous address. And we may skip some alignments.

            while True:
                assert position > 0  # >= self.offset_table_element_size # Needed?

                previous_word = self.kernel_img[position - address_byte_size : position]

                if previous_word != address_byte_size * b"\x00":
                    break
                position -= address_byte_size

            if has_base_relative:
                self.has_base_relative = True

                position -= address_byte_size

                # Parse the base_relative value

                self.relative_base_address: int = int.from_bytes(
                    self.kernel_img[position : position + address_byte_size],
                    "big" if self.is_big_endian else "little",
                )

                # Go right after the previous offset

                while True:
                    assert position > 0  # >= self.offset_table_element_size # Needed?

                    previous_word = self.kernel_img[
                        position - offset_byte_size : position
                    ]

                    if previous_word != offset_byte_size * b"\x00":
                        break
                    position -= offset_byte_size

                position -= self.num_symbols * offset_byte_size

            else:
                self.has_base_relative = False

                position -= self.num_symbols * address_byte_size

            self.kallsyms_addresses_or_offsets__offset = position

            # Check the obtained values

            endianness_marker = ">" if self.is_big_endian else "<"

            if self.has_base_relative:
                long_size_marker = {2: "h", 4: "i"}[
                    offset_byte_size
                ]  # Offsets may be negative, contrary to addresses
            else:
                long_size_marker = {2: "H", 4: "I", 8: "Q"}[address_byte_size]

            # Parse symbols addresses

            tentative_addresses_or_offsets = list(
                unpack_from(
                    endianness_marker + str(self.num_symbols) + long_size_marker,
                    self.kernel_img,
                    self.kallsyms_addresses_or_offsets__offset,
                )
            )

            if self.has_base_relative:
                number_of_negative_items = len(
                    [offset for offset in tentative_addresses_or_offsets if offset < 0]
                )

                # Many kernels put their addresses in the upper half of the
                # virtual address space. This means that many of the addresses
                # will look like negative numbers. On the other hand (?), there
                # should be the same zeroes in the high part of the address.

                # A true negative address will probably have the top 3 nibbles
                # or so as in 0xfff00000.  Let's check this as well.

                BITS = 64 if self.is_64_bits else 32
                NEGATIVE_HEURISTIC_MASK = 0xFFF << (
                    BITS - 12
                )  # Mask for the top 3 nibbles
                ABSOLUTE_HEURISTIC_MASK = 0x3F << (
                    BITS - 8
                )  # Mask for zeros in the top byte

                heuristically_negative = len(
                    [
                        offset
                        for offset in tentative_addresses_or_offsets
                        if (offset & NEGATIVE_HEURISTIC_MASK) == NEGATIVE_HEURISTIC_MASK
                    ]
                )
                heuristically_absolute = len(
                    [
                        offset
                        for offset in tentative_addresses_or_offsets
                        if (offset & ABSOLUTE_HEURISTIC_MASK) == 0
                    ]
                )

                heuristic_negative_percent = heuristically_negative / len(
                    tentative_addresses_or_offsets
                )
                heuristic_absolute_percent = heuristically_absolute / len(
                    tentative_addresses_or_offsets
                )

                if heuristic_negative_percent < 0.5:
                    logging.warning(
                        f"[!] WARNING: Less than half ({math.trunc(heuristic_negative_percent * 100)}%) of offsets are negative"
                    )
                    logging.warning(
                        "             You may want to re-run this utility, overriding the relative base"
                    )

                if heuristic_absolute_percent > 0.5:
                    logging.warning(
                        f"[!] WARNING: More than half ({math.trunc(heuristic_absolute_percent * 100)}%) of offsets look like absolute addresses"
                    )
                    logging.warning(
                        "[!]          You may want to re-run this utility, overriding the relative base"
                    )

                if heuristic_absolute_percent > 0.5 or heuristic_negative_percent < 0.5:
                    logging.info(
                        "[i] Note: sometimes there is junk at the beginning of the kernel, and the load address is not the guessed"
                    )
                    logging.info(
                        "          base address. You may need to play around with different load addresses to get everything"
                    )
                    logging.info(
                        "          to line up. There may be some decent tables in the kernel with known patterns that could be"
                    )
                    logging.info(
                        "          used to line things up heuristically, but this has not been explored this yet."
                    )

                logging.info(
                    "[i] Negative offsets overall: %g %%"
                    % (
                        number_of_negative_items
                        / len(tentative_addresses_or_offsets)
                        * 100
                    )
                )

                if (
                    number_of_negative_items / len(tentative_addresses_or_offsets)
                    >= 0.5
                ):  # Non-absolute symbols are negative with CONFIG_KALLSYMS_ABSOLUTE_PERCPU
                    self.has_absolute_percpu = True

                    tentative_addresses_or_offsets = [
                        (
                            (self.relative_base_address - 1 - offset)
                            if offset < 0
                            else offset
                        )
                        for offset in tentative_addresses_or_offsets
                    ]  # https://github.com/torvalds/linux/blob/v5.4/kernel/kallsyms.c#L159
                else:
                    self.has_absolute_percpu = False

                    tentative_addresses_or_offsets = [
                        offset + self.relative_base_address
                        for offset in tentative_addresses_or_offsets
                    ]

            else:
                self.has_absolute_percpu = False

            number_of_null_items = len(
                [address for address in tentative_addresses_or_offsets if address == 0]
            )

            logging.info(
                "[i] Null addresses overall: %g %%"
                % (number_of_null_items / len(tentative_addresses_or_offsets) * 100)
            )

            if (
                number_of_null_items / len(tentative_addresses_or_offsets) >= 0.2
            ):  # If there are too much null symbols we have likely tried to parse the wrong integer size
                if can_skip:
                    continue

            logging.info(
                "[+] Found %s at file offset 0x%08x"
                % (
                    "kallsyms_offsets"
                    if self.has_base_relative
                    else "kallsyms_addresses",
                    position,
                )
            )

            self.kernel_addresses = tentative_addresses_or_offsets

            break

    def get_token_table(self) -> list:
        if not self.uncompressed_kallsyms:
            # Parse symbol name tokens

            tokens = []

            position = self.kallsyms_token_table__offset

            for num_token in range(256):
                token = ""

                while self.kernel_img[position]:
                    token += chr(self.kernel_img[position])
                    position += 1

                position += 1

                tokens.append(token)

        else:
            tokens = [chr(i) for i in range(256)]

        return tokens

    def parse_symbol_table(self):
        tokens = self.get_token_table()

        # Parse symbol names

        self.symbol_names = []

        position = self.kallsyms_names__offset

        for num_symbol in range(self.num_symbols):
            symbol_name = ""

            length = self.kernel_img[position]
            position += 1
            if length & 0x80:
                length = length & 0x7F | (self.kernel_img[position] << 7)
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

        for symbol_address, symbol_name in zip(
            self.kernel_addresses, self.symbol_names
        ):
            symbol = KallsymsSymbol()

            symbol.name = symbol_name[1:]  # Exclude the type letter

            symbol.virtual_address = symbol_address

            if symbol_name[0].lower() in "uvw":
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

        logging.info("Symbol types => %r" % sorted(symbol_types))
        logging.info("")

        # Print symbols, in a fashion similar to /proc/kallsyms

        for symbol_address, symbol_name in zip(
            self.kernel_addresses, self.symbol_names
        ):
            logging.info(
                "{0:s} {1:s} {2:s}".format(
                    "%016x" % symbol_address
                    if self.is_64_bits
                    else "%08x" % symbol_address,
                    symbol_name[0],  # The symbol type
                    symbol_name[1:],  # The symbol name itself
                )
            )
