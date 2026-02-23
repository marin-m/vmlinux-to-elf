#!/usr/bin/env python3
# -*- encoding: Utf-8 -*-
from ctypes import (
    BigEndianStructure,
    LittleEndianStructure,
    c_char,
    c_int32,
    c_int64,
    c_uint8,
    c_uint16,
    c_uint32,
    c_uint64,
)
from enum import IntEnum
from io import BytesIO

from vmlinux_to_elf.utils.pretty_print import pretty_print_structure

"""
    This file contains a wrapper for parsing ARM64 PE/EFI boot stub files.

    UEFI is always little-endian, and so is most of this structure:
    https://www.workofard.com/page/2/

    https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/arm64/booting.rst?id=v5.13
    "As of v3.17, all fields are little endian unless stated otherwise."

    But not everything:
    "Prior to v3.17, the endianness of text_offset was not specified.  In
    these cases image_size is zero and text_offset is 0x80000 in the
    endianness of the kernel.  Where image_size is non-zero image_size is
    little-endian and must be respected.  Where image_size is zero,
    text_offset can be assumed to be 0x80000."

    "Bit 0		Kernel endianness.  1 if BE, 0 if LE."
"""


class LinuxARM64EFIStub(LittleEndianStructure):
    # See:
    # - https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/arm64/kernel/head.S?id=v5.13
    # - https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/arm64/kernel/efi-header.S?id=v5.13
    # - section 4 of https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/arch/arm64/booting.rst

    _fields_ = [
        # __HEAD - .L_head - offset 0
        # "code0/code1 are responsible for branching to stext."
        # "when booting through EFI, code0/code1 are initially skipped."
        # "res5 is an offset to the PE header and the PE header has the EFI
        # entry point (efi_stub_entry).  When the stub has done its work, it
        # jumps to code0 to resume the normal boot process."
        (
            'code0',
            c_char * 4,
        ),  # ARM64 code: efi_signature_nop - "MZ@\xFA" - 4D 5A 40 FA
        ('code1', c_uint32),  # ARM64 code: b primary_entry
        ('text_offset', c_uint64),  # Image load offset, effectively 0
        (
            'image_size',
            c_uint64,
        ),  # Effective Image size, _kernel_size_le, 0x02000000 = 32 MB
        # "Prior to v3.17, the endianness of text_offset was not specified.  In
        # these cases image_size is zero and text_offset is 0x80000 in the
        # endianness of the kernel.  Where image_size is non-zero image_size is
        # little-endian and must be respected.  Where image_size is zero,
        # text_offset can be assumed to be 0x80000."
        ('flags', c_uint64),  # _kernel_flags_le
        # The flags field (introduced in v3.17) is a little-endian 64-bit field
        # Bit 0		Kernel endianness.  1 if BE, 0 if LE.
        # Bit 1-2	Kernel Page size.
        # Bit 3		Kernel physical placement
        ('res2', c_uint64),  # reserved
        ('res3', c_uint64),  # reserved
        ('res4', c_uint64),  # reserved
        (
            'magic',
            c_char * 4,
        ),  # Magic number - ARM64_IMAGE_MAGIC - "ARM\x64" - 41 52 4d 64
        (
            'pe_header_offset',
            c_uint32,
        ),  # reserved - Offset to the PE header (0x40)
        # __EFI_PE_HEADER - .Lpe_header_offset - offset 0x40 = decimal 64
        # See: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#signature-image-only
        ('pe_magic', c_char * 4),  # PE_MAGIC - "PE\0\0" - 50 45 00 00
        ('pe_machine', c_uint16)(  # IMAGE_FILE_MACHINE_ARM64 - 0xaa64 - 64 AA
            'pe_section_count', c_uint16
        )(  # NumberOfSections - .Lsection_count - 2
            'pe_date_timestamp', c_uint32
        )(  # TimeDateStamp - fixed 0
            'pe_pointer_to_symbol_table', c_uint32
        )(  # PointerToSymbolTable - fixed 0
            'pe_number_of_symbols', c_uint32
        )(  # NumberOfSymbols - fixed 0
            'pe_size_of_optional_header', c_uint16
        ),  # SizeOfOptionalHeader: here 0xA0
        ('pe_characteristics', c_uint16),  # Characteristics:
        # IMAGE_FILE_DEBUG_STRIPPED (0x0200) |
        # IMAGE_FILE_EXECUTABLE_IMAGE (0x0002) |
        # IMAGE_FILE_LINE_NUMS_STRIPPED (0x0004)
        # .Loptional_header - offset 0x58 = decimal 88
        (
            'pe32plus_magic',
            c_char * 2,
        ),  # PE_OPT_MAGIC_PE32PLUS - PE32+ format - 0B 02
        ('major_linker_version', c_uint8),  # MajorLinkerVersion - 0x02
        ('minor_linker_version', c_uint8),  # MinorLinkerVersion - 0x14
        ('size_of_code', c_uint32),  # SizeOfCode
        ('size_of_initialized_data', c_uint32),  # SizeOfInitializedData
        (
            'size_of_uninitialized_data',
            c_uint32,
        ),  # SizeOfUninitializedData - 0
        ('address_of_entry_point', c_uint32),  # AddressOfEntryPoint
        ('base_of_code', c_uint32),  # BaseOfCode
        ('image_base', c_uint64),  # ImageBase -0
        ('section_alignment', c_uint32),  # SectionAlignment
        ('file_alignment', c_uint32),  # FileAlignment
        ('major_os_version', c_uint16),  # MajorOperatingSystemVersion - 0
        ('minor_os_version', c_uint16),  # MinorOperatingSystemVersion - 0
        ('major_image_version', c_uint16),  # MajorImageVersion
        ('minor_image_version', c_uint16),  # MinorImageVersion
        ('major_subsystem_version', c_uint16),  # MajorSubsystemVersion
        ('minor_subsystem_version', c_uint16),  # MinorSubsystemVersion
        ('win32_version_value', c_uint32),  # Win32VersionValue
        ('size_of_image', c_uint32),  # SizeOfImage
        # "Everything before the kernel image is considered part of the header"
        ('size_of_headers', c_uint32),  # SizeOfHeaders
        ('checksum', c_uint32),  # CheckSum - 0
        (
            'subsystem',
            c_uint16,
        ),  # Subsystem - IMAGE_SUBSYSTEM_EFI_APPLICATION - decimal 10
        ('dll_characteristics', c_uint16),  # DllCharacteristics - 0
        ('size_of_stack_reserve', c_uint64),  # SizeOfStackReserve - 0
        ('size_of_stack_commit', c_uint64),  # SizeOfStackCommit - 0
        ('size_of_heap_reserve', c_uint64),  # SizeOfHeapReserve - 0
        ('size_of_heap_commit', c_uint64),  # SizeOfHeapCommit - 0
        ('loader_flags', c_uint32),  # LoaderFlags - 0
        ('number_of_rva_and_sizes', c_uint32),  # NumberOfRvaAndSizes
        ('export_table', c_uint64),  # ExportTable - 0
        ('import_table', c_uint64),  # ImportTable - 0
        ('resource_table', c_uint64),  # ResourceTable - 0
        ('exception_table', c_uint64),  # ExceptionTable - 0
        ('certification_table', c_uint64),  # CertificationTable - 0
        ('base_relocation_table', c_uint64),  # BaseRelocationTable - 0
    ]
