#!/usr/bin/env python3
#-*- encoding: Utf-8 -*-
from ctypes import BigEndianStructure, LittleEndianStructure
from ctypes import c_uint8, c_uint16, c_int32, c_uint32, c_int64, c_uint64, c_char
from io import SEEK_END, BytesIO
from enum import Enum, IntEnum
from typing import List, Dict

from sys import path
from os.path import dirname, realpath

path.append(realpath(dirname(__file__)))

from pretty_print import pretty_print_structure

"""
    This file contains a wrapper for parsing and writing ELF files.
    
    o o o o o o o o o o o o o o o o o o o o o o o o o o o o o o o o o o o o o o
    o                                                                         o 
    o The ELF specification is here => https://uclibc.org/docs/elf-64-gen.pdf o
    o                                                                         o
    o ftp://www.linux-mips.org/pub/linux/mips/doc/ABI/elf64-2.4.pdf           o
    o                                                                         o
    o o o o o o o o o o o o o o o o o o o o o o o o o o o o o o o o o o o o o o
    
    Each exposed object may have the following methods, which are called in
        this order when all present:
    
    - from_bytes (classmethod, taking at least a BytesIO): return an instance of
        a subclass of the concerned object while automatically inferring parameters
        such as endianness, bit size or section type
        
    
    - __init__ (taking two booleans): initialize the structure with the knowledge
        of whether the structure should be 64-bit or 32-bit, and whether it should
        be big- or little-endian
    
    - unserialize (taking a BytesIO): unserialize the structure at the current offset
    - _unserialize_contents (taking a BytesIO): unserialize the contents of a section
        (if the concerned object is a section) at the current offset, while unserialize()
        will unserialize the section header
    - post_unserialize (taking no arguments): called once all sections have been unserialized,
        complete fields of the concerned object based on the contents of other sections
        (interlink a relocation entry with symbol table entry, a symbol table entry with
        string table entry...)
    
    - pre_serialize (taking no arguments): counterpart of post_unserialize, updating the
        internal state of objects holding string tables from other sections
    - serialize (taking a BytesIO): serialize the structure at the current offset
    - _serialize_contents (taking a BytesIO): serialize the contents of a section
        (if the concerned object is a section), while serialize() will serialize
        the section header
    
"""



Elf32_Addr = c_uint32
Elf32_Half = c_uint16
Elf32_Off = c_uint32
Elf32_Sword = c_int32
Elf32_Word = c_uint32

Elf64_Addr = c_uint64
Elf64_Half = c_uint16
Elf64_Off = c_uint64
Elf64_Sword = c_int32
Elf64_Sxword = c_int64
Elf64_Word = c_uint32
Elf64_Lword = c_uint64
Elf64_Xword = c_uint64



class VariableEndiannessAndWordsizeStructure:
    
    def __new__(cls, is_big_endian = False, is_64_bits = False):
        
        actual_class = type(
            cls.__name__,
            
            (
                BigEndianStructure
                if is_big_endian
                else LittleEndianStructure,
                VariableEndiannessAndWordsizeStructure,
            ),
            
            {
                **{name: getattr(cls, name) for name in dir(cls) if '__' not in name or name == '__init__'},
                
                'is_big_endian': is_big_endian,
                'is_64_bits': is_64_bits,
            
                '_pack_': True,
                '_fields_': [
                    (
                        field[0], field[1] if is_64_bits else {
                            c_int64: c_int32,
                            c_uint64: c_uint32
                        }.get(field[1], field[1]), field[2] if len(field) > 2 else None
                    )[:3 if len(field) > 2 else 2]
                    
                    for field
                    in cls._fields_
                ]
            }
        )
        
        return actual_class()
    
    def unserialize(self, data : BytesIO):
        
        data.readinto(self)
        
    
    def serialize(self, data : BytesIO):
        
        data.write(self)
    
    
    def pretty_print(self):
        
      pretty_print_structure(self)  
        


class ElfFile:
    
    def __init__(self, is_big_endian = False, is_64_bits = False):

        self.is_big_endian = is_big_endian
        self.is_64_bits = is_64_bits
        
        # Exposed to the user
        
        self.sections : List[ElfSection] = []
        
        self.section_string_table : ElfStrtab = None
        
        self.file_header = ElfFileHeader(is_big_endian, is_64_bits)
        
        # Not exposed to the user (inferred from sections)
        
        self.segments : List[Elf32ProgramHeaderEntry] = []
    
    @classmethod
    def from_bytes(cls, data : BytesIO):
    
        file_header = data.read(E_IDENT_INDEXES.EI_NIDENT)
        
        is_64_bits = {
            EI_CLASS.ELFCLASS32: False,
            EI_CLASS.ELFCLASS64: True
        }[file_header[E_IDENT_INDEXES.EI_CLASS]]
        
        is_big_endian = {
            EI_DATA.ELFDATA2LSB: False,
            EI_DATA.ELFDATA2MSB: True
        }[file_header[E_IDENT_INDEXES.EI_DATA]]

        obj = cls(is_big_endian, is_64_bits)
        
        data.seek(0)
        obj.unserialize(data)
        
        return obj
    
    def unserialize(self, data : BytesIO):
        
        self.file_header.unserialize(data)
        
        # Parse sections and data
        
        for num_section in range(self.file_header.e_shnum):
        
            data.seek(self.file_header.e_shoff + self.file_header.e_shentsize * num_section)
            
            self.sections.append(ElfSection.from_bytes(data, self))
        
        # Name sections and link relocations (now that string and symbol tables are parsed)
        
        for section in self.sections:
            
            section.post_unserialize()
        
        
        # Remember about the string symbol table section
        
        self.section_string_table = self.sections[self.file_header.e_shstrndx]
            
        
        # Parse the segment headers
        
        for num_segment in range(self.file_header.e_phnum):
        
            data.seek(self.file_header.e_phoff + self.file_header.e_phentsize * num_segment)
            
            segment_class = Elf32ProgramHeaderEntry if not self.is_64_bits else Elf64ProgramHeaderEntry
            
            segment = segment_class(self.is_big_endian, self.is_64_bits)
            
            segment.unserialize(data)
            
            self.segments.append(segment)
    
    
    def serialize(self, data : BytesIO):
        
        # Filter out .gnu.version not to confuse readelf for now TODO
        self.sections = list(filter(lambda section: '.gnu.version' not in section.section_name, self.sections))
            
            
        self.file_header.e_ehsize = memoryview(self.file_header).nbytes

        self.file_header.e_shstrndx = self.sections.index(self.section_string_table)
        
        self.file_header.e_shoff = self.file_header.e_ehsize
        
        self.file_header.e_shnum = len(self.sections)
        
        self.file_header.e_shentsize = memoryview(self.sections[0].section_header).nbytes
        
        # Update the string tables

        for section in self.sections:
            
            if isinstance(section, ElfStrtab):
                
                section.raw_string_table = b''
                
                section.add_string_and_return_offset('')
        
        for section in self.sections:
            
            section.pre_serialize()
        
        # Write sections and data
        
        for num_section, section in enumerate(self.sections):
            
            data.seek(self.file_header.e_shoff + self.file_header.e_shentsize * num_section)
            
            section.serialize(data)
        
            
        
        # Calculate the address of segments
        
        section_type_to_segment_type = {
            SH_TYPE.SHT_DYNAMIC: P_TYPE.PT_DYNAMIC,
            SH_TYPE.SHT_NOTE: P_TYPE.PT_NOTE
        }
        
        self.segments = []
        
        for section in self.sections:
            
            if section.section_header.sh_flags & SH_FLAGS.SHF_ALLOC:
                
                segment_class = Elf32ProgramHeaderEntry if not self.is_64_bits else Elf64ProgramHeaderEntry
                
                segment = segment_class(self.is_big_endian, self.is_64_bits)
                
                segment.p_type = section_type_to_segment_type.get(section.section_header.sh_type, P_TYPE.PT_LOAD)
                
                segment.p_flags = P_FLAGS.PF_R | P_FLAGS.PF_X | P_FLAGS.PF_W
                if section.section_header.sh_flags & SH_FLAGS.SHF_EXECINSTR:
                    segment.p_flags |= P_FLAGS.PF_X
                if section.section_header.sh_flags & SH_FLAGS.SHF_WRITE:
                    segment.p_flags |= P_FLAGS.PF_W
                
                segment.p_vaddr = section.section_header.sh_addr
                segment.p_paddr = section.section_header.sh_addr
                segment.p_memsz = section.section_header.sh_size
                segment.p_offset = section.section_header.sh_offset
                segment.p_filesz = section.section_header.sh_size if not isinstance(section, ElfNoBits) else 0
                
                self.segments.append(segment)
                
        if not self.segments:
            
            raise ValueError('This ELF object does not have a section with SH_ALLOC flag')
        
        
        
        # Write the segment headers
        
        data.seek(0, SEEK_END)
        
        
        
        
        
        
        self.file_header.e_phoff = data.tell()
        
        self.file_header.e_phnum = len(self.segments)
        
        self.file_header.e_phentsize = memoryview(self.segments[0]).nbytes
        
        for num_segment, segment in enumerate(self.segments):
        
            data.seek(self.file_header.e_phoff + self.file_header.e_phentsize * num_segment)
            
            segment.serialize(data)
        
        
        
        
        # Write the program headers
        
        data.seek(0)
        
        self.file_header.serialize(data)
        
        
        
        """
        self._program_header.unserialize(data)
        """
    
    """
        When writing sections, make sure to 
    """



# class ElfSectionTable


class SH_TYPE(IntEnum):
    
    SHT_NULL = 0 # Inactive section.
    SHT_PROGBITS = 1 # Information defined by the program
    SHT_SYMTAB = 2 # Symbol table (one per object file)
    SHT_STRTAB = 3 # String table (multiple sections OK)
    SHT_RELA = 4 # Relocation with explicit addends
    SHT_HASH = 5 # Symbol hash table (one per object)
    SHT_DYNAMIC = 6 # Dynamic linking information
    SHT_NOTE = 7 # Vendor-specific file information
    SHT_NOBITS = 8 # Section contains no bits in object file
    SHT_REL = 9 # Relocation without explicit addends
    SHT_SHLIB = 10 # Reserved — non-conforming
    SHT_DYNSYM = 11 # Dynamic linking symbol table (one)
    
    SHT_INIT_ARRAY = 14 # Array of constructors
    SHT_FINI_ARRAY = 15 # Array of destructors
    SHT_PREINIT_ARRAY = 16 # Array of pre-constructors
    SHT_GROUP = 17 # Section group
    SHT_SYMTAB_SHNDX = 18 # Extended section indeces
    SHT_NUM = 19 # Number of defined types.
    
    
    SHT_GNU_ATTRIBUTES = 0x6ffffff5
    SHT_GNU_HASH = 0x6ffffff6
    SHT_GNU_LIBLIST = 0x6ffffff7
    SHT_GNU_VERDEF = 0x6ffffffd
    SHT_GNU_VERNEED = 0x6ffffffe
    SHT_GNU_VERSYM = 0x6fffffff
    SHT_MIPS_REGINFO = 0x70000006
    SHT_MIPS_ABIFLAGS = 0x7000002a


class SH_FLAGS(IntEnum):
    
    SHF_WRITE = 0x1 # Section writable during execution
    SHF_ALLOC = 0x2 # Section occupies memory
    SHF_EXECINSTR = 0x4 # Section contains executable instruc-tions





class ElfSectionHeader(VariableEndiannessAndWordsizeStructure):
    
    _fields_ = [
    
          ('sh_name', Elf64_Word), # Section name, index in string table
          ('sh_type', Elf64_Word), # Type of section
          ('sh_flags', Elf64_Xword), # Miscellaneous section attributes
          ('sh_addr', Elf64_Addr), # Section virtual addr at execution
          ('sh_offset', Elf64_Off), # Section file offset
          ('sh_size', Elf64_Xword), # Size of section in bytes
          ('sh_link', Elf64_Word), # Index of another section -> REL(A)|HASH->SYMTAB, SYMTAB->STRTAB, DYNAMIC|DYMSYM->DYNSTR
          ('sh_info', Elf64_Word), # Additional section information
          ('sh_addralign', Elf64_Xword), # Section alignment
          ('sh_entsize', Elf64_Xword), # Entry size if section holds table
    ]
    
    # The library will set sh_name and sh_offset when serializing, as well
    # as sh_size except if the section is a NOBITS

        
class ElfSection:
    
    section_name : str = None # will be written to section_string_table when serializing
    
    section_table : list = None # reference to the ElfFile.sections list
    elf_file : ElfFile = None
    
    section_header : ElfSectionHeader = None
    section_contents : bytes = None
    
    
    def __init__(self, elf_file : ElfFile):
        
        self.elf_file = elf_file
        
        self.is_big_endian = elf_file.is_big_endian
        self.is_64_bits = elf_file.is_64_bits

        self.section_header = ElfSectionHeader(self.is_big_endian, self.is_64_bits)
        
        if self.__class__ in SECTION_CLASS_TO_TYPE:
            
            self.section_header.sh_type = SECTION_CLASS_TO_TYPE[self.__class__]
    
    @classmethod
    def from_bytes(cls, data : BytesIO, elf_file : ElfFile):
    
        section_header_offset = data.tell()
        
        # Guess the correct type for the class to create
        # based on the section header
    
        impersonal_section = cls(elf_file)
        impersonal_section.unserialize(data)
        
        section_class = SECTION_TYPE_TO_CLASS.get(
            SH_TYPE(impersonal_section.section_header.sh_type), 
            ElfSection
        )
        
        data.seek(section_header_offset)
        
        obj = section_class(elf_file)
        obj.unserialize(data)
        
        return obj
    
    def unserialize(self, data : BytesIO):
        
        """
            Consider that:
            a) We are at the position of the section header corresponding
               to the current section
        """
        
        self.section_header.unserialize(data)
        
        data.seek(self.section_header.sh_offset)
        
        self._unserialize_contents(data)
    
    def _unserialize_contents(self, data : BytesIO):
        
        self.section_contents = data.read(self.section_header.sh_size)
            
    
    def post_unserialize(self):
        
        # Name sections (now that .shstrndx is parsed)
        
        section_string_table = self.elf_file.sections[self.elf_file.file_header.e_shstrndx]
        
        self.section_name = section_string_table.return_string_from_offset(self.section_header.sh_name)
    
    # -
    
    def pre_serialize(self):
        
        # Write our entry in .shstrtab
        
        section_string_table = self.elf_file.sections[self.elf_file.file_header.e_shstrndx]
        
        self.section_header.sh_name = section_string_table.add_string_and_return_offset(self.section_name)
    
    def serialize(self, data : BytesIO):
        
        """
            Consider that:
            a) Sections are serialized in order
            b) The file is laid out like this: [ File header | Section headers | Section contents | Segment headers ]
            c) We are located at our section header's offset when called
        """
        
        section_header_offset = data.tell()
        
        # a) Calculate where the contents will start
        
        start_of_contents = self.elf_file.file_header.e_shoff
        start_of_contents += self.elf_file.file_header.e_shentsize * self.elf_file.file_header.e_shnum
        
        data.seek(0, SEEK_END)
        start_of_contents = max(data.tell(), start_of_contents)
        
        if self.section_header.sh_addralign:
            start_of_contents += -start_of_contents % self.section_header.sh_addralign
        
        # b) Write our section contents
        
        data.seek(start_of_contents)
        
        self._serialize_contents(data)
        
        end_of_contents = data.tell()
        
        # c) Write the section header
        
        data.seek(section_header_offset)
        
        self.section_header.sh_offset = start_of_contents
        
        if not isinstance(self, ElfNoBits):
            self.section_header.sh_size = end_of_contents - start_of_contents
        
        self.section_header.serialize(data)
    
    def _serialize_contents(self, data : BytesIO):
        
        data.write(self.section_contents)

        



class ElfNullSection(ElfSection):
    
    def _unserialize_contents(self, data : BytesIO):
        
        pass
    
    def _serialize_contents(self, data : BytesIO):
        
        pass
    
    
class ElfProgbits(ElfSection):
    
    # virtual adress stored in self.section_header.sh_addr

    # Only PROGBITS and NOBITS will have their virtual address specified
    # in their ElfSection structure. For sections like INTERP or DYNAMIC
    # which also have a segment, the serialization code will choose an
    # arbitrary address located right after.
    
    def unserialize(self, data : BytesIO):
        
        super().unserialize(data)
            
    def serialize(self, data : BytesIO):
                
        super().serialize(data)

class ElfNoBits(ElfProgbits):
    
    # virtual adress stored in self.section_header.sh_addr
    
    
    def _unserialize_contents(self, data : BytesIO):
        
        pass
    
    def _serialize_contents(self, data : BytesIO):
        
        pass
        

class ST_INFO_TYPE(IntEnum): # SYMBOL_TYPE

    STT_NOTYPE = 0 # Not specified
    STT_OBJECT = 1 # Data object: variable, array, etc.
    STT_FUNC = 2 # Function or other executable code
    STT_SECTION = 3 # Section. Exists primarily for relocation
    STT_FILE = 4 # Name (pathname?) of the source file associated with object. Binding is STT_LOCAL, section index is SHN_ABS, and it precedes other STB_LOCAL symbols if present

class ST_INFO_BINDING(IntEnum): # SYMBOL_BINDING
    
    STB_LOCAL = 0 # Not visible outside object file where defined
    STB_GLOBAL = 1 # Visible to all object files. Multiple definitions cause errors. Force extraction of defining object from archive file.
    STB_WEAK = 2 # Visible to all object files. Ignored if STB_GLOBAL with same name found. Do not force extraction of defining object from archive file. Value is 0 if undefined.

class SPECIAL_SECTION_INDEX(IntEnum):
    
    SHN_UNDEF = 0
    SHN_LORESERVE = 0xff00
    SHN_LOPROC = 0xff00
    SHN_HIPROC = 0xff1f
    SHN_LIVEPATCH = 0xff20
    SHN_ABS = 0xfff1
    SHN_COMMON = 0xfff2
    SHN_HIRESERVE = 0xffff

class Elf32LittleEndianSymbolTableEntry(VariableEndiannessAndWordsizeStructure):
    
    _fields_ = [
        ('st_name', Elf32_Word), # Symbol name, index in string tbl
        ('st_value', Elf32_Addr), # Value of the symbol
        ('st_size', Elf32_Word), # Associated symbol size
        ('st_info_type', c_uint8, 4), # Type and binding attributes
        ('st_info_binding', c_uint8, 4),
        ('st_other', c_uint8), # No defined meaning, 0
        ('st_shndx', Elf32_Half), # Associated section index
    ]
    
    symbol_name : str = None
    
    associated_section : ElfSection = None
    
    
    # The user should fill st_name, st_info_type, st_info_binding, st_value

class Elf32BigEndianSymbolTableEntry(Elf32LittleEndianSymbolTableEntry):
    
    _fields_ = [
        ('st_name', Elf32_Word), # Symbol name, index in string tbl
        ('st_value', Elf32_Addr), # Value of the symbol
        ('st_size', Elf32_Word), # Associated symbol size
        ('st_info_binding', c_uint8, 4), # Type and binding attributes
        ('st_info_type', c_uint8, 4),
        ('st_other', c_uint8), # No defined meaning, 0
        ('st_shndx', Elf32_Half), # Associated section index
    ]
    
    
class Elf64LittleEndianSymbolTableEntry(Elf32LittleEndianSymbolTableEntry):
    
    _fields_ = [
        ('st_name', Elf64_Word), # Symbol name, index in string tbl
        ('st_info_type', c_uint8, 4), # Type and binding attributes
        ('st_info_binding', c_uint8, 4),
        ('st_other', c_uint8), # No defined meaning, 0
        ('st_shndx', Elf64_Half), # Associated section index
        ('st_value', Elf64_Addr), # Value of the symbol
        ('st_size', Elf64_Xword), # Associated symbol size
    ]
    
    
class Elf64BigEndianSymbolTableEntry(Elf64LittleEndianSymbolTableEntry):
    
    _fields_ = [
        ('st_name', Elf64_Word), # Symbol name, index in string tbl
        ('st_info_binding', c_uint8, 4), # Type and binding attributes
        ('st_info_type', c_uint8, 4),
        ('st_other', c_uint8), # No defined meaning, 0
        ('st_shndx', Elf64_Half), # Associated section index
        ('st_value', Elf64_Addr), # Value of the symbol
        ('st_size', Elf64_Xword), # Associated symbol size
    ]



class ElfSymtab(ElfSection):

    string_table : ElfSection = None # .dynstr or .strtab
    
    symbol_table : List[Elf32LittleEndianSymbolTableEntry] = None
    
    def __init__(self, elf_file : ElfFile):
        
        super().__init__(elf_file)
        
        self.symbol_table = []
    
    def _unserialize_contents(self, data : BytesIO):
        
        self.symbol_table = []
        
        for num_symbol in range(self.section_header.sh_size // self.section_header.sh_entsize):
            
            data.seek(self.section_header.sh_offset + num_symbol * self.section_header.sh_entsize)
            
            symbol_class = {
                (False, False): Elf32LittleEndianSymbolTableEntry,
                (True, False): Elf32BigEndianSymbolTableEntry,
                (False, True): Elf64LittleEndianSymbolTableEntry,
                (True, True): Elf64BigEndianSymbolTableEntry,
            }[(self.is_big_endian, self.is_64_bits)]
            
            symbol = symbol_class(self.is_big_endian, self.is_64_bits)
            
            symbol.unserialize(data)
            
            self.symbol_table.append(symbol)
            
    
    def post_unserialize(self):
            
        super().post_unserialize()
        
        # print('=> Interpreting symbol table at', self.section_name, 'at', hex(self.section_header.sh_offset))
        
        # Link strings to symbols
            
        self.string_table  = self.elf_file.sections[self.section_header.sh_link]
        
        for symbol in self.symbol_table:
            
            # symbol.pretty_print()
        
            # print(self.string_table.offset_to_string)
            symbol.symbol_name = self.string_table.return_string_from_offset(symbol.st_name)
        
            # In addition to strings, add a reference to
            # the associated section
            
            if symbol.st_shndx not in SPECIAL_SECTION_INDEX.__members__.values():
                
                symbol.associated_section = self.elf_file.sections[symbol.st_shndx]
            
            else:
                
                symbol.associated_section = SPECIAL_SECTION_INDEX(symbol.st_shndx)
        
    def pre_serialize(self):
        
        super().pre_serialize()
        
        self.section_header.sh_link = self.elf_file.sections.index(self.string_table)
        
        for symbol in self.symbol_table:
            
            symbol.st_name = self.string_table.add_string_and_return_offset(symbol.symbol_name)
            
            if symbol.associated_section and not isinstance(symbol.associated_section, SPECIAL_SECTION_INDEX):
            
                symbol.st_shndx = self.elf_file.sections.index(symbol.associated_section)
        
        self.section_header.sh_entsize = memoryview(self.symbol_table[0]).nbytes
    
    def _serialize_contents(self, data : BytesIO):
        
        local_symbols_first = lambda symbol: symbol.st_info_binding != ST_INFO_BINDING.STB_LOCAL
        
        found_a_non_local_symbol = False
        
        for num_symbol, symbol in enumerate(sorted(self.symbol_table, key = local_symbols_first)):
            
            if (symbol.st_info_binding != ST_INFO_BINDING.STB_LOCAL
                and not found_a_non_local_symbol):
                 
                found_a_non_local_symbol = True
                
                
                self.section_header.sh_info = num_symbol
                
            
            symbol.serialize(data)
            
        
        
    
class ElfDynsym(ElfSymtab):
    
    pass
    
class ElfStrtab(ElfSection):

    is_shstrtab : bool = None
    
    raw_string_table : bytes = None
    
    def _unserialize_contents(self, data : BytesIO):
        
        self.raw_string_table = data.read(self.section_header.sh_size)
    
    def _serialize_contents(self, data : BytesIO):
        
        data.write(self.raw_string_table)
    
    def return_string_from_offset(self, offset):
        
        return self.raw_string_table.decode('ascii')[offset:].split('\x00', 1)[0]
    
    def add_string_and_return_offset(self, string):
        
        string_offset = self.raw_string_table.find(string.encode('ascii') + b'\x00')
        
        if string_offset != -1:
            return string_offset
        
        string_offset = len(self.raw_string_table)
        
        self.raw_string_table += string.encode('ascii') + b'\x00'
        
        return string_offset




class Elf32LittleEndianRelocationTableEntry(VariableEndiannessAndWordsizeStructure):
    
    _fields_ = [
       ('r_offset', Elf32_Addr), # Location at which to apply the relocaction
       ('r_info_type', Elf32_Word, 8), # index and type of relocation
       ('r_info_sym', Elf32_Word, 24),
    ]
    
    # symbol_name : str = None
    
    associated_symbol : Elf32LittleEndianSymbolTableEntry = None


class Elf32BigEndianRelocationTableEntry(Elf32LittleEndianRelocationTableEntry):
    
    _fields_ = [
       ('r_offset', Elf32_Addr), # Location at which to apply the relocaction
       ('r_info_sym', Elf32_Word, 24), # index and type of relocation
       ('r_info_type', Elf32_Word, 8),
    ]
    

class Elf64LittleEndianRelocationTableEntry(Elf32LittleEndianRelocationTableEntry):
    
    _fields_ = [
       ('r_offset', Elf64_Addr), # Location at which to apply the action
       ('r_info_type', Elf64_Xword, 32), # index and type of relocation
       ('r_info_sym', Elf64_Xword, 32),
    ]
    

class Elf64BigEndianRelocationTableEntry(Elf64LittleEndianRelocationTableEntry):
    
    _fields_ = [
       ('r_offset', Elf64_Addr), # Location at which to apply the action
       ('r_info_sym', Elf64_Xword, 32), # index and type of relocation
       ('r_info_type', Elf64_Xword, 32),
    ]
    





















class Elf32LittleEndianRelocationWithAddendTableEntry(Elf32LittleEndianRelocationTableEntry):

    _fields_ = [
        *Elf32LittleEndianRelocationTableEntry._fields_,
        ('r_addend', Elf32_Sword), # Constant addend used to compute value
    ]


class Elf32BigEndianRelocationWithAddendTableEntry(Elf32LittleEndianRelocationTableEntry):

    _fields_ = [
        *Elf32BigEndianRelocationTableEntry._fields_,
        ('r_addend', Elf32_Sword), # Constant addend used to compute value
    ]


class Elf64LittleEndianRelocationWithAddendTableEntry(Elf32LittleEndianRelocationWithAddendTableEntry):

    _fields_ = [
        *Elf64LittleEndianRelocationTableEntry._fields_,
        ('r_addend', Elf64_Sxword), # Constant addend used to compute value
    ]

class Elf64BigEndianRelocationWithAddendTableEntry(Elf64LittleEndianRelocationWithAddendTableEntry):

    _fields_ = [
        *Elf64BigEndianRelocationTableEntry._fields_,
        ('r_addend', Elf64_Sxword), # Constant addend used to compute value
    ]
        
        



class ElfRel(ElfSection):
    
    relocation_table : List[Elf32LittleEndianRelocationTableEntry] = None
    
    
    def _unserialize_contents(self, data : BytesIO):
        
        self.relocation_table = []
        
        for num_symbol in range(self.section_header.sh_size // self.section_header.sh_entsize):
            
            
            relocation_class = {
                (False, False): Elf32LittleEndianRelocationTableEntry,
                (True, False): Elf32BigEndianRelocationTableEntry,
                (False, True): Elf64LittleEndianRelocationTableEntry,
                (True, True): Elf64BigEndianRelocationTableEntry,
            }[(self.is_big_endian, self.is_64_bits)]
            
            relocation = relocation_class(self.is_big_endian, self.is_64_bits)
            
            
            relocation.unserialize(data)
            
            self.relocation_table.append(relocation)
            
            
            
            
            
        
        
    
    def post_unserialize(self):
        
        super().post_unserialize()
        
        self.symtab_section  = self.elf_file.sections[self.section_header.sh_link]
        
        for relocation in self.relocation_table:
            
            relocation.associated_symbol = self.symtab_section.symbol_table[relocation.r_info_sym]
            
            # relocation.pretty_print()
            
            # print('le', relocation.associated_symbol.symbol_name)
            
            # relocation.symbol_name = relocation.associated_symbol.symbol_name
    
    
    def pre_serialize(self):
        
        super().pre_serialize()
        
        for relocation in self.relocation_table:
            
            relocation.r_info_sym = self.symtab_section.symbol_table.index(relocation.associated_symbol)
        
        self.section_header.sh_entsize = memoryview(self.relocation_table[0]).nbytes
    
    def _serialize_contents(self, data : BytesIO):
        
        for relocation in self.relocation_table:
            
            relocation.serialize(data)
            
            

class ElfRela(ElfRel):
    
    relocation_table : List[Elf32LittleEndianRelocationWithAddendTableEntry] = None
    
    
    def unserialize(self, data : BytesIO):
        
        super().unserialize(data)
        
        data.seek(self.section_header.sh_offset)
        
        self.relocation_table = []
        
        for num_symbol in range(self.section_header.sh_size // self.section_header.sh_entsize):

            relocation_class = {
                (False, False): Elf32LittleEndianRelocationWithAddendTableEntry,
                (True, False): Elf32BigEndianRelocationWithAddendTableEntry,
                (False, True): Elf64LittleEndianRelocationWithAddendTableEntry,
                (True, True): Elf64BigEndianRelocationWithAddendTableEntry,
            }[(self.is_big_endian, self.is_64_bits)]
            
            relocation = relocation_class(self.is_big_endian, self.is_64_bits)
            
            relocation.unserialize(data)
            
            self.relocation_table.append(relocation)
            
    

class ElfDynamic(ElfSection):
    
    pass

class ElfHash(ElfSection):
    
    symbol_table : ElfSection = None
        
        
        
        
SECTION_TYPE_TO_CLASS = {
    SH_TYPE.SHT_NULL: ElfNullSection,
    SH_TYPE.SHT_PROGBITS: ElfProgbits,
    SH_TYPE.SHT_NOBITS: ElfNoBits,
    SH_TYPE.SHT_SYMTAB: ElfSymtab,
    SH_TYPE.SHT_STRTAB: ElfStrtab,
    SH_TYPE.SHT_RELA: ElfRela,
    SH_TYPE.SHT_HASH: ElfHash,
    SH_TYPE.SHT_DYNAMIC: ElfDynamic,
    SH_TYPE.SHT_REL: ElfRel,
    SH_TYPE.SHT_DYNSYM: ElfDynsym
}

SECTION_CLASS_TO_TYPE = {v: k for k, v in    SECTION_TYPE_TO_CLASS.items()} 
        
        

class E_IDENT_INDEXES(IntEnum):

    EI_MAG0 = 0
    EI_MAG1 = 1
    EI_MAG2 = 2
    EI_MAG3 = 3
    EI_CLASS = 4
    EI_DATA = 5
    EI_VERSION = 6
    EI_OSABI = 7
    EI_ABIVERSION = 8
    EI_NIDENT = 16


class EI_VERSION(IntEnum):
    
    EV_CURRENT = 1   


class EI_CLASS(IntEnum):
    
    ELFCLASS32 = 1
    
    ELFCLASS64 = 2


class EI_DATA(IntEnum):
    
    ELFDATA2LSB = 1 # 32-bit objects
    
    ELFDATA2MSB = 2 # 64-bit objects


class EI_OSABI(IntEnum):
    
    ELFOSABI_SYSV = 0 # System V ABI
    
    ELFOSABI_HPUX = 1 # HP-UX operating system
    
    ELFOSABI_STANDALONE = 255 # Standalone (embedded) application


class E_TYPE(IntEnum):
    
    ET_NONE = 0 # No file type
    
    ET_REL = 1 # Relocatable object file
    
    ET_EXEC = 2 # Executable file
    
    ET_DYN = 3 # Shared object file
    
    ET_CORE = 4 # Core file


class ElfFileHeader(VariableEndiannessAndWordsizeStructure):
    
    _fields_ = [
    
      ('EI_MAG', c_char * 4), # ELF "magic number"
      ('EI_CLASS', c_uint8), # File class
      ('EI_DATA', c_uint8), # Data encoding
      ('EI_VERSION', c_uint8), # File version
      ('EI_OSABI', c_uint8), # OS/ABI identification
      ('EI_ABIVERSION', c_uint8), # ABI version
      ('EI_PAD', c_uint8 * 7),
      
      ('e_type', Elf64_Half),
      ('e_machine', Elf64_Half),
      ('e_version', Elf64_Word),
      ('e_entry', Elf64_Addr), # Entry point virtual address
      ('e_phoff', Elf64_Off), # Program header table file offset
      ('e_shoff', Elf64_Off), # Section header table file offset
      ('e_flags', Elf64_Word),
      ('e_ehsize', Elf64_Half),
      ('e_phentsize', Elf64_Half),
      ('e_phnum', Elf64_Half),
      ('e_shentsize', Elf64_Half),
      ('e_shnum', Elf64_Half),
      ('e_shstrndx', Elf64_Half),
    ]
    
    def __init__(self):
                
        self.EI_MAG = b'\x7fELF'
        
        self.EI_CLASS = {
            False: EI_CLASS.ELFCLASS32,
            True: EI_CLASS.ELFCLASS64
        }[self.is_64_bits]
        
        self.EI_DATA = {
            False: EI_DATA.ELFDATA2LSB,
            True: EI_DATA.ELFDATA2MSB
        }[self.is_big_endian]
        
        self.EI_OSABI = EI_OSABI.ELFOSABI_SYSV
        
        self.e_version = self.EI_VERSION = EI_VERSION.EV_CURRENT
        
        
        
        # Let the user set e_flags, e_machine, e_entry
        
        



class P_TYPE: # PROGRAM_HEADER_TYPE
    
    PT_NULL = 0 # Null descriptor — ignore
    PT_LOAD = 1 # Loadable segment
    PT_DYNAMIC = 2 # Dynamic segment
    PT_INTERP = 3 # Interpreter pathname
    PT_NOTE = 4 # Auxiliary information segment
    PT_SHLIB = 5 # Reserved
    PT_PHDR = 6 # Program header segment


class P_FLAGS: # PROGRAM_HEADER_FLAGS
    
    PF_X = 0x1 # Executable
    PF_W = 0x2 # Writable
    PF_R = 0x4 # Readable

    
    

class Elf32ProgramHeaderEntry(VariableEndiannessAndWordsizeStructure):
    
    _fields_ = [
        ('p_type', Elf32_Word),
        ('p_offset', Elf32_Off), # Segment file offset
        ('p_vaddr', Elf32_Addr), # Segment virtual address
        ('p_paddr', Elf32_Addr), # Segment physical address
        ('p_filesz', Elf32_Word), # Segment size in file
        ('p_memsz', Elf32_Word), # Segment size in memory
        ('p_flags', Elf32_Word),
        ('p_align', Elf32_Word), # Segment alignment, file & memory
    ]
    

class Elf64ProgramHeaderEntry(Elf32ProgramHeaderEntry):
    
    _fields_ = [
        ('p_type', Elf64_Word),
        ('p_flags', Elf64_Word),
        ('p_offset', Elf64_Off), # Segment file offset
        ('p_vaddr', Elf64_Addr), # Segment virtual address
        ('p_paddr', Elf64_Addr), # Segment physical address
        ('p_filesz', Elf64_Xword), # Segment size in file
        ('p_memsz', Elf64_Xword), # Segment size in memory
        ('p_align', Elf64_Xword), # Segment alignment, file & memory
    ]
    










