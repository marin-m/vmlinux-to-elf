#!/usr/bin/env python3
#-*- encoding: Utf-8 -*-
from lzma import LZMADecompressor
from io import BytesIO, SEEK_END
from bz2 import BZ2Decompressor
from gzip import _GzipReader
from struct import unpack
from typing import Union
from re import search
import importlib

"""
    How to detect a vmlinuz file?
    
    A "standard" script for it does not
    attempt to interprete architecture-specific
    details, but just scans for a file compression
    signature:
    https://github.com/torvalds/linux/blob/master/scripts/extract-vmlinux
    
    This script uses supports the following compression formats, which are all
    the standard compression formats for the kernel, some of which have been
    added quite recently (including LZO, LZ4 and Facebook's ZSTD):
    
    try_decompress b'\x1f\x8b\x08'  xy    gunzip          1f8b08
    try_decompress b'\xfd7zXZ\x00'  abcde unxz            fd377a585a00   (AND NOT "fd377a585a00000000".decode('hex')+"XZ decompressor")
    try_decompress b'BZh'           xy    bunzip2
    try_decompress b']\x00\x00\x00' xxx   unlzma
    try_decompress b'\x89LZ'        xy    'lzop -d'
    try_decompress b'\x02!L\x18'    xxx   'lz4 -d'
    try_decompress b'(\xb5/\xfd'    xxx   unzstd
    
    On x86:
    Sample assembly is here https://github.com/torvalds/linux/blob/master/arch/x86/boot/header.S#L300
    => How does libmagic detect it?
    ==> https://github.com/threatstack/libmagic/blob/master/magic/Magdir/linux#L99
    
    On ARM:
    Sample assembly is here https://github.com/torvalds/linux/blob/master/arch/arm/boot/compressed/head.S#L180
    => Magics defined here: https://github.com/torvalds/linux/blob/master/arch/arm/boot/compressed/vmlinux.lds.S#L111
    ==> Magic numbers are: 0x04030201 and 0x016f2818
    ==> The data put after allows to know the offset of the end of the compressed vmlinuz executable (the total file size normally), and jump from the end of the size to the offset of the integer containing the offset to the compressed XZ data (located at -0x28 from the end (is this an appended dtb?))
    ==> Additional information with magics numbers 0x45454545 and 0x5a534c4b has been added as of September 2017 (kernel 4.15)
    => How does binwalk detect it?
    => How does libmagic detect it?
    ==> https://github.com/threatstack/libmagic/blob/master/magic/Magdir/linux#L194
"""

"""
    This class contains well-known vmlinux signatures
"""
class Signature:
    Compressed_GZIP = b'\x1f\x8b\x08'
    Compressed_XZ   = b'\xfd7zXZ\x00'
    Compressed_LZMA = b']\x00\x00'
    Compressed_BZ2  = b'BZh'
    Compressed_LZ4  = b'\x04"M\x18'     # https://github.com/lz4/lz4/blob/dev/doc/lz4_Frame_format.md

    Compressed = [
        Compressed_GZIP,
        Compressed_XZ,
        Compressed_LZMA,
        Compressed_BZ2,
        Compressed_LZ4,
    ]

    @staticmethod
    def check(data, offset, sign):
        return sign == data[offset:offset + len(sign)]

    @staticmethod
    def is_compressed(data, offset):
        for sign in Signature.Compressed:
            if Signature.check(data, offset, sign):
                return True
        return False    

"""
    This class will try to read a single GZip file
    out of a given input buffer, rather than an unlimited
    number of succeeding GZip files.
    
    The constructor takes a single BytesIO instance as an
    argument.
"""

class SingleGzipReader(_GzipReader):
    read_one_gzip_header : bool = False
    __new_member : bool = None
    
    @property
    def _new_member(self):
        return self.__new_member
    
    @_new_member.setter
    def _new_member(self, new_value): # Property normally set to True once per GZip header to be read
        if new_value:
            if self.read_one_gzip_header:
                self._fp.file.seek(0, SEEK_END) # Simulate EOF when called for the second time
                self._fp._read = None
            self.read_one_gzip_header = True
        self.__new_member = new_value
        

"""
    Try to decompress a file at a given offset, without
    knowing the compression algorithm
"""


def try_decompress_at(input_file : bytes, offset : int) -> bytes:
    
    decoded = None

    try:
        
        if Signature.check(input_file, offset, Signature.Compressed_GZIP):
            decoded = SingleGzipReader(BytesIO(input_file[offset:])).read(-1) # Will stop reading after the GZip footer thanks to our modification above.
        
        elif (Signature.check(input_file, offset, Signature.Compressed_XZ) or
              Signature.check(input_file, offset, Signature.Compressed_LZMA)):
            try:
                decoded = LZMADecompressor().decompress(input_file[offset:]) # Will discard the extra bytes and put it an attribute.
                
            except Exception:
                decoded = LZMADecompressor().decompress(input_file[offset:offset + 5] + b'\xff' * 8 + input_file[offset + 5:]) # pylzma format compatibility
        
        elif Signature.check(input_file, offset, Signature.Compressed_BZ2):
            decoded = BZ2Decompressor().decompress(input_file[offset:]) # Will discard the extra bytes and put it an attribute.

        elif Signature.check(input_file, offset, Signature.Compressed_LZ4):
            try:
                LZ4Decompressor = importlib.import_module('lz4.frame')
                
            except ModuleNotFoundError:
                print('ERROR: This kernel requres LZ4 decompression.')
                print('       But "lz4" python package does not found.')
                print('       Example installation command: "sudo pip3 install lz4"')
                print()
                return

            context = LZ4Decompressor.create_decompression_context()
            decoded, bytes_read, end_of_frame = LZ4Decompressor.decompress_chunk(context, input_file[offset:])
    
    except Exception:
        pass
    
    if decoded and len(decoded) > 0x1000:
        print(('[+] Kernel successfully decompressed in-memory (the offsets that ' +
            'follow will be given relative to the decompressed binary)'))
    
        return decoded

def obtain_raw_kernel_from_file(input_file: bytes) -> bytes:
    
    # Check for known signatures at fixed offsets.
    # 
    # Note that mangled semi-correct kernel version strings may be present
    # in the compressed output at this point, so don't check for a kernel
    # version string for now.
    
    file_size = len(input_file)

    # Try offsets that may be stored in the
    # last words of the file, as well for
    # the start of the file
    
    possible_offsets :     Set[int] =         set([0])

    for possible_endianness in '<>':
        possible_offsets |=       set(unpack(possible_endianness + '20I',  input_file[file_size - 4 * 20:]))
    
    for possible_offset in sorted(possible_offsets):
        decompressed_data = try_decompress_at(input_file, possible_offset)
        if decompressed_data:
            return decompressed_data
    
    if not search(b'Linux version (\d+\.[\d.]*\d)[ -~]+', input_file):  # No kernel version string found

        # If not successful, scan for compression signatures in the whole document
        for possible_signature in Signature.Compressed:
            
            possible_offset = input_file.find(possible_signature)
            
            while possible_offset > -1:
                decompressed_data = try_decompress_at(input_file, possible_offset)
                if decompressed_data:
                    return decompressed_data
                possible_offset = input_file.find(possible_signature, possible_offset + 1)

    
    return input_file
    
    


