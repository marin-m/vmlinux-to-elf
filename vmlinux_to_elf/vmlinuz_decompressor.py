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
import logging

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
    Compressed_LZ4_Legacy = b'\x02!L\x18'
    Compressed_ZSTD = b'(\xb5/\xfd'
    Compressed_LZO  = b'\x89LZ'
    DTB_Appended_Qualcomm = b'UNCOMPRESSED_IMG' # https://www.google.com/search?q="PATCHED_KERNEL_MAGIC"
    Android_Bootimg = b'ANDROID!' # https://source.android.com/devices/bootloader/boot-image-header

    Compressed = [
        Compressed_GZIP,
        Compressed_XZ,
        Compressed_LZMA,
        Compressed_BZ2,
        Compressed_LZ4,
        Compressed_LZ4_Legacy,
        Compressed_ZSTD,
        Compressed_LZO,
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
        
        if Signature.check(input_file, offset, Signature.DTB_Appended_Qualcomm): # Merely unpack a Qualcomm kernel file containing a magic and DTB offset at the start (so that offsets aren't wrong)
            
            dtb_offset_le = int.from_bytes(input_file[offset + 16:offset + 20], 'little')
            dtb_offset_be = int.from_bytes(input_file[offset + 16:offset + 20], 'big')
            
            decoded = input_file[offset + 20:offset + 20 + min(dtb_offset_le, dtb_offset_be)]
        
        elif Signature.check(input_file, offset, Signature.Android_Bootimg): # Unpack an uncompressed Android Bootimg file, version 0, 1, 2 or 3
            
            # See, for reference:
            # - https://github.com/osm0sis/mkbootimg/blob/master/unpackbootimg.c
            # - https://github.com/osm0sis/mkbootimg/blob/master/bootimg.h
            
            assert len(input_file) > 4096
            
            header_version_raw = input_file[offset + 10 * 4: offset + 11 * 4]
            
            endianness = 'little'

            if header_version_raw in (b'\0\0\0\3', b'\3\0\0\0'):
                page_size = 4096
                
                if header_version_raw == b'\0\0\0\3':
                    endianness = 'big'
                
            else:
                page_size_raw = input_file[offset + 9 * 4:offset + 10 * 4]
                
                page_size_le = int.from_bytes(page_size_raw, 'little')
                page_size_be = int.from_bytes(page_size_raw, 'big')
                
                if page_size_le < page_size_be:
                    page_size = page_size_le
                else:
                    endianness = 'big'
                    page_size = page_size_be
            
            kernel_size = int.from_bytes(input_file[offset + 2 * 4:offset + 3 * 4], endianness)
            
            assert len(input_file) > kernel_size > 0x1000
            assert len(input_file) > page_size > 0x200
            
            decoded = input_file[offset + page_size:offset + page_size + kernel_size]
            
            # Also try to re-unpack the output image in the case where the nested
            # kernel would start with a "UNCOMPRESSED_IMG" Qualcomm magic, for example
            
            decoded = try_decompress_at(decoded, 0) or decoded
        
        
        elif Signature.check(input_file, offset, Signature.Compressed_GZIP):
            decoded = SingleGzipReader(BytesIO(input_file[offset:])).read(-1) # GZIP - Will stop reading after the GZip footer thanks to our modification above.
        
        elif (Signature.check(input_file, offset, Signature.Compressed_XZ) or
              Signature.check(input_file, offset, Signature.Compressed_LZMA)):
            try:
                decoded = LZMADecompressor().decompress(input_file[offset:]) # LZMA - Will discard the extra bytes and put it an attribute.
                
            except Exception:
                decoded = LZMADecompressor().decompress(input_file[offset:offset + 5] + b'\xff' * 8 + input_file[offset + 5:]) # pylzma format compatibility
        
        elif Signature.check(input_file, offset, Signature.Compressed_BZ2):
            decoded = BZ2Decompressor().decompress(input_file[offset:]) # BZ2 - Will discard the extra bytes and put it an attribute.

        elif Signature.check(input_file, offset, Signature.Compressed_LZ4): # LZ4 support
            try:
                LZ4Decompressor = importlib.import_module('lz4.frame')
                
            except ModuleNotFoundError:
                logging.error('ERROR: This kernel requres LZ4 decompression.')
                logging.error('       But "lz4" python package was not found.')
                logging.error('       Example installation command: "sudo pip3 install lz4"')
                logging.error()
                return

            context = LZ4Decompressor.create_decompression_context()
            decoded, bytes_read, end_of_frame = LZ4Decompressor.decompress_chunk(context, input_file[offset:])
        
        elif Signature.check(input_file, offset, Signature.Compressed_LZ4_Legacy): # LZ4 support (legacy format)
            
            try:
                from utils.lz4_legacy import decompress_lz4_buffer
            except ImportError:
                try:
                    from vmlinux_to_elf.utils.lz4_legacy import decompress_lz4_buffer
                except ModuleNotFoundError:
                    logging.error('ERROR: This kernel requres LZ4 decompression.')
                    logging.error('       But "lz4" python package was not found.')
                    logging.error('       Example installation command: "sudo pip3 install lz4"')
                    logging.error()
                    return
                
            decoded = decompress_lz4_buffer(BytesIO(input_file[offset:]))

        elif Signature.check(input_file, offset, Signature.Compressed_ZSTD):
            try:
                import zstandard as zstd
            except ModuleNotFoundError:
                logging.error('ERROR: This kernel requres ZSTD decompression.')
                logging.error('       But "zstandard" python package was not found.')
                logging.error('       Example installation command: "sudo pip3 install zstandard"')
                logging.error()
                return
            buf = BytesIO()
            context = zstd.ZstdDecompressor()
            for chunk in context.read_to_iter(BytesIO(input_file[offset:])):
                buf.write(chunk)
            buf.seek(0)
            decoded = buf.read()

        elif Signature.check(input_file, offset, Signature.Compressed_LZO):
            try:
                import lzo
            except ModuleNotFoundError:
                logging.error('ERROR: This kernel requres LZO decompression.')
                logging.error('       But "python-lzo" python package was not found.')
                logging.error('       Example installation command: "sudo pip3 install git+https://github.com/clubby789/python-lzo@b4e39df"')
                logging.error()
                return
            buf = BytesIO(input_file[offset:])
            decoded = lzo.LzoFile(fileobj=buf, mode='rb').read()
    except Exception:
        pass
    
    if decoded and len(decoded) > 0x1000:
        logging.info(('[+] Kernel successfully decompressed in-memory (the offsets that ' +
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
    
    


