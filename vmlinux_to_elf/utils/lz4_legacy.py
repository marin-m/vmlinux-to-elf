#!/usr/bin/python3
#-*- encoding: Utf-8 -*-
from lz4.block import decompress
from io import BytesIO

"""
    This file  contains a basic translator for turning compression
    streams using the legacy LZ4 format [1] (magic 0x184C2102),
    used by various old or less old Linux kernels, into the newer
    LZ4 format [2] (magic 0x184D2204).
    
    [1] 02 21 4C 18 - https://github.com/lz4/lz4/blob/dev/doc/lz4_Frame_format.md#legacy-frame
    [2] 04 22 4D 18 - https://github.com/lz4/lz4/blob/dev/doc/lz4_Frame_format.md#general-structure-of-lz4-frame-format
"""

def decompress_lz4_buffer(lz4_buffer : BytesIO):
    
    assert lz4_buffer.read(4) == (0x184C2102).to_bytes(4, 'little') # Check the legacy magic
    
    MAX_LEGACY_BLOCK_SIZE = 8 * 1024 * 1024 # 8 MB
    
    uncompressed_stream = b''
    
    while True:
        compressed_block_size_raw = lz4_buffer.read(4)
        if len(compressed_block_size_raw) < 4:
            break
        
        compressed_block_size = int.from_bytes(compressed_block_size_raw, 'little')
        
        compressed_block = lz4_buffer.read(compressed_block_size)
        if len(compressed_block) < compressed_block_size or not compressed_block_size:
            break
        
        uncompressed_block = decompress(compressed_block, MAX_LEGACY_BLOCK_SIZE)
        uncompressed_stream += uncompressed_block
        if len(uncompressed_block) < MAX_LEGACY_BLOCK_SIZE:
            break
        
    return uncompressed_stream
        
        

