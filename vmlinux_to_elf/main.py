#!/usr/bin/env python3
#-*- encoding: Utf-8 -*-
from argparse import ArgumentParser
from io import BytesIO
from sys import argv


try:
    from vmlinuz_decompressor import obtain_raw_kernel_from_file
    from elf_symbolizer import ElfSymbolizer

except ImportError:
    from vmlinux_to_elf.vmlinuz_decompressor import obtain_raw_kernel_from_file
    from vmlinux_to_elf.elf_symbolizer import ElfSymbolizer

if __name__ == '__main__':
    
    args = ArgumentParser(description = 'Turn a raw or compressed kernel binary, ' +
        'or a kernel ELF without symbols, into a fully analyzable ELF whose ' +
        'symbols were extracted from the kernel symbol table')
    
    args.add_argument('input_file', help = 'Path to the vmlinux/vmlinuz/zImage/' +
        'bzImage/kernel.bin/kernel.elf file to make into an analyzable .ELF')
    
    args.add_argument('output_file', help = 'Path to the analyzable ' +
        '.ELF to output')
    
    args = args.parse_args()
    
    with open(args.input_file, 'rb') as kernel_bin:
        
        ElfSymbolizer(
            obtain_raw_kernel_from_file(
                kernel_bin.read()
            ), args.output_file
        )
