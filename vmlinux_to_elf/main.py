#!/usr/bin/env python3
#-*- encoding: Utf-8 -*-
from argparse import ArgumentParser
from io import BytesIO
from sys import argv, stdout
import logging

try:
    from vmlinuz_decompressor import obtain_raw_kernel_from_file
    from elf_symbolizer import ElfSymbolizer
    from architecture_detecter import ArchitectureGuessError

except ImportError:
    from vmlinux_to_elf.vmlinuz_decompressor import obtain_raw_kernel_from_file
    from vmlinux_to_elf.elf_symbolizer import ElfSymbolizer
    from vmlinux_to_elf.architecture_detecter import ArchitectureGuessError

if __name__ == '__main__':

    logging.basicConfig(stream=stdout, level=logging.INFO, format='%(message)s')
    
    args = ArgumentParser(description = 'Turn a raw or compressed kernel binary, ' +
        'or a kernel ELF without symbols, into a fully analyzable ELF whose ' +
        'symbols were extracted from the kernel symbol table')
    
    args.add_argument('input_file', help = 'Path to the vmlinux/vmlinuz/zImage/' +
        'bzImage/kernel.bin/kernel.elf file to make into an analyzable .ELF')
    
    args.add_argument('output_file', help = 'Path to the analyzable .ELF to output')
    
    args.add_argument('--e-machine', help = 'Force overriding the output ELF ' +
        '"e_machine" field with this integer value (rather than auto-detect)',
        type = lambda string: int(string, 0), metavar = 'DECIMAL_NUMBER')
    
    args.add_argument('--bit-size', help = 'Force overriding the input kernel ' +
        'bit size, providing 32 or 64 bit (rather than auto-detect)', type = int)
    
    args.add_argument('--file-offset', help = 'Consider that the raw kernel starts ' +
        'at this offset of the provided raw file or compressed stream (rather than ' +
        '0, or the beginning of the ELF sections if an ELF header was present in the ' +
        'input)', type = lambda string: int(string.replace('0x', ''), 16), metavar = 'HEX_NUMBER')
    
    args.add_argument('--base-address', help = 'Force overriding the output ELF ' +
        'base address field with this integer value (rather than auto-detect)',
        type = lambda string: int(string.replace('0x', ''), 16), metavar = 'HEX_NUMBER')

    args = args.parse_args()
    
    if ((args.e_machine is not None and args.bit_size is None) or
        (args.e_machine is None and args.bit_size is not None)):
        
        logging.error('[!] Please specify both an addressing bit size ' +
            'and the ELF "e_machine" field, or neither for ' +
            'auto-detection')
        
        exit()
            
    
    with open(args.input_file, 'rb') as kernel_bin:
        
        try:
            
            ElfSymbolizer(
                obtain_raw_kernel_from_file(
                    kernel_bin.read()
                ), args.output_file, args.e_machine, args.bit_size,
                args.base_address, args.file_offset
            )
        
        except ArchitectureGuessError:
        
            exit('[!] The architecture of your kernel could not be guessed ' +
                'successfully. Please specify the --e-machine and --bit-size ' +
                'arguments manually (use --help for their precise specification).')

