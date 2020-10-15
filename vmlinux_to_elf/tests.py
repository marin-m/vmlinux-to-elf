#!/usr/bin/env python3
#-*- encoding: Utf-8 -*-

"""
    Check the program's ability to decompress
    the files files whose the absolute path
    is referenced by the "test_kernels.txt"
    present in the current directory (one kernel
    path per line, separated with LF)
    
    As this file is local to your own machine,
    it is ignored by the ".gitignore"
    
    It will also write successfully reconstructed
    ELF files to an automatically created "tests_output/" folder.
"""


try:
    from vmlinuz_decompressor import obtain_raw_kernel_from_file
    from elf_symbolizer import ElfSymbolizer

except ImportError:
    from vmlinux_to_elf.vmlinuz_decompressor import obtain_raw_kernel_from_file
    from vmlinux_to_elf.elf_symbolizer import ElfSymbolizer

from os.path import dirname, realpath, exists
from traceback import print_exc
from os import makedirs
from re import sub
from sys import stdout
import logging

SCRIPT_DIR = dirname(realpath(__file__))
TEST_KERNELS_PATH = realpath(SCRIPT_DIR + '/test_kernels.txt')
ELF_KERNELS_OUTPUT_PATH = realpath(SCRIPT_DIR + '/tests_output')

def slugify(file_path):
    
    return sub('[^a-z0-9]+', '-', file_path.lower()).strip('-')

if __name__ == '__main__':

    logging.basicConfig(stream=stdout, level=logging.INFO, format='%(message)s')

    if not exists(TEST_KERNELS_PATH):
        
        exit(('[!] In order to use this script, please ' +
             'create a file at %s, containing to path ' +
             'to one kernel to extract per line. Quitting.') % (TEST_KERNELS_PATH))
    
    makedirs(ELF_KERNELS_OUTPUT_PATH, exist_ok = True)


    for file_name in filter(None, map(str.strip, open(TEST_KERNELS_PATH, 'r'))):
        
        logging.info('Testing ' + file_name)
        
        with open(file_name, 'rb') as fd:
            contents = fd.read()
        
        raw_data = obtain_raw_kernel_from_file(contents)
        try:
            ElfSymbolizer(raw_data, ELF_KERNELS_OUTPUT_PATH + '/' + slugify(file_name) + '.elf')
        except Exception:
            logging.error('=> No symbols!')
            print_exc()
        
        






