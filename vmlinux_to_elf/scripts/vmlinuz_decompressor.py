#!/usr/bin/env python3
# -*- encoding: Utf-8 -*-
import logging
from importlib.metadata import version
from argparse import ArgumentParser
from sys import stderr, argv

from vmlinux_to_elf.core.auto_unpack import VmlinuzDecompressor


def main():
    logging.basicConfig(
        stream=stderr, level=logging.INFO, format='%(message)s'
    )

    if '-V' in argv or '--version' in argv:
        print('vmlinux-to-elf version ' + version('vmlinux-to-elf'))
        exit(0)

    args = ArgumentParser(
        description='Utility to turn a compressed or packed kernel '
        + 'binary (with or without a symbols table) into an raw uncompressed kernel binary'
    )

    args.add_argument(
        '-V',
        '--version',
        action='store_true',
        help='Print package version to the standard output',
    )

    args.add_argument(
        'input_file',
        help='Path to the vmlinux/vmlinuz/zImage/'
        + 'bzImage/kernel.bin/kernel.elf file to decompress',
    )

    args.add_argument(
        'output_file', help='Path to the decompressed file to output'
    )

    args = args.parse_args()

    with open(args.input_file, 'rb') as kernel_bin:
        compressed_data = kernel_bin.read()
        uncompressed_data = VmlinuzDecompressor(
            compressed_data, is_entry_point=True
        ).decompressed

    if compressed_data == uncompressed_data:
        logging.error(
            '[!] No compressed or packed data was recognized '
            + 'within the given input kernel file'
        )
        exit()

    with open(args.output_file, 'wb') as output_bin:
        output_bin.write(uncompressed_data)


if __name__ == '__main__':
    main()
