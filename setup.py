#!/usr/bin/python3

from distutils.core import setup

setup(name='vmlinux-to-elf',
      version='1.0',
      description='A tool to recover a fully analyzable .ELF from a raw kernel, through extracting the kernel symbol table (kallsyms)',
      author='Marin Moulinier',
      author_email='',
      url='https://github.com/marin-m/vmlinux-to-elf',
      install_requires=['lz4', 'zstandard', 'python-lzo'],
      packages=['vmlinux_to_elf', 'vmlinux_to_elf.utils'],
      scripts=['vmlinux-to-elf', 'kallsyms-finder']
     )
