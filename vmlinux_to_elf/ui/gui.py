#!/usr/bin/env python3
#-*- encoding: Utf-8 -*-
from os.path import dirname, realpath
import sys

SCRIPT_DIR = dirname(realpath(__file__))
PACKAGE_DIR = dirname(SCRIPT_DIR)
PARENT_DIR = dirname(PACKAGE_DIR)
sys.path.insert(0, PARENT_DIR)

from vmlinux_to_elf.ui.gtk_app import main

if __name__ == '__main__':
    main()
