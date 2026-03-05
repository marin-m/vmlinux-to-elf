#!/bin/bash
cd "$(dirname "$0")/../.."
sudo snap remove --purge vmlinux-to-elf
rm -f vmlinux-to-elf_*_amd64.snap
snapcraft pack && \
    sudo snap install --dangerous vmlinux-to-elf_*_amd64.snap && \
    sleep 5 &&
    vmlinux-to-elf
    vmlinux-to-elf.gui
