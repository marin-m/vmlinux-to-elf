#!/bin/bash

cd "$(dirname "$0")"
set -ex

glib-compile-resources vmlinux-to-elf.gresource.xml
