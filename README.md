# vmlinux-to-elf

This tool allows to obtain a fully analyzable .ELF file from a vmlinux/vmlinuz/bzImage/zImage kernel image (either a raw binary blob or a preexisting but stripped .ELF file), with recovered function and variable symbols.

<p align="center"><img src="https://raw.githubusercontent.com/marin-m/vmlinux-to-elf/master/pics/landing_illustration.png"></p>

For this, it scans your kernel for a kernel symbol table ([kallsyms](https://github.com/torvalds/linux/blob/master/kernel/kallsyms.c)), a compressed symbol table that is present in almost every kernel, mostly unaltered.

Because the concerned symbol table is originally compressed, it should recover strings that aren't visible in the original binary.

It produces an .ELF file that you can analyze using IDA Pro and Ghidra. This tool is hence useful for embedded systems reverse engineering.

Usage:

```bash
./vmlinux-to-elf <input_kernel.bin> <output_kernel.elf>
```

System-wide installation (the second command may not be needed as PIP should find the dependencies within the `setup.py` file):

```bash
sudo apt install python3-pip
sudo pip3 install --upgrade lz4 zstandard git+https://github.com/clubby789/python-lzo@b4e39df
sudo pip3 install --upgrade git+https://github.com/marin-m/vmlinux-to-elf
```

## Features
* Take a raw binary blob or ELF kernel file as an input  [OK]
* Automatically detect and unpack the main compression formats used for the Linux kernel [OK]
* Find and extract the embedded kernel symbols table (kallsyms) from the input file  [OK]
* Infer the instruction set architecture, endianness, bit size, relying upon other things on common function prologue signatures [OK]
* Infer the entry point of the kernel from the symbols contained in the kallsyms table  [OK]
* Provide basic inference for the kernel base address  [OK] (for now, consider that it is the first "TEXT" symbol address of the binary with the lower 0xfff bits clear - seems to work well enough)
* Unpack certain types of Android `boot.img` files, starting with an `ANDROID!` or `UNCOMPRESSED_IMG` magic [OK]
* Produce an .ELF file fully analyzable with IDA Pro or Ghidra as an output  [OK]


## How does it work, really?

A brief history of the "kallsyms" symbol table can be found at the top of the "[kallsyms_finder.py](vmlinux_to_elf/kallsyms_finder.py)" file. Briefly, this was introduced circa 2004 in the Linux kernel in its current form and is used to print the "Kernel oops" messages, among other things.

It contains tuples of "symbol name", "symbol address", "symbol type" (symbol types being designated with a single letter in a fashion similar to the [`nm`](http://man7.org/linux/man-pages/man1/nm.1p.html) utility), this information being tightly packed with a simple compression algorithm.

The schema below displays how this information is serialized into the kernel, the offset of each respective structure being detected by `vmlinux-to-elf` through [heuristics](vmlinux_to_elf/kallsyms_finder.py):

| Array name | Description | Sample contents |
| ---------- | ----------- | --------------- |
| `kallsyms_addresses` (or `kallsyms_offsets` + `kallsyms_relative_base`) |  The addresses (or offsets relative to a base, in recent kernels) of each symbol, as an array | `80 82 00 C0  80 82 00 C0  80 82 00 C0  0C 84 00 C0  B4 84 00 C0  5C 85 00 C0  60 85 00 C0  60 85 00 C0` ...
| `kallsyms_num_syms`      | The total number of symbols, as an integer (useful for checking for endianness, alignment, correct decoding of the symbols table) | `54 D4 00 00`
| `kallsyms_names`         | The compressed, length-separated symbol names themselves. Each byte in the compressed symbol strings references an index in the "kallsyms_token_index" array, that itself references the offset of a character or string fragment in the "kallsyms_token_table" array. | `09 54 64 6F  5F E1 F1 66  F5 25 05 54  F3 74 AB 74  0E 54 FF AB` ...
| `kallsyms_markers`       | A lookup table serving to find quickly the approximative offset of a compressed symbol name in "kallsyms_names": every 256 symbols, an offset to the concerned symbol in "kallsyms_names" is added as a long to this table. | `00 00 00 00  03 0C 00 00  0C 18 00 00  1B 24 00 00  0F 31 00 00  DA 3D 00 00  CF 4A 00 00` ...
| `kallsyms_token_table`   | Null-terminated string fragments or characters that may be contained in kernel symbol names. This can contain at most 256 string fragments or characters. Indexes corresponding to ASCII code points which are actually used in any kernel symbol will correspond to the concerned ASCII character, other positions will contain a statistically chosen string fragment. This tool tries to heuristically find this array across the passed file first in order to find the `kallsyms` symbols table. | `73 69 00 67  70 00 74 74  00 79 6E 00  69 6E 74 5F  00 66 72 00  ` ...
| `kallsyms_token_index`   | 256 words, each mapping to the offsets of the characters or string fragments designated by their respective indexes in "kallsyms_token_table". |  `00 00 03 00  06 00 09 00  0C 00 11 00  14 00 1B 00  1E 00 22 00  2C 00 30 00  35 00 38 00` ...

These fields have variable alignment and field size. The field sizes may vary over architecture and kernel version too. For this reason, `vmlinux-to-elf` has been tested over a variety of cases.

OpenWRT [since 2013](https://git.openwrt.org/?p=openwrt/svn-archive/archive.git;a=commit;h=5317e9cb69bb42dee167e0552a5e1f01147ba072) has a [patch](https://github.com/openwrt-mirror/openwrt/blob/9b4650b/target/linux/generic/patches-4.4/203-kallsyms_uncompressed.patch) that removes compression over the `kallsyms` table by default (when building `kallsyms` has been enabled by the user). They do this in order to save space when re-compressing over the kernel using LZMA.

This means that the `kallsyms_token_table` and `kallsyms_token_address` entries disappear, and that the symbol names use plain text ASCII instead. This case is supported too.

## Kernels support
It supports kernels from version 2.6.10 (December 2004) until now. Only kernels explicitly configured without `CONFIG_KALLSYMS` should not be supported. If this kernel configuration variable was not set at build, then you will get: `KallsymsNotFoundException: No embedded symbol table found in this kernel`.

For raw kernels, the following architectures can be detected (using magics from [binwalk](https://github.com/ReFirmLabs/binwalk/blob/master/src/binwalk/magic/binarch)): MIPSEL, MIPSEB, ARMEL, ARMEB, PowerPC, SPARC, x86, x86-64, ARM64, MIPS64, SuperH, ARC.

The following kernel compression formats can be automatically detected: XZ, LZMA, GZip, BZ2, LZ4, LZO and Zstd.

## Advanced usage

You can also obtain a text-only output of the kernel's symbol names, addresses and types through using the `kallsyms-finder` utility, also bundled with this tool. The format of its output will be similar to the `/proc/kallsyms` procfs file.

Some parameters that should be automatically inferred by the tool (such as the instruction set or base address) may be overriden in case of issue. The full specification of the arguments allowing to do that is presented below:

```
$ vmlinux-to-elf -h
usage: vmlinux-to-elf [-h] [--e-machine DECIMAL_NUMBER] [--bit-size BIT_SIZE]
                      [--file-offset HEX_NUMBER] [--base-address HEX_NUMBER]
                      input_file output_file

Turn a raw or compressed kernel binary, or a kernel ELF without symbols, into
a fully analyzable ELF whose symbols were extracted from the kernel symbol
table

positional arguments:
  input_file            Path to the
                        vmlinux/vmlinuz/zImage/bzImage/kernel.bin/kernel.elf
                        file to make into an analyzable .ELF
  output_file           Path to the analyzable .ELF to output

optional arguments:
  -h, --help            show this help message and exit
  --e-machine DECIMAL_NUMBER
                        Force overriding the output ELF "e_machine" field with
                        this integer value (rather than auto-detect)
  --bit-size BIT_SIZE   Force overriding the input kernel bit size, providing
                        32 or 64 bit (rather than auto-detect)
  --file-offset HEX_NUMBER
                        Consider that the raw kernel starts at this offset of
                        the provided raw file or compressed stream (rather
                        than 0, or the beginning of the ELF sections if an ELF
                        header was present in the input)
  --base-address HEX_NUMBER
                        Force overriding the output ELF base address field
                        with this integer value (rather than auto-detect)

$ kallsyms-finder -h
usage: kallsyms-finder [-h] [--bit-size BIT_SIZE] input_file

Find the kernel's embedded symbol table from a raw or stripped ELF kernel
file, and print these to the standard output with their addresses

positional arguments:
  input_file           Path to the kernel file to extract symbols from

optional arguments:
  -h, --help           show this help message and exit
  --bit-size BIT_SIZE  Force overriding the input kernel bit size, providing
                       32 or 64 bit (rather than auto-detect)

```

Don't hesitate to [open an issue](https://github.com/marin-m/vmlinux-to-elf/issues/new) for any suggestion of improvement.







