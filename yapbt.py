#!/usr/bin/env python3

import pefile
import argparse
from pemodify import *

def main(src_file, dest):
    pe_contents = src_file.read() + b"\x00"*0x2000
    pe = pefile.PE(data=pe_contents)

    #original_size = len(pe_contents)

    #shellcode_virtual_offset, shellcode_raw_offset = new_section(pe, b".pwn", 0x1000)
    #pe.write(dest)

    #pe = pefile.PE(dest)
    #patch_section(pe, shellcode_virtual_offset, shellcode_raw_offset)
    #pe.write(dest)

    patch_code_cave(pe)
    pe.write(dest)

    dump_sections(dest)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Modify PE file")
    parser.add_argument('src_file', type=argparse.FileType("rb", 0), help="PE file to modify")
    parser.add_argument('dest_filename', type=str, default=None, help="PE file to modify")
    args = parser.parse_args()

    main(args.src_file, args.dest_filename)

