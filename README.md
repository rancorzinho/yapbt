# YAPBT

Yet Another PE Backdoor Tool is a script to make backdoored PE executables. It uses the `pefile`
Python library for the necessary header modifications. No effort has been made to bypass AV
detection.

This has been done to death but most of the resources I found on this uses Olly and/or manual
patching. I prefer fully automated solutions.

## Usage

Modify `decoder.template` and `shellcode.template` to do what you want and then run:
`./yapbt.py original.exe backdoored.exe`

## How does it work?

This script can backdoor a PE file in two ways:

- Create a new malicious section and change the program's entrypoint to the new section.
- Find a code cave, patch it and change the program's entrypoint to point to the code cave.

## TODOs
- Implement support for `x86_64`.
- Clean up.
- Better log messages.

## References
https://axcheron.github.io/code-injection-with-python/
