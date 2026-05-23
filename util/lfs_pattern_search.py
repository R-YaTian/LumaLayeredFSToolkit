#!/usr/bin/env python3
"""
ARM11 Instruction Pattern Search Script - For searching lfs functions in code.bin
"""

def find_function_start(code, pos):
    """
    Search forward from the given position to find the function start address
    Scans toward lower memory addresses to find PUSH instruction (0xE92D)

    Args:
        code: Binary data
        pos: Current address

    Returns:
        Function start address, returns 0xFFFFFFFF if not found
    """
    while pos >= 4:
        pos -= 4
        # Check if 16-bit value at pos+2 is 0xE92D (PUSH instruction flag)
        if pos + 2 < len(code):
            push_instr = int.from_bytes(code[pos+2:pos+4], 'little')
            if push_instr == 0xE92D:
                return pos
    
    return 0xFFFFFFFF


def search_patterns(filename):
    """
    Search for ARM instruction patterns

    Args:
        filename: Binary file to search

    Returns:
        List of found functions
    """
    # Define function patterns
    patterns = {
        0xE5970010: {
            'name': 'fsMountArchive',
            'checks': lambda code, addr, size: (
                addr <= size - 12 and
                code[addr+4:addr+8] == b'\xD8\x20\xCD\xE1' and
                (int.from_bytes(code[addr+8:addr+12], 'little') & 0xFFFFFF) == 0x008D0000
            )
        },
        0xE24DD028: {
            'name': 'fsMountArchive',
            'checks': lambda code, addr, size: (
                addr <= size - 16 and
                code[addr+4:addr+8] == b'\x00\x40\xA0\xE1' and
                code[addr+8:addr+12] == b'\xA8\xF0\x9F\xE5' and
                code[addr+12:addr+16] == b'\x01\xC0\xA0\xE3'
            )
        },
        0xE2844001: {
            'name': 'fsUnMountArchive',
            'checks': lambda code, addr, size: (
                addr <= size - 12 and
                code[addr+4:addr+8] == b'\x20\x00\x54\xE3' and
                code[addr+8:addr+12] == b'\xF0\xFF\xFF\x3A'
            )
        },
        0xE353003A: {
            'name': 'fsUnMountArchive',
            'checks': lambda code, addr, size: (
                addr <= size - 12 and
                (int.from_bytes(code[addr+4:addr+8], 'little') & 0xFFFFFF0F) == 0x0A000009 and
                (int.from_bytes(code[addr+8:addr+12], 'little') & 0xFFFF0FF0) == 0xE1A00400
            )
        },
        0xE3500008: {
            'name': 'fsRegisterArchive',
            'checks': lambda code, addr, size: (
                addr <= size - 12 and
                (int.from_bytes(code[addr+4:addr+8], 'little') & 0xFFF00FF0) == 0xE1800400 and
                (int.from_bytes(code[addr+8:addr+12], 'little') & 0xFFF00FF0) == 0xE1800FC0
            )
        },
        0xE351003A: {
            'name': 'fsTryOpenFile',
            'checks': lambda code, addr, size: (
                addr <= size - 0x40 and
                code[addr+4:addr+8] == b'\xFC\xFF\xFF\x1A' and
                code[addr+0x34:addr+0x38] == b'\x00\xC0\x90\xE5' and
                code[addr+0x3C:addr+0x40] == b'\x3C\xFF\x2F\xE1'
            )
        },
        0x08030204: {
            'name': 'fsOpenFileDirectly',
            'checks': lambda code, addr, size: True  # Only need to find this instruction
        },
    }
    
    print(f"Reading file: {filename}")
    with open(filename, 'rb') as f:
        code = f.read()

    size = len(code)
    print(f"File size: {size} bytes (0x{size:X})")
    print("\nStarting pattern search...\n")
    
    found_functions = []
    found_count = 0
    found_names = set()  # Track found function names to avoid duplicates

    # Traverse with 4-byte alignment
    addr = 0
    while addr <= size - 4:
        # Read 32-bit value at current address
        instr = int.from_bytes(code[addr:addr+4], 'little')

        # Check if matches any pattern
        if instr in patterns:
            pattern_info = patterns[instr]
            func_name = pattern_info['name']

            # Skip if this function name was already found
            if func_name in found_names:
                addr += 4
                continue

            # Perform check
            try:
                if pattern_info['checks'](code, addr, size):
                    # Find function start address
                    func_start = find_function_start(code, addr)

                    if func_start != 0xFFFFFFFF:
                        found_count += 1
                        found_names.add(func_name)  # Mark this function name as found
                        result = {
                            'name': func_name,
                            'pattern_addr': addr,
                            'func_start': func_start,
                            'pattern': f"0x{instr:08X}"
                        }
                        found_functions.append(result)

                        print(f"[{found_count}] Found function: {func_name}")
                        print(f"    Pattern instruction address: 0x{addr:08X}")
                        print(f"    Function start address:      0x{func_start:08X}")
                        print(f"    Instruction encoding:        {f'0x{instr:08X}'}")
                        print()

                        if found_count >= 5:
                            break
            except Exception as e:
                # Handle boundary check error
                pass
        
        addr += 4

    return found_functions, found_count


def main():
    import sys

    filename = 'code.bin' if len(sys.argv) < 2 else sys.argv[1]

    try:
        found_functions, count = search_patterns(filename)

        print(f"\n{'='*60}")
        print(f"Search complete! Found {count} functions")
        print(f"{'='*60}\n")

        if found_functions:
            print("Found functions list:")
            print(f"{'No.':<5} {'Function Name':<25} {'Start Address':<12} {'Pattern Address':<12}")
            print("-" * 60)
            for i, func in enumerate(found_functions, 1):
                print(f"{i:<5} {func['name']:<25} 0x{func['func_start']:08X}   0x{func['pattern_addr']:08X}")
        else:
            print("No matching functions found")

    except FileNotFoundError:
        print(f"Error: File not found {filename}")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
