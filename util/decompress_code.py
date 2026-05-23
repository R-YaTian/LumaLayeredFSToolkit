#!/usr/bin/env python3
"""
BLZ Decompression Script - For decompressing code.bin files
"""

def blz_decompress(input_data):
    """
    BLZ Decompression Algorithm

    Args:
        input_data: Compressed data (bytes)

    Returns:
        Decompressed data (bytes)
    """
    delta_size = int.from_bytes(input_data[-4:], 'little')
    ranges = int.from_bytes(input_data[-8:-4], 'little')
    current_out = len(input_data) + delta_size
    current_in = len(input_data) - (ranges >> 24)
    end = len(input_data) - (ranges & 0xFFFFFF)
    buffer = [b'\0'] * (len(input_data) + delta_size)
    buffer[:len(input_data)] = input_data

    while current_in > end:
        current_in -= 1
        control = buffer[current_in]
        for _ in range(8):
            if control & 0x80:
                current_in -= 1
                b1 = buffer[current_in]
                current_in -= 1
                b2 = buffer[current_in]
                index = ((b2 | (int(b1) << 8)) & 0xFFFF0FFF) + 2
                loops = (b1 >> 4) + 2
                while True:
                    b = buffer[current_out + index]
                    current_out -= 1
                    buffer[current_out] = b
                    loops -= 1
                    if loops < 0:
                        break
            else:
                current_out -= 1
                current_in -= 1
                buffer[current_out] = buffer[current_in]

            control = (control << 1) & 0xFF
            if current_in <= end:
                return bytes(buffer)

    return bytes(buffer)


def decompress_file(input_file, output_file):
    """
    Decompress a file

    Args:
        input_file: Input file path
        output_file: Output file path
    """
    print(f"Reading file: {input_file}")
    with open(input_file, 'rb') as f:
        compressed_data = f.read()

    print(f"File size: {len(compressed_data)} bytes")
    print("Decompressing...")
    
    decompressed_data = blz_decompress(compressed_data)

    print(f"Decompression complete! Decompressed size: {len(decompressed_data)} bytes")
    print(f"Compression ratio: {len(compressed_data) / len(decompressed_data) * 100:.2f}%")
    
    print(f"Saving file: {output_file}")
    with open(output_file, 'wb') as f:
        f.write(decompressed_data)

    print("Done!")


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1:
        input_file = sys.argv[1]
        output_file = sys.argv[2] if len(sys.argv) > 2 else input_file + '.decompressed'
    else:
        input_file = 'code.bin'
        output_file = 'code.bin.decompressed'

    try:
        decompress_file(input_file, output_file)
    except FileNotFoundError:
        print(f"Error: File not found {input_file}")
    except Exception as e:
        print(f"Error: {e}")
