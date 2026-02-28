import os
import random
import struct

def generate_synthetic_image(filename="synthetic_test.img", size_mb=10):
    print(f"Generating synthetic disk image: {filename} ({size_mb} MB)...")
    
    # 1. Base image setup (10MB total)
    size_bytes = size_mb * 1024 * 1024
    cluster_size = 4096
    total_clusters = size_bytes // cluster_size
    
    data = bytearray(size_bytes)
    
    # 2. Fill with simulated "natural" data (pseudo-random, high entropy but not 1.0)
    # We use a mix of repeating patterns and random bytes to simulate real files
    print("Filling with baseline data...")
    for i in range(0, size_bytes, 8):
        # Semi-natural repeating header-like bytes mixed with random data
        struct.pack_into('<Q', data, i, random.getrandbits(64) & 0xFFFFFFFFFF0000FF | 0x0000000000ABCD00)
        
    for i in range(0, size_bytes, 1024):
        # Inject some text paths to simulate a filesystem
        text = f"C:\\Users\\Admin\\Documents\\finance_report_{i}.pdf".encode()
        data[i:i+len(text)] = text

    # 3. Inject "Zero-Fill Wipe" (Simulate native OS clear or basic wipe)
    # Wipe clusters 500 to 700 with all zeros
    print("Injecting zero-fill wipe (Clusters 500-700)...")
    for i in range(500 * cluster_size, 700 * cluster_size):
        data[i] = 0x00
        
    # 4. Inject "Intentional Random Wipe" (Simulate DBAN / sdelete)
    # Wipe clusters 1500 to 1800 with high-entropy random data and tool signature
    print("Injecting DBAN/sdelete random wipe (Clusters 1500-1800)...")
    for i in range(1500 * cluster_size, 1800 * cluster_size):
        data[i] = random.randint(0, 255)
        
    # Inject signature at the start of the wiped region
    dban_sig = b"DBAN.DOD.5220.22-M"
    data[1500 * cluster_size : 1500 * cluster_size + len(dban_sig)] = dban_sig
    
    # 5. Inject a "Targeted File Wipe" (Simulate specific file destruction)
    # Wipe clusters 2100 to 2150 with a repeating 0xFF pattern (common in focused shredders)
    print("Injecting targeted DoD wipe pattern (Clusters 2100-2150)...")
    for i in range(2100 * cluster_size, 2150 * cluster_size):
        data[i] = 0xFF
        
    # Inject a directory hint right before it so the agent knows what was deleted
    hint_text = b"DELETED: /var/log/auth.log\x00\x00"
    target_cluster = 2099 * cluster_size
    data[target_cluster : target_cluster + len(hint_text)] = hint_text

    # Write to file
    with open(filename, "wb") as f:
        f.write(data)
        
    print(f"Success! Image generated: {os.path.abspath(filename)}")
    print("\nTest Summary for ISEA:")
    print(" - Total Size: 10 MB")
    print(" - Zero Fill: ~800 KB (Natural/OS Clear)")
    print(" - Random Fill: ~1.2 MB (DBAN signature)")
    print(" - Pattern Fill: ~200 KB (0xFF DoD pass)")

if __name__ == "__main__":
    generate_synthetic_image()
