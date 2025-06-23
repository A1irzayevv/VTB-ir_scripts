#!/usr/bin/env python3
import math
import argparse
import os

def entropy(data):
    if not data:
        return 0
    byte_freq = [0] * 256
    for b in data:
        byte_freq[b] += 1
    data_len = len(data)
    return -sum((f / data_len) * math.log2(f / data_len) for f in byte_freq if f != 0)

def check_file(path, threshold=7.0, chunk_size=1024*1024):
    try:
        with open(path, "rb") as f:
            data = f.read(chunk_size)
        e = entropy(data)
        status = "POSSIBLY ENCRYPTED" if e >= threshold else "Normal"
        print(f"{path}: Entropy = {e:.2f} → {status}")
    except Exception as e:
        print(f"{path}: ERROR - {e}")

def main():
    parser = argparse.ArgumentParser(description="Entropy scanner for potential ransomware detection.")
    parser.add_argument("files", nargs="+", help="Files or directories to scan")
    parser.add_argument("-t", "--threshold", type=float, default=7.0, help="Entropy threshold for encryption warning")
    parser.add_argument("-r", "--recursive", action="store_true", help="Recursively scan directories")

    args = parser.parse_args()
    targets = []

    for path in args.files:
        if os.path.isdir(path) and args.recursive:
            for root, _, files in os.walk(path):
                for f in files:
                    targets.append(os.path.join(root, f))
        elif os.path.isfile(path):
            targets.append(path)
        else:
            print(f"Skipping: {path} (not found or not a file)")

    for file_path in targets:
        check_file(file_path, args.threshold)

if __name__ == "__main__":
    main()
