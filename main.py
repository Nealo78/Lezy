#!/usr/bin/env python3
"""
Lezy - Lightweight Exploiter
===============
A simple exploit framework designed for educational purposes.
Features:
- Basic TCP socket operations
- Command execution with shellcode
- Memory dumping capabilities
"""
import io
import sys
import os
import socket
import struct
from ctypes import *

print("""
  ______     ____ _____  _   _
 / ___\ \   / / /|___ \ | \ | |
| |    \ \ / /| || __) ||  \| |
| |___  \ V / | || |_| || |\  |
 \____|  \_/  |_(_)___(_)_| \_|
                                 
Version: 1.0 - Alpha Edition
""")

class LEZYExploit:
    def execute_payload(self, ip, port, payload):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        s.send(payload)
        response = s.recv(1024)
        s.close()
        return response
    
    def dump_memory(self, pid):
        process_handle = windll.kernel32.OpenProcess(0x1F0FFF, False, pid)
        memory_regions = []
        
        class MEMORY_BASIC_INFORMATION(Structure):
            _fields_ = [("BaseAddress", c_void_p),
                       ("AllocationBase", c_void_p),
                       ("AllocationProtect", c_ulong),
                       ("RegionSize", c_size_t),
                       ("State", c_ulong),
                       ("Protect", c_ulong),
                       ("Type", c_ulong)]
        
        mbi = MEMORY_BASIC_INFORMATION()
        size = sizeof(mbi)
        addr = 0
        
        while windll.kernel32.VirtualQueryEx(process_handle, addr, byref(mbi), sizeof(mbi)):
            memory_regions.append(mbi)
            addr += mbi.RegionSize
            
        windll.kernel32.CloseHandle.process_handle
        return memory_regions

def usage():
    print("USAGE:")
    print("  python3 lezy.py --exploit <options>")
    print("  python3 lezy.py --dump <options>\n")
    
    print("EXPLOIT OPTIONS:")
    print("  --shellcode <file>     Specify path to shellcode file")
    print("  --target-ip <address>  Target IP address")
    print("  --target-port <number> Target port number\n")
    
    print("MEMORY DUMP OPTIONS:")
    print("  --pid <number>         Process ID to target")
    print("  --output-file <file>   Output file for dumped memory")

def main():
    if len(sys.argv) < 2:
        usage()
        return
        
    lezy = LEZYExploit()
    
    if "--exploit" in sys.argv:
        idx = sys.argv.index("--exploit")
        if len(sys.argv) >= idx+5:
            shellcode_path = sys.argv[idx+2]
            target_ip = sys.argv[idx+4]
            target_port = int(sys.argv[idx+6])
            
            with open(shellcode_path, "rb") as f:
                shellcode = f.read()
                
            print("[+] Executing payload...")
            response = lezy.execute_payload(target_ip, target_port, shellcode)
            print("[+] Response received:", response)
        else:
            print("[-] Missing exploit parameters")
            
    elif "--dump" in sys.argv:
        idx = sys.argv.index("--dump")
        if len(sys.argv) >= idx+4:
            pid = int(sys.argv[idx+2])
            output_file = sys.argv[idx+4]
            
            print("[+] Dumping process memory...")
            regions = lezy.dump_memory(pid)
            
            with open(output_file, "wb") as f:
                for region in regions:
                    f.write(region.BaseAddress)
                    
            print(f"[+] Dump completed. Saved {len(regions)} regions to {output_file}")
        else:
            print("[-] Missing dump parameters")
    else:
        usage()

if __name__ == "__main__":
    main()