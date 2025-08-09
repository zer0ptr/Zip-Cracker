#!/usr/bin/env python3
import sys
import os
from modules.zip_analyzer import ZipAnalyzer
from modules.brute_force import BruteForce
from modules.utils import print_banner
import threading


def main():
    print_banner()

    if len(sys.argv) == 1:
        print("[*] Usage 1 (built-in dictionary): python main.py YourZipFile.zip")
        print("[*] Usage 2 (custom dictionary): python main.py YourZipFile.zip YourDict.txt")
        sys.exit(0)

    zip_file = sys.argv[1]
    dict_file = sys.argv[2] if len(sys.argv) > 2 else 'password_list.txt'

    analyzer = ZipAnalyzer(zip_file)
    brute_force = BruteForce(zip_file, dict_file)

    if analyzer.is_encrypted():
        if analyzer.has_fake_encryption():
            fixed_zip = analyzer.fix_fake_encryption()
            print(f"[*] Fixed fake encryption. Created: {fixed_zip}")
            sys.exit(0)

        print("[+] Starting attack...")
        brute_force.start_attack()
    else:
        print("[!] ZIP file is not encrypted, can be extracted directly.")


if __name__ == '__main__':
    main()