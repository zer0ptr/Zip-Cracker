import binascii
import itertools as its
import string

class CRCCracker:
    @staticmethod
    def crack(filename, crc, size):
        """Attempt CRC32 collision attack"""
        dic = its.product(string.printable, repeat=size)
        print(f"[+] Starting CRC32 collision attack for {filename}...")
        for s in dic:
            s = ''.join(s).encode()
            if crc == binascii.crc32(s):
                print(f'[*] Found content: {s.decode()}')
                return s.decode()
        return None