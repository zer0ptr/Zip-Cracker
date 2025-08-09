import zipfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from .password_generator import PasswordGenerator
from .crc_cracker import CRCCracker
from .progress_display import ProgressDisplay
from .utils import get_cpu_count


class BruteForce:
    def __init__(self, zip_file, dict_file):
        self.zip_file = zip_file
        self.dict_file = dict_file
        self.status = {
            "stop": False,
            "tried_passwords": [],
            "lock": threading.Lock(),
            "total_passwords": 0
        }

    def start_attack(self):
        """Start brute force attack"""
        # First try CRC attack if small files exist
        if self._try_crc_attack():
            return

        # Then proceed with dictionary attack
        self._run_dictionary_attack()

    def _try_crc_attack(self):
        """Attempt CRC32 attack on small files"""
        with zipfile.ZipFile(self.zip_file) as zf:
            for filename in zf.namelist():
                if filename.endswith('/'):
                    continue
                info = zf.getinfo(filename)
                if info.file_size <= 6:
                    print(f"[!] Found small file {filename} ({info.file_size} bytes)")
                    choice = input("Attempt CRC32 collision attack? (y/n): ")
                    if choice.lower() == 'y':
                        result = CRCCracker.crack(filename, info.CRC, info.file_size)
                        if result:
                            return True
        return False

    def _run_dictionary_attack(self):
        """Run dictionary-based brute force attack"""
        # Calculate total passwords
        total = self._count_passwords()
        self.status["total_passwords"] = total
        print(f"[+] Total passwords to try: {total}")

        # Start progress display
        progress = ProgressDisplay(self.status)
        progress.start()

        try:
            # Start attack
            self._attack_with_threads()
        finally:
            self.status["stop"] = True
            progress.join()

    def _count_passwords(self):
        """Count passwords in dictionary"""
        count = 0
        try:
            with open(self.dict_file, 'r', encoding='utf-8', errors='ignore') as f:
                count = sum(1 for _ in f)
        except Exception as e:
            print(f"[!] Error counting passwords: {e}")

        # Add numeric passwords (0-6 digits)
        count += sum(10 ** i for i in range(1, 7))
        return count

    def _attack_with_threads(self):
        """Run attack with thread pool"""
        max_threads = min(128, get_cpu_count() * 4)
        print(f"[+] Using {max_threads} threads")

        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            # Try dictionary passwords
            for chunk in PasswordGenerator.from_file(self.dict_file):
                self._process_chunk(executor, chunk)
                if self.status["stop"]:
                    return

            # Try numeric passwords
            for length in range(1, 7):
                chunk = list(PasswordGenerator.generate_numeric(length))
                self._process_chunk(executor, chunk)
                if self.status["stop"]:
                    return

    def _process_chunk(self, executor, chunk):
        """Process a chunk of passwords"""
        futures = {
            executor.submit(self._try_password, password): password
            for password in chunk
        }

        for future in as_completed(futures):
            if future.result():
                self.status["stop"] = True
                return

    def _try_password(self, password):
        """Try a single password"""
        if self.status["stop"]:
            return False

        try:
            with zipfile.ZipFile(self.zip_file) as zf:
                zf.setpassword(password.encode())
                zf.testzip()
                zf.extractall()
                print(f"\n[*] Success! Password: {password}")
                print(f"[*] Extracted files: {zf.namelist()}")
                return True
        except:
            with self.status["lock"]:
                self.status["tried_passwords"].append(password)
            return False