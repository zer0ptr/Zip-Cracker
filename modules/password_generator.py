import itertools as its
import string


class PasswordGenerator:
    @staticmethod
    def generate_numeric(length=6):
        """Generate numeric passwords"""
        for num in its.product(string.digits, repeat=length):
            yield ''.join(num)

    @staticmethod
    def from_file(file_path, chunk_size=1000000):
        """Generate passwords from dictionary file in chunks"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                chunk = []
                for line in f:
                    chunk.append(line.strip())
                    if len(chunk) >= chunk_size:
                        yield chunk
                        chunk = []
                if chunk:
                    yield chunk
        except Exception as e:
            raise Exception(f"Failed to load dictionary: {e}")