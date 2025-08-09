import zipfile
import os
import shutil


class ZipAnalyzer:
    def __init__(self, zip_path):
        self.zip_path = zip_path

    def is_encrypted(self):
        """Check if ZIP is encrypted"""
        with zipfile.ZipFile(self.zip_path) as zf:
            for info in zf.infolist():
                if info.flag_bits & 0x1:
                    return True
        return False

    def has_fake_encryption(self):
        """Check for fake encryption"""
        try:
            with zipfile.ZipFile(self.zip_path) as zf:
                zf.testzip()
            return False
        except RuntimeError as e:
            if "encrypted" in str(e):
                return True
            return False

    def fix_fake_encryption(self):
        """Fix fake encrypted ZIP"""
        temp_path = self.zip_path + ".tmp"
        with zipfile.ZipFile(self.zip_path) as zf, zipfile.ZipFile(temp_path, "w") as temp_zf:
            for info in zf.infolist():
                if info.flag_bits & 0x1:
                    info.flag_bits ^= 0x1
                temp_zf.writestr(info, zf.read(info.filename))

        fixed_path = os.path.join(os.path.dirname(self.zip_path), "fixed_" + os.path.basename(self.zip_path))
        try:
            shutil.move(temp_path, fixed_path)
        except Exception:
            os.remove(fixed_path)
            shutil.move(temp_path, fixed_path)

        return fixed_path