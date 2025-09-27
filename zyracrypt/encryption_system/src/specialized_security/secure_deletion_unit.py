
import os

class SecureDeletionUnit:
    def __init__(self):
        pass

    def _overwrite_file(self, filepath: str, passes: int, block_size: int = 4096, overwrite_byte: bytes = None):
        """Overwrites a file with random data or a specific byte multiple times."""
        file_size = os.path.getsize(filepath)
        with open(filepath, "r+b") as f:
            for _ in range(passes):
                f.seek(0) # Go to the beginning of the file
                remaining_bytes = file_size
                while remaining_bytes > 0:
                    write_size = min(remaining_bytes, block_size)
                    if overwrite_byte:
                        f.write(overwrite_byte * write_size)
                    else:
                        f.write(os.urandom(write_size))
                    remaining_bytes -= write_size
            f.flush()
            os.fsync(f.fileno()) # Ensure data is written to disk

    def dod_5220_22_m_erase(self, filepath: str):
        """Securely erases a file using DoD 5220.22-M standard (3 passes)."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")

        # Pass 1: Overwrite with a character (e.g., 0x00)
        self._overwrite_file(filepath, 1, overwrite_byte=b'\x00')
        
        # Pass 2: Overwrite with the complement of the character (e.g., 0xFF)
        self._overwrite_file(filepath, 1, overwrite_byte=b'\xff')

        # Pass 3: Overwrite with random characters and verify
        self._overwrite_file(filepath, 1) # Random data

        # Rename and delete the file
        try:
            os.remove(filepath)
        except OSError as e:
            print(f"Error deleting file {filepath}: {e}")


