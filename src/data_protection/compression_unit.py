

import zlib

class CompressionUnit:
    def __init__(self):
        pass

    def compress_data(self, data: bytes) -> bytes:
        """Compresses data using zlib."""
        return zlib.compress(data)

    def decompress_data(self, data: bytes) -> bytes:
        """Decompresses data using zlib."""
        return zlib.decompress(data)


