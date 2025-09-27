
from PIL import Image
import os

class SteganographyUnit:
    def __init__(self):
        pass

    def _bytes_to_binary(self, data: bytes) -> str:
        """Converts bytes to a binary string."""
        return "".join(format(byte, "08b") for byte in data)

    def _binary_to_bytes(self, binary_string: str) -> bytes:
        """Converts a binary string to bytes."""
        byte_array = bytearray()
        for i in range(0, len(binary_string), 8):
            byte_array.append(int(binary_string[i:i+8], 2))
        return bytes(byte_array)

    def embed_data(self, image_path: str, data: bytes, output_path: str):
        """Embeds data into an image using LSB (Least Significant Bit) method."""
        img = Image.open(image_path).convert("RGB")
        width, height = img.size
        pixels = img.load()

        # Add a delimiter to mark the end of the data
        data_to_embed = data + b"#####END#####"
        binary_data = self._bytes_to_binary(data_to_embed)
        data_len = len(binary_data)

        if data_len > width * height * 3: # Each pixel has 3 color channels (R, G, B)
            raise ValueError("Data is too large to embed in the image.")

        data_index = 0
        for y in range(height):
            for x in range(width):
                r, g, b = pixels[x, y]

                if data_index < data_len:
                    r = (r & 0xFE) | int(binary_data[data_index])
                    data_index += 1
                if data_index < data_len:
                    g = (g & 0xFE) | int(binary_data[data_index])
                    data_index += 1
                if data_index < data_len:
                    b = (b & 0xFE) | int(binary_data[data_index])
                    data_index += 1
                
                pixels[x, y] = (r, g, b)

                if data_index >= data_len:
                    break
            if data_index >= data_len:
                break

        img.save(output_path)

    def extract_data(self, image_path: str) -> bytes:
        """Extracts embedded data from an image."""
        img = Image.open(image_path).convert("RGB")
        width, height = img.size
        pixels = img.load()

        extracted_binary_data = []
        for y in range(height):
            for x in range(width):
                r, g, b = pixels[x, y]
                extracted_binary_data.append(str(r & 1))
                extracted_binary_data.append(str(g & 1))
                extracted_binary_data.append(str(b & 1))
        binary_string = "".join(extracted_binary_data)
        extracted_bytes = self._binary_to_bytes(binary_string)

        # Find the delimiter
        delimiter = b"#####END#####"
        try:
            end_index = extracted_bytes.index(delimiter)
            return extracted_bytes[:end_index]
        except ValueError:
            raise ValueError("No embedded data or delimiter not found.")


