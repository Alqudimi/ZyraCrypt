
import json
import xml.etree.ElementTree as ET
from typing import Union

class DataTypeManager:
    def __init__(self):
        pass

    def serialize(self, data: Union[str, bytes, dict, ET.Element]) -> bytes:
        """Serializes various data types into bytes for encryption."""
        if isinstance(data, str):
            return data.encode("utf-8")
        elif isinstance(data, bytes):
            return data
        elif isinstance(data, dict):
            return json.dumps(data).encode("utf-8")
        elif isinstance(data, ET.Element):
            return ET.tostring(data, encoding="utf-8")
        else:
            raise TypeError(f"Unsupported data type for serialization: {type(data)}")

    def deserialize(self, data_bytes: bytes, original_type: str) -> Union[str, bytes, dict, ET.Element]:
        """Deserializes bytes back to their original data type."""
        if original_type == "str":
            return data_bytes.decode("utf-8")
        elif original_type == "bytes":
            return data_bytes
        elif original_type == "dict":
            return json.loads(data_bytes.decode("utf-8"))
        elif original_type == "xml":
            return ET.fromstring(data_bytes.decode("utf-8"))
        else:
            raise ValueError(f"Unsupported original_type for deserialization: {original_type}")

    def get_type_name(self, data: Union[str, bytes, dict, ET.Element]) -> str:
        """Returns a string representation of the data type."""
        if isinstance(data, str):
            return "str"
        elif isinstance(data, bytes):
            return "bytes"
        elif isinstance(data, dict):
            return "dict"
        elif isinstance(data, ET.Element):
            return "xml"
        else:
            raise TypeError(f"Unsupported data type: {type(data)}")




    def detect_data_type(self, data_bytes: bytes) -> str:
        """Detects the type of data (JSON, XML, TEXT, BINARY)."""
        try:
            json.loads(data_bytes.decode("utf-8"))
            return "JSON"
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

        try:
            ET.fromstring(data_bytes.decode("utf-8"))
            return "XML"
        except (ET.ParseError, UnicodeDecodeError):
            pass

        # Heuristic for text vs binary
        # Check for a high proportion of printable ASCII characters
        printable_chars = sum(1 for byte in data_bytes if 32 <= byte <= 126 or byte in [9, 10, 13])
        if len(data_bytes) > 0 and (printable_chars / len(data_bytes)) > 0.8:
            return "TEXT"
        
        return "BINARY"


