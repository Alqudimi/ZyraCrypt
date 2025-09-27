
import json
import os
from datetime import datetime, timedelta
from typing import Dict, Any

class SecureKeyStore:
    def __init__(self, storage_path: str = "./key_store.json"):
        self.storage_path = storage_path
        self.keys: Dict[str, Dict[str, Any]] = self._load_keys()

    def _load_keys(self) -> Dict[str, Dict[str, Any]]:
        if os.path.exists(self.storage_path):
            with open(self.storage_path, "r") as f:
                return json.load(f)
        return {}

    def _save_keys(self):
        with open(self.storage_path, "w") as f:
                json.dump(self.keys, f, indent=4)

    def store_key(self, key_id: str, key_material: bytes, expiration_days: int = None):
        """Stores a key securely with an optional expiration date."""
        expiration_date = None
        if expiration_days:
            expiration_date = (datetime.now() + timedelta(days=expiration_days)).isoformat()

        self.keys[key_id] = {
            "key_material": key_material.hex(), # Store as hex string
            "expiration_date": expiration_date,
            "created_at": datetime.now().isoformat()
        }
        self._save_keys()

    def get_key(self, key_id: str) -> bytes:
        """Retrieves a key, checking for expiration."""
        key_info = self.keys.get(key_id)
        if not key_info:
            raise ValueError(f"Key with ID {key_id} not found.")

        if key_info["expiration_date"]:
            if datetime.now() > datetime.fromisoformat(key_info["expiration_date"]):
                raise ValueError(f"Key with ID {key_id} has expired.")
        
        return bytes.fromhex(key_info["key_material"])

    def delete_key(self, key_id: str):
        """Deletes a key from the store."""
        if key_id in self.keys:
            del self.keys[key_id]
            self._save_keys()
        else:
            raise ValueError(f"Key with ID {key_id} not found.")

    def list_keys(self) -> Dict[str, Any]:
        """Lists all stored keys (excluding key material)."""
        return {k: {"expiration_date": v["expiration_date"], "created_at": v["created_at"]} for k, v in self.keys.items()}


