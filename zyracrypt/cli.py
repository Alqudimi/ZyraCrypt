#!/usr/bin/env python3
"""
Simple CLI interface for the Alqudimi Encryption System
"""

def main():
    """Main CLI entry point"""
    print("Alqudimi Encryption System v2.0.0")
    print("Enterprise-grade cryptographic library")
    print("For API usage, import the modules in your Python code.")
    
    # Simple test to verify the library works
    try:
        from alqudimi_encryption_system.encryption_system.src.core_cryptography.symmetric_encryption import SymmetricEncryption
        crypto = SymmetricEncryption()
        print("✓ Core encryption modules available")
        print("Library installation successful!")
    except Exception as e:
        print(f"✗ Error loading encryption modules: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    import sys
    sys.exit(main())