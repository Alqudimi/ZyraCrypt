#!/usr/bin/env python3
"""
ZyraCrypt Example: Basic Encryption Operations
Demonstrates: Core symmetric and asymmetric encryption functionality
Skill Level: Beginner
"""

import os
import sys
import time
from typing import Tuple

# Add ZyraCrypt to path for development/testing
try:
    from zyracrypt.encryption_system.src.core_cryptography.symmetric_encryption import SymmetricEncryption
    from zyracrypt.encryption_system.src.core_cryptography.asymmetric_encryption import AsymmetricEncryption
    from zyracrypt.encryption_system.src.core_cryptography.encryption_framework import EncryptionFramework
except ImportError as e:
    print(f"❌ Import Error: {e}")
    print("Make sure ZyraCrypt is installed: pip install zyracrypt")
    sys.exit(1)


def demonstrate_symmetric_encryption():
    """Demonstrate AES-GCM and ChaCha20-Poly1305 symmetric encryption."""
    print("\n🔐 === Symmetric Encryption Examples ===")
    
    # Initialize symmetric encryption
    sym_enc = SymmetricEncryption()
    
    # Generate a secure 256-bit key
    key = os.urandom(32)
    print(f"🔑 Generated 256-bit key: {key[:8].hex()}...")
    
    # Test data
    plaintext = b"Hello, ZyraCrypt! This is a secret message."
    print(f"📝 Original message: {plaintext.decode()}")
    
    print("\n--- AES-GCM Encryption ---")
    start_time = time.time()
    
    # Encrypt with AES-GCM
    iv, ciphertext, tag = sym_enc.encrypt_aes_gcm(key, plaintext)
    encrypt_time = time.time() - start_time
    
    print(f"🛡️ IV (12 bytes): {iv.hex()}")
    print(f"🔒 Ciphertext: {ciphertext.hex()}")
    print(f"🏷️ Authentication tag: {tag.hex()}")
    print(f"⏱️ Encryption time: {encrypt_time:.4f} seconds")
    
    # Decrypt with AES-GCM
    start_time = time.time()
    decrypted = sym_enc.decrypt_aes_gcm(key, iv, ciphertext, tag)
    decrypt_time = time.time() - start_time
    
    print(f"✅ Decrypted message: {decrypted.decode()}")
    print(f"⏱️ Decryption time: {decrypt_time:.4f} seconds")
    print(f"✓ Message integrity: {'VERIFIED' if decrypted == plaintext else 'FAILED'}")
    
    print("\n--- ChaCha20-Poly1305 Encryption ---")
    start_time = time.time()
    
    # Encrypt with ChaCha20-Poly1305
    nonce, ciphertext2, tag2 = sym_enc.encrypt_chacha20_poly1305(key, plaintext)
    encrypt_time2 = time.time() - start_time
    
    print(f"🛡️ Nonce (12 bytes): {nonce.hex()}")
    print(f"🔒 Ciphertext: {ciphertext2.hex()}")
    print(f"🏷️ Authentication tag: {tag2.hex()}")
    print(f"⏱️ Encryption time: {encrypt_time2:.4f} seconds")
    
    # Decrypt with ChaCha20-Poly1305
    start_time = time.time()
    decrypted2 = sym_enc.decrypt_chacha20_poly1305(key, nonce, ciphertext2, tag2)
    decrypt_time2 = time.time() - start_time
    
    print(f"✅ Decrypted message: {decrypted2.decode()}")
    print(f"⏱️ Decryption time: {decrypt_time2:.4f} seconds")
    print(f"✓ Message integrity: {'VERIFIED' if decrypted2 == plaintext else 'FAILED'}")


def demonstrate_asymmetric_encryption():
    """Demonstrate RSA and ECC asymmetric encryption."""
    print("\n🔐 === Asymmetric Encryption Examples ===")
    
    # Initialize asymmetric encryption
    asym_enc = AsymmetricEncryption()
    
    # Test data (smaller for RSA)
    plaintext = b"Secret message for public key encryption!"
    print(f"📝 Original message: {plaintext.decode()}")
    
    print("\n--- RSA-2048 Encryption ---")
    start_time = time.time()
    
    # Generate RSA key pair
    rsa_private_key, rsa_public_key = asym_enc.generate_rsa_key_pair(2048)
    keygen_time = time.time() - start_time
    print(f"🔑 RSA key pair generated in {keygen_time:.4f} seconds")
    
    # Encrypt with RSA public key
    start_time = time.time()
    rsa_ciphertext = asym_enc.encrypt_rsa_oaep(rsa_public_key, plaintext)
    encrypt_time = time.time() - start_time
    
    print(f"🔒 RSA ciphertext length: {len(rsa_ciphertext)} bytes")
    print(f"⏱️ Encryption time: {encrypt_time:.4f} seconds")
    
    # Decrypt with RSA private key
    start_time = time.time()
    rsa_decrypted = asym_enc.decrypt_rsa_oaep(rsa_private_key, rsa_ciphertext)
    decrypt_time = time.time() - start_time
    
    print(f"✅ Decrypted message: {rsa_decrypted.decode()}")
    print(f"⏱️ Decryption time: {decrypt_time:.4f} seconds")
    print(f"✓ Message integrity: {'VERIFIED' if rsa_decrypted == plaintext else 'FAILED'}")
    
    print("\n--- ECC Digital Signature ---")
    start_time = time.time()
    
    # Generate ECC key pair
    ecc_private_key, ecc_public_key = asym_enc.generate_ecc_key_pair()
    keygen_time = time.time() - start_time
    print(f"🔑 ECC key pair generated in {keygen_time:.4f} seconds")
    
    # Sign message with ECC private key
    start_time = time.time()
    signature = asym_enc.sign_ecc(ecc_private_key, plaintext)
    sign_time = time.time() - start_time
    
    print(f"✍️ ECC signature length: {len(signature)} bytes")
    print(f"⏱️ Signing time: {sign_time:.4f} seconds")
    
    # Verify signature with ECC public key
    start_time = time.time()
    is_valid = asym_enc.verify_ecc(ecc_public_key, plaintext, signature)
    verify_time = time.time() - start_time
    
    print(f"✓ Signature verification: {'VALID' if is_valid else 'INVALID'}")
    print(f"⏱️ Verification time: {verify_time:.4f} seconds")


def demonstrate_encryption_framework():
    """Demonstrate the intelligent encryption framework."""
    print("\n🔐 === Encryption Framework (Auto Algorithm Selection) ===")
    
    # Initialize encryption framework
    framework = EncryptionFramework()
    
    # Generate key for framework
    key = os.urandom(32)
    
    # Test messages of different sizes
    test_messages = [
        b"Short message",
        b"Medium length message with more content to demonstrate algorithm selection",
        b"Very long message " * 100 + b" that exceeds typical thresholds for algorithm selection"
    ]
    
    for i, message in enumerate(test_messages, 1):
        print(f"\n--- Test Message {i} ({len(message)} bytes) ---")
        print(f"📝 Message preview: {message[:50].decode()}{'...' if len(message) > 50 else ''}")
        
        # Encrypt using framework (automatic algorithm selection)
        start_time = time.time()
        algorithm, iv, ciphertext, tag = framework.encrypt(message, key)
        encrypt_time = time.time() - start_time
        
        print(f"🤖 Selected algorithm: {algorithm}")
        print(f"🛡️ IV/Nonce: {iv.hex()}")
        print(f"🔒 Ciphertext length: {len(ciphertext)} bytes")
        print(f"🏷️ Tag: {tag.hex()}")
        print(f"⏱️ Encryption time: {encrypt_time:.4f} seconds")
        
        # Decrypt using framework
        start_time = time.time()
        if algorithm == "aes_gcm":
            decrypted = framework.symmetric.decrypt_aes_gcm(key, iv, ciphertext, tag)
        elif algorithm == "chacha20_poly1305":
            decrypted = framework.symmetric.decrypt_chacha20_poly1305(key, iv, ciphertext, tag)
        else:
            print(f"❌ Unknown algorithm: {algorithm}")
            continue
        
        decrypt_time = time.time() - start_time
        
        print(f"✅ Decryption successful: {len(decrypted)} bytes")
        print(f"⏱️ Decryption time: {decrypt_time:.4f} seconds")
        print(f"✓ Message integrity: {'VERIFIED' if decrypted == message else 'FAILED'}")


def demonstrate_key_security():
    """Demonstrate secure key handling practices."""
    print("\n🔐 === Secure Key Management ===")
    
    print("🔑 Key Generation Best Practices:")
    
    # Generate different key sizes
    key_sizes = [16, 24, 32]  # 128, 192, 256 bits
    
    for size in key_sizes:
        key = os.urandom(size)
        print(f"   • {size * 8}-bit key: {key.hex()}")
    
    print("\n🛡️ Key Storage Recommendations:")
    print("   • Use environment variables for application keys")
    print("   • Store keys in secure key management systems (KMS)")
    print("   • Never hardcode keys in source code")
    print("   • Use key derivation functions for password-based keys")
    print("   • Implement key rotation policies")
    
    print("\n⚠️ Key Security Warnings:")
    print("   • Keys shown here are for demonstration only")
    print("   • Generate new keys for each application")
    print("   • Use different keys for different purposes")
    print("   • Protect keys with same security level as encrypted data")


def main():
    """Main function to run all basic encryption examples."""
    print("🚀 ZyraCrypt Basic Encryption Examples")
    print("=" * 50)
    
    try:
        # Run all demonstrations
        demonstrate_symmetric_encryption()
        demonstrate_asymmetric_encryption()
        demonstrate_encryption_framework()
        demonstrate_key_security()
        
        print("\n" + "=" * 50)
        print("✅ All basic encryption examples completed successfully!")
        print("\n📚 Next Steps:")
        print("   • Try advanced_encryption.py for enterprise features")
        print("   • Explore post_quantum_examples.py for quantum-resistant crypto")
        print("   • Check out performance_benchmarks.py for optimization")
        
        return 0
        
    except Exception as e:
        print(f"\n❌ Error during example execution: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())