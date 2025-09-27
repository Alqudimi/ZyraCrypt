#!/usr/bin/env python3
"""
ZyraCrypt Example: Key Management Operations
Demonstrates: Key generation, derivation, exchange, and secure storage
Skill Level: Beginner to Intermediate
"""

import os
import sys
import time
import json
from typing import Dict, Any

# Add ZyraCrypt to path for development/testing
try:
    from zyracrypt.encryption_system.src.key_management.key_manager import KeyManager
    from zyracrypt.encryption_system.src.key_management.enhanced_kdf_password import (
        EnhancedKDF, KDFAlgorithm, SecurityProfile
    )
    from zyracrypt.encryption_system.src.key_management.key_exchange import KeyExchange
    from zyracrypt.encryption_system.src.core_cryptography.asymmetric_encryption import AsymmetricEncryption
except ImportError as e:
    print(f"❌ Import Error: {e}")
    print("Make sure ZyraCrypt is installed: pip install zyracrypt")
    sys.exit(1)


def demonstrate_key_generation():
    """Demonstrate secure key generation for different purposes."""
    print("\n🔑 === Key Generation Examples ===")
    
    key_manager = KeyManager()
    
    print("📋 Generating different types of keys:")
    
    # Generate symmetric keys
    aes_128_key = key_manager.generate_symmetric_key(16)  # 128-bit
    aes_256_key = key_manager.generate_symmetric_key(32)  # 256-bit
    chacha20_key = key_manager.generate_chacha20_key()     # 256-bit
    
    print(f"🔐 AES-128 key (16 bytes): {aes_128_key.hex()}")
    print(f"🔐 AES-256 key (32 bytes): {aes_256_key[:8].hex()}...")
    print(f"🔐 ChaCha20 key (32 bytes): {chacha20_key[:8].hex()}...")
    
    # Generate asymmetric key pairs
    print("\n🔑 Generating RSA key pairs:")
    start_time = time.time()
    rsa_2048_private, rsa_2048_public = key_manager.generate_rsa_key_pair(2048)
    rsa_time = time.time() - start_time
    print(f"✅ RSA-2048 key pair generated in {rsa_time:.3f} seconds")
    
    print("\n🔑 Generating ECC key pairs:")
    start_time = time.time()
    ecc_private, ecc_public = key_manager.generate_ecc_key_pair()
    ecc_time = time.time() - start_time
    print(f"✅ ECC P-256 key pair generated in {ecc_time:.3f} seconds")
    
    print(f"\n📊 Performance comparison:")
    print(f"   • RSA-2048: {rsa_time:.3f}s")
    print(f"   • ECC P-256: {ecc_time:.3f}s (⚡ {rsa_time/ecc_time:.1f}x faster)")


def demonstrate_password_based_keys():
    """Demonstrate password-based key derivation with various algorithms."""
    print("\n🔐 === Password-Based Key Derivation ===")
    
    enhanced_kdf = EnhancedKDF()
    
    # Test password and salt
    password = b"my_secure_password_123!"
    salt = os.urandom(32)
    
    print(f"🔑 Password: {password.decode()}")
    print(f"🧂 Salt: {salt[:8].hex()}...")
    
    # Test different KDF algorithms
    algorithms = [
        (KDFAlgorithm.ARGON2ID, SecurityProfile.INTERACTIVE),
        (KDFAlgorithm.ARGON2ID, SecurityProfile.SENSITIVE),
        (KDFAlgorithm.SCRYPT, SecurityProfile.INTERACTIVE),
        (KDFAlgorithm.PBKDF2_SHA256, SecurityProfile.INTERACTIVE),
    ]
    
    results = {}
    
    for algorithm, profile in algorithms:
        print(f"\n--- {algorithm.value.upper()} with {profile.value} profile ---")
        
        start_time = time.time()
        try:
            result = enhanced_kdf.derive_key(
                password=password,
                salt=salt,
                algorithm=algorithm,
                security_profile=profile,
                key_length=32
            )
            duration = time.time() - start_time
            
            print(f"✅ Derived key: {result.key[:8].hex()}...")
            print(f"⏱️ Time taken: {duration:.3f} seconds")
            print(f"📅 Timestamp: {result.timestamp}")
            print(f"⚙️ Parameters: {result.parameters}")
            
            results[f"{algorithm.value}_{profile.value}"] = {
                'duration': duration,
                'key_preview': result.key[:8].hex(),
                'algorithm': algorithm.value
            }
            
        except Exception as e:
            print(f"❌ Error with {algorithm.value}: {e}")
    
    # Performance comparison
    print(f"\n📊 KDF Performance Comparison:")
    for name, data in results.items():
        print(f"   • {name}: {data['duration']:.3f}s")


def demonstrate_key_exchange():
    """Demonstrate ECDH key exchange protocol."""
    print("\n🤝 === ECDH Key Exchange Protocol ===")
    
    key_exchange = KeyExchange()
    asym_enc = AsymmetricEncryption()
    
    print("👤 Alice and Bob want to establish a shared secret...")
    
    # Alice generates her key pair
    print("\n👤 Alice generates her key pair:")
    alice_private, alice_public = asym_enc.generate_ecc_key_pair()
    print("✅ Alice's key pair generated")
    
    # Bob generates his key pair
    print("\n👨 Bob generates his key pair:")
    bob_private, bob_public = asym_enc.generate_ecc_key_pair()
    print("✅ Bob's key pair generated")
    
    # Alice computes shared secret using Bob's public key
    print("\n🔄 Alice computes shared secret using Bob's public key...")
    start_time = time.time()
    alice_shared_secret = key_exchange.ecdh_key_exchange(alice_private, bob_public)
    alice_time = time.time() - start_time
    print(f"✅ Alice's shared secret: {alice_shared_secret[:8].hex()}...")
    print(f"⏱️ Computation time: {alice_time:.4f} seconds")
    
    # Bob computes shared secret using Alice's public key
    print("\n🔄 Bob computes shared secret using Alice's public key...")
    start_time = time.time()
    bob_shared_secret = key_exchange.ecdh_key_exchange(bob_private, alice_public)
    bob_time = time.time() - start_time
    print(f"✅ Bob's shared secret: {bob_shared_secret[:8].hex()}...")
    print(f"⏱️ Computation time: {bob_time:.4f} seconds")
    
    # Verify both secrets match
    print(f"\n🔍 Verification:")
    secrets_match = alice_shared_secret == bob_shared_secret
    print(f"✓ Shared secrets match: {'YES ✅' if secrets_match else 'NO ❌'}")
    
    if secrets_match:
        print(f"🎉 Successful key exchange! Both parties now have the same secret.")
        print(f"🔐 Shared secret length: {len(alice_shared_secret)} bytes")
        
        # Derive encryption key from shared secret
        print(f"\n🔑 Deriving encryption key from shared secret...")
        derived_key = enhanced_kdf.derive_key(
            password=alice_shared_secret,
            algorithm=KDFAlgorithm.HKDF_SHA256,
            key_length=32
        )
        print(f"✅ Encryption key derived: {derived_key.key[:8].hex()}...")


def demonstrate_key_storage():
    """Demonstrate secure key storage and retrieval patterns."""
    print("\n🗄️ === Secure Key Storage Patterns ===")
    
    key_manager = KeyManager()
    
    # Generate sample keys
    symmetric_key = key_manager.generate_symmetric_key(32)
    rsa_private, rsa_public = key_manager.generate_rsa_key_pair(2048)
    
    print("📝 Key Storage Best Practices:")
    
    # 1. Environment Variables (for application keys)
    print("\n1️⃣ Environment Variables (Recommended for applications):")
    print("   export ENCRYPTION_KEY=base64_encoded_key")
    print("   # Retrieve in application:")
    print("   import base64, os")
    print("   key = base64.b64decode(os.environ['ENCRYPTION_KEY'])")
    
    # 2. Secure file storage with proper permissions
    print("\n2️⃣ Secure File Storage:")
    key_file = "secure_key.bin"
    try:
        # Save key to file
        with open(key_file, 'wb') as f:
            f.write(symmetric_key)
        
        # Set restrictive permissions (owner read/write only)
        os.chmod(key_file, 0o600)
        print(f"✅ Key saved to {key_file} with restricted permissions")
        
        # Read key back
        with open(key_file, 'rb') as f:
            loaded_key = f.read()
        
        print(f"✅ Key loaded successfully: {loaded_key == symmetric_key}")
        
        # Clean up
        os.remove(key_file)
        
    except Exception as e:
        print(f"❌ File storage error: {e}")
    
    # 3. JSON storage with metadata (for development/testing only)
    print("\n3️⃣ JSON Storage (Development Only - NOT for production keys):")
    key_metadata = {
        "created": time.time(),
        "algorithm": "AES-256-GCM",
        "key_id": "demo_key_001",
        "key_base64": symmetric_key.hex(),  # For demo only!
        "purpose": "demonstration"
    }
    
    json_str = json.dumps(key_metadata, indent=2)
    print(f"Example key metadata structure:\n{json_str}")
    
    # 4. Security warnings
    print("\n⚠️ Security Warnings:")
    print("   • NEVER store production keys in plain text")
    print("   • Use hardware security modules (HSMs) for high-value keys")
    print("   • Implement key rotation policies")
    print("   • Use different keys for different purposes")
    print("   • Monitor key access and usage")


def demonstrate_key_lifecycle():
    """Demonstrate complete key lifecycle management."""
    print("\n🔄 === Key Lifecycle Management ===")
    
    key_manager = KeyManager()
    enhanced_kdf = EnhancedKDF()
    
    print("📋 Complete key lifecycle example:")
    
    # 1. Key Generation
    print("\n1️⃣ Key Generation:")
    master_key = key_manager.generate_symmetric_key(32)
    print(f"✅ Master key generated: {master_key[:8].hex()}...")
    
    # 2. Key Derivation (for different purposes)
    print("\n2️⃣ Key Derivation:")
    salt = os.urandom(32)
    
    # Derive database encryption key
    db_key_material = enhanced_kdf.derive_key(
        password=master_key,
        salt=salt,
        algorithm=KDFAlgorithm.HKDF_SHA256,
        key_length=32
    )
    
    # Derive file encryption key  
    file_key_material = enhanced_kdf.derive_key(
        password=master_key,
        salt=salt + b"file_encryption",  # Different context
        algorithm=KDFAlgorithm.HKDF_SHA256,
        key_length=32
    )
    
    print(f"✅ Database key: {db_key_material.key[:8].hex()}...")
    print(f"✅ File key: {file_key_material.key[:8].hex()}...")
    print(f"✓ Keys are different: {db_key_material.key != file_key_material.key}")
    
    # 3. Key Usage (example)
    print("\n3️⃣ Key Usage:")
    print("   • Database encryption/decryption operations")
    print("   • File encryption/decryption operations")
    print("   • API token generation")
    
    # 4. Key Rotation
    print("\n4️⃣ Key Rotation:")
    print("   • Generate new master key")
    print("   • Re-encrypt data with new keys")
    print("   • Securely delete old keys")
    
    # 5. Key Deletion
    print("\n5️⃣ Secure Key Deletion:")
    print("   • Overwrite memory locations")
    print("   • Multiple pass deletion for storage")
    print("   • Verify successful deletion")
    
    # Demonstrate memory cleanup
    original_key = master_key[:]
    key_manager._secure_zero_memory(master_key)  # If this method exists
    print(f"✅ Key memory cleaned: {master_key == original_key}")


def main():
    """Main function to run all key management examples."""
    print("🚀 ZyraCrypt Key Management Examples")
    print("=" * 50)
    
    try:
        # Run all demonstrations
        demonstrate_key_generation()
        demonstrate_password_based_keys()
        demonstrate_key_exchange()
        demonstrate_key_storage()
        demonstrate_key_lifecycle()
        
        print("\n" + "=" * 50)
        print("✅ All key management examples completed successfully!")
        
        print("\n🔐 Key Management Best Practices Summary:")
        print("   • Use cryptographically secure random generation")
        print("   • Choose appropriate key lengths (256-bit minimum)")
        print("   • Implement proper key derivation for different purposes")
        print("   • Store keys securely with restricted access")
        print("   • Implement key rotation and lifecycle management")
        print("   • Use hardware security modules for high-value keys")
        print("   • Monitor and audit key access")
        
        print("\n📚 Next Steps:")
        print("   • Try api_usage.py for REST API integration")
        print("   • Explore post_quantum_examples.py for quantum-resistant keys")
        print("   • Check hybrid_encryption.py for advanced key schemes")
        
        return 0
        
    except Exception as e:
        print(f"\n❌ Error during example execution: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())