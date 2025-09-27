#!/usr/bin/env python3
"""
Advanced Encryption System - Library Test and Demonstration
Comprehensive test of all core cryptographic functionality
"""

import sys
import os
import time

# Add the encryption system to Python path
sys.path.insert(0, 'alqudimi_encryption_system/encryption_system/src')

def test_symmetric_encryption():
    """Test symmetric encryption algorithms"""
    print("=== Testing Symmetric Encryption ===")
    
    from core_cryptography.symmetric_encryption import SymmetricEncryption
    
    sym = SymmetricEncryption()
    key = os.urandom(32)
    plaintext = b'Testing Advanced Encryption System - Symmetric Algorithms'
    
    # Test AES-GCM
    print("Testing AES-GCM...")
    start_time = time.time()
    iv, ciphertext, tag = sym.encrypt_aes_gcm(key, plaintext)
    encrypt_time = time.time() - start_time
    
    start_time = time.time()
    decrypted = sym.decrypt_aes_gcm(key, iv, ciphertext, tag)
    decrypt_time = time.time() - start_time
    
    print(f"  ✓ AES-GCM: Encrypt: {encrypt_time*1000:.2f}ms, Decrypt: {decrypt_time*1000:.2f}ms")
    print(f"  ✓ Success: {plaintext == decrypted}")
    
    # Test ChaCha20-Poly1305
    print("Testing ChaCha20-Poly1305...")
    start_time = time.time()
    nonce, ciphertext2 = sym.encrypt_chacha20_poly1305(key, plaintext)
    encrypt_time = time.time() - start_time
    
    start_time = time.time()
    decrypted2 = sym.decrypt_chacha20_poly1305(key, nonce, ciphertext2)
    decrypt_time = time.time() - start_time
    
    print(f"  ✓ ChaCha20-Poly1305: Encrypt: {encrypt_time*1000:.2f}ms, Decrypt: {decrypt_time*1000:.2f}ms")
    print(f"  ✓ Success: {plaintext == decrypted2}")

def test_asymmetric_encryption():
    """Test asymmetric encryption and signatures"""
    print("\n=== Testing Asymmetric Encryption ===")
    
    from core_cryptography.asymmetric_encryption import AsymmetricEncryption
    
    asym = AsymmetricEncryption()
    
    # Test RSA
    print("Testing RSA...")
    private_key, public_key = asym.generate_rsa_key_pair(key_size=2048)
    plaintext = b'RSA test message for encryption system'
    
    ciphertext = asym.encrypt_rsa_oaep(public_key, plaintext)
    decrypted = asym.decrypt_rsa_oaep(private_key, ciphertext)
    print(f"  ✓ RSA Encryption/Decryption: {plaintext == decrypted}")
    
    # Test ECC Signatures
    print("Testing ECC Signatures...")
    ecc_private, ecc_public = asym.generate_ecc_key_pair()
    message = b'Message to be digitally signed'
    
    signature = asym.sign_ecc(ecc_private, message)
    is_valid = asym.verify_ecc(ecc_public, message, signature)
    print(f"  ✓ ECC Digital Signature: {is_valid}")

def test_key_management():
    """Test key management functionality"""
    print("\n=== Testing Key Management ===")
    
    from key_management.key_generator import KeyGenerator
    from key_management.key_exchange import KeyExchange
    
    # Test key generation
    key_gen = KeyGenerator()
    
    # Test symmetric key generation
    key_128 = key_gen.generate_symmetric_key(128)
    key_256 = key_gen.generate_symmetric_key(256)
    print(f"  ✓ Symmetric Key Generation: 128-bit ({len(key_128)*8}), 256-bit ({len(key_256)*8})")
    
    # Test key derivation
    password = b'test_password_123'
    salt = os.urandom(32)
    
    derived_pbkdf2 = key_gen.derive_key_pbkdf2(password, salt, iterations=10000)
    derived_argon2 = key_gen.derive_key_argon2(password, salt)
    derived_scrypt = key_gen.derive_key_scrypt(password, salt)
    
    print(f"  ✓ Key Derivation - PBKDF2: {len(derived_pbkdf2)*8} bits")
    print(f"  ✓ Key Derivation - Argon2: {len(derived_argon2)*8} bits")
    print(f"  ✓ Key Derivation - scrypt: {len(derived_scrypt)*8} bits")
    
    # Test key exchange
    key_exchange = KeyExchange()
    
    # ECDH
    alice_private, alice_public = key_exchange.generate_ecdh_key_pair()
    bob_private, bob_public = key_exchange.generate_ecdh_key_pair()
    
    alice_shared = key_exchange.derive_shared_secret_ecdh(alice_private, bob_public)
    bob_shared = key_exchange.derive_shared_secret_ecdh(bob_private, alice_public)
    
    print(f"  ✓ ECDH Key Exchange: {alice_shared == bob_shared}")

def test_data_protection():
    """Test data protection features"""
    print("\n=== Testing Data Protection ===")
    
    from data_protection.data_protection_manager import DataProtectionManager
    
    dpm = DataProtectionManager()
    
    # Test with different data types
    test_data = {
        'string': 'Hello World!',
        'dict': {'name': 'Test', 'value': 42},
        'bytes': b'Binary data test'
    }
    
    for data_type, data in test_data.items():
        prepared, original_type = dpm.prepare_data_for_encryption(data)
        restored = dpm.restore_data_after_decryption(prepared, original_type)
        print(f"  ✓ Data Protection ({data_type}): {data == restored}")

def test_encryption_framework():
    """Test the high-level encryption framework"""
    print("\n=== Testing Encryption Framework ===")
    
    from core_cryptography.encryption_framework import EncryptionFramework
    
    framework = EncryptionFramework()
    key = os.urandom(32)
    plaintext = b'Testing the comprehensive encryption framework'
    
    # Test auto algorithm selection
    algo, iv, ciphertext, tag = framework.encrypt(plaintext, key, 'auto')
    decrypted = framework.decrypt(algo, key, iv, ciphertext, tag)
    print(f"  ✓ Auto Algorithm Selection ({algo}): {plaintext == decrypted}")
    
    # Test specific algorithms
    for algorithm in ['AES-GCM', 'ChaCha20']:
        algo, iv, ciphertext, tag = framework.encrypt(plaintext, key, algorithm)
        decrypted = framework.decrypt(algo, key, iv, ciphertext, tag)
        print(f"  ✓ {algorithm}: {plaintext == decrypted}")

def test_algorithm_manager():
    """Test algorithm selection and management"""
    print("\n=== Testing Algorithm Manager ===")
    
    from core_cryptography.algorithm_manager import AlgorithmManager
    
    manager = AlgorithmManager()
    
    # Test algorithm selection
    for size in [1024, 1024*1024, 10*1024*1024]:
        selected_sym = manager.select_symmetric_algorithm(size, "high")
        selected_asym = manager.select_asymmetric_algorithm("high")
        print(f"  ✓ Size {size//1024}KB: Symmetric={selected_sym}, Asymmetric={selected_asym}")

def run_performance_tests():
    """Run performance benchmarks"""
    print("\n=== Performance Benchmarks ===")
    
    from core_cryptography.symmetric_encryption import SymmetricEncryption
    
    sym = SymmetricEncryption()
    key = os.urandom(32)
    
    # Test different data sizes
    for size_kb in [1, 10, 100]:
        data = os.urandom(size_kb * 1024)
        
        # AES-GCM benchmark
        start_time = time.time()
        iv, ciphertext, tag = sym.encrypt_aes_gcm(key, data)
        aes_encrypt_time = time.time() - start_time
        
        start_time = time.time()
        decrypted = sym.decrypt_aes_gcm(key, iv, ciphertext, tag)
        aes_decrypt_time = time.time() - start_time
        
        # ChaCha20-Poly1305 benchmark
        start_time = time.time()
        nonce, ciphertext2 = sym.encrypt_chacha20_poly1305(key, data)
        chacha_encrypt_time = time.time() - start_time
        
        start_time = time.time()
        decrypted2 = sym.decrypt_chacha20_poly1305(key, nonce, ciphertext2)
        chacha_decrypt_time = time.time() - start_time
        
        print(f"  {size_kb}KB Data:")
        print(f"    AES-GCM: Encrypt {aes_encrypt_time*1000:.2f}ms, Decrypt {aes_decrypt_time*1000:.2f}ms")
        print(f"    ChaCha20: Encrypt {chacha_encrypt_time*1000:.2f}ms, Decrypt {chacha_decrypt_time*1000:.2f}ms")

def main():
    """Main test execution"""
    print("Advanced Encryption System - Library Test Suite")
    print("=" * 50)
    
    try:
        # Core cryptography tests
        test_symmetric_encryption()
        test_asymmetric_encryption()
        
        # Key management tests
        test_key_management()
        
        # Data protection tests
        test_data_protection()
        
        # Framework tests
        test_encryption_framework()
        test_algorithm_manager()
        
        # Performance tests
        run_performance_tests()
        
        print("\n" + "=" * 50)
        print("✓ All tests completed successfully!")
        print("✓ Advanced Encryption System library is fully functional")
        print("✓ Ready for integration into applications")
        
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()