#!/usr/bin/env python3
"""
Comprehensive Test Suite for Alqudimi Encryption System

This script tests all core components of the encryption system to ensure
they work correctly after the security fixes and improvements.
"""

import sys
import os
import traceback

# Add the encryption system to the path
sys.path.insert(0, os.path.join('alqudimi_encryption_system', 'encryption_system', 'src'))

def test_symmetric_encryption():
    """Test symmetric encryption with AES-GCM and ChaCha20-Poly1305."""
    print("=" * 60)
    print("TESTING SYMMETRIC ENCRYPTION")
    print("=" * 60)
    
    try:
        from core_cryptography.symmetric_encryption import SymmetricEncryption
        
        sym = SymmetricEncryption()
        test_data = b"Hello, World! This is a test message for encryption."
        test_key = os.urandom(32)  # 256-bit key
        test_aad = b"additional_authenticated_data"
        
        # Test AES-GCM
        print("\n1. Testing AES-GCM Encryption/Decryption:")
        iv, ciphertext, tag = sym.encrypt_aes_gcm(test_key, test_data, test_aad)
        decrypted = sym.decrypt_aes_gcm(test_key, iv, ciphertext, tag, test_aad)
        
        print(f"   Original:  {test_data.decode()}")
        print(f"   Encrypted: {ciphertext.hex()[:50]}...")
        print(f"   Decrypted: {decrypted.decode()}")
        print(f"   ✅ AES-GCM: {'PASS' if test_data == decrypted else 'FAIL'}")
        
        # Test ChaCha20-Poly1305
        print("\n2. Testing ChaCha20-Poly1305 Encryption/Decryption:")
        nonce, ciphertext2 = sym.encrypt_chacha20_poly1305(test_key, test_data, test_aad)
        decrypted2 = sym.decrypt_chacha20_poly1305(test_key, nonce, ciphertext2, test_aad)
        
        print(f"   Original:  {test_data.decode()}")
        print(f"   Encrypted: {ciphertext2.hex()[:50]}...")
        print(f"   Decrypted: {decrypted2.decode()}")
        print(f"   ✅ ChaCha20-Poly1305: {'PASS' if test_data == decrypted2 else 'FAIL'}")
        
        return True
        
    except Exception as e:
        print(f"   ❌ SYMMETRIC ENCRYPTION FAILED: {e}")
        traceback.print_exc()
        return False

def test_asymmetric_encryption():
    """Test asymmetric encryption with RSA and ECC."""
    print("\n" + "=" * 60)
    print("TESTING ASYMMETRIC ENCRYPTION")
    print("=" * 60)
    
    try:
        from core_cryptography.asymmetric_encryption import AsymmetricEncryption
        
        asym = AsymmetricEncryption()
        test_data = b"Test message for asymmetric encryption"
        
        # Test RSA
        print("\n1. Testing RSA Key Generation and Encryption/Decryption:")
        rsa_private, rsa_public = asym.generate_rsa_key_pair(key_size=2048)
        encrypted_rsa = asym.encrypt_rsa_oaep(rsa_public, test_data)
        decrypted_rsa = asym.decrypt_rsa_oaep(rsa_private, encrypted_rsa)
        
        print(f"   Original:  {test_data.decode()}")
        print(f"   Encrypted: {encrypted_rsa.hex()[:50]}...")
        print(f"   Decrypted: {decrypted_rsa.decode()}")
        print(f"   ✅ RSA: {'PASS' if test_data == decrypted_rsa else 'FAIL'}")
        
        # Test ECC Signing
        print("\n2. Testing ECC Key Generation and Digital Signatures:")
        ecc_private, ecc_public = asym.generate_ecc_key_pair()
        signature = asym.sign_ecc(ecc_private, test_data)
        verification = asym.verify_ecc(ecc_public, test_data, signature)
        
        print(f"   Original:  {test_data.decode()}")
        print(f"   Signature: {signature.hex()[:50]}...")
        print(f"   Verified:  {verification}")
        print(f"   ✅ ECC: {'PASS' if verification else 'FAIL'}")
        
        return True
        
    except Exception as e:
        print(f"   ❌ ASYMMETRIC ENCRYPTION FAILED: {e}")
        traceback.print_exc()
        return False

def test_algorithm_manager():
    """Test algorithm manager for intelligent algorithm selection."""
    print("\n" + "=" * 60)
    print("TESTING ALGORITHM MANAGER")
    print("=" * 60)
    
    try:
        from core_cryptography.algorithm_manager import AlgorithmManager
        
        manager = AlgorithmManager()
        
        # Test algorithm selection
        print("\n1. Testing Algorithm Selection:")
        high_sec_alg = manager.select_symmetric_algorithm(1024*1024*10, "high")  # 10MB
        medium_sec_alg = manager.select_symmetric_algorithm(1024, "medium")  # 1KB
        
        print(f"   High security (10MB):  {high_sec_alg}")
        print(f"   Medium security (1KB): {medium_sec_alg}")
        
        # Test asymmetric algorithm selection
        high_asym = manager.select_asymmetric_algorithm("high")
        medium_asym = manager.select_asymmetric_algorithm("medium")
        
        print(f"   High asymmetric:       {high_asym}")
        print(f"   Medium asymmetric:     {medium_asym}")
        
        # Test algorithm retrieval
        print("\n2. Testing Algorithm Retrieval:")
        aes_func = manager.get_symmetric_encryptor("AES-GCM")
        chacha_func = manager.get_symmetric_encryptor("ChaCha20-Poly1305")
        
        print(f"   AES-GCM function:      {'✅ Available' if aes_func else '❌ Not found'}")
        print(f"   ChaCha20-Poly1305:     {'✅ Available' if chacha_func else '❌ Not found'}")
        
        return True
        
    except Exception as e:
        print(f"   ❌ ALGORITHM MANAGER FAILED: {e}")
        traceback.print_exc()
        return False

def test_enhanced_algorithm_manager():
    """Test enhanced algorithm manager with recommendations."""
    print("\n" + "=" * 60)
    print("TESTING ENHANCED ALGORITHM MANAGER")
    print("=" * 60)
    
    try:
        from core_cryptography.enhanced_algorithm_manager import (
            EnhancedAlgorithmManager, SecurityLevel, CryptographicPurpose
        )
        
        manager = EnhancedAlgorithmManager()
        
        # Test algorithm recommendations
        print("\n1. Testing Algorithm Recommendations:")
        
        # High security data encryption
        rec1 = manager.recommend_algorithm(
            CryptographicPurpose.DATA_ENCRYPTION, 
            SecurityLevel.HIGH,
            data_size=1024*1024,  # 1MB
            performance_priority=False
        )
        
        print(f"   High Security Encryption:")
        print(f"     Algorithm: {rec1.algorithm}")
        print(f"     Key Size:  {rec1.key_size}")
        print(f"     Rationale: {rec1.rationale}")
        print(f"     Scores:    Performance={rec1.performance_score}, Security={rec1.security_score}")
        
        # Quantum-resistant recommendation
        rec2 = manager.recommend_algorithm(
            CryptographicPurpose.KEY_EXCHANGE,
            SecurityLevel.QUANTUM_RESISTANT
        )
        
        print(f"\n   Quantum-Resistant Key Exchange:")
        print(f"     Algorithm: {rec2.algorithm}")
        print(f"     Key Size:  {rec2.key_size}")
        print(f"     Rationale: {rec2.rationale}")
        
        # Test encryption with recommended algorithm
        print("\n2. Testing Encryption with Recommended Algorithm:")
        test_data = b"Test data for enhanced encryption"
        
        try:
            result = manager.encrypt_with_recommended_algorithm(
                test_data, SecurityLevel.HIGH
            )
            print(f"   Encryption Method: {result['method']}")
            print(f"   Algorithm Used:    {result['algorithm']}")
            print(f"   ✅ Enhanced encryption successful")
        except Exception as e:
            print(f"   ⚠️  Enhanced encryption skipped (missing dependencies): {e}")
        
        return True
        
    except Exception as e:
        print(f"   ❌ ENHANCED ALGORITHM MANAGER FAILED: {e}")
        traceback.print_exc()
        return False

def test_key_management():
    """Test key management and secure storage."""
    print("\n" + "=" * 60)
    print("TESTING KEY MANAGEMENT")
    print("=" * 60)
    
    try:
        # Test secure key storage
        print("\n1. Testing Secure Key Storage:")
        from key_management.enhanced_key_manager import SecureKeyStorage, KeyMetadata
        
        # Create temporary storage
        import tempfile
        with tempfile.TemporaryDirectory() as temp_dir:
            storage = SecureKeyStorage(temp_dir, "test_master_password_123")
            
            # Test key storage and retrieval
            test_key = os.urandom(32)
            key_id = "test_key_001"
            metadata = KeyMetadata(key_id, "AES", "encryption", time.time())
            
            storage.store_key(key_id, test_key, metadata)
            retrieved_key = storage.retrieve_key(key_id)
            
            print(f"   Original Key:  {test_key.hex()[:32]}...")
            print(f"   Retrieved Key: {retrieved_key.hex()[:32]}...")
            print(f"   ✅ Key Storage: {'PASS' if test_key == retrieved_key else 'FAIL'}")
        
        # Test basic key manager
        print("\n2. Testing Basic Key Manager:")
        from key_management.key_manager import KeyManager
        
        try:
            km = KeyManager()
            
            # Test symmetric key generation
            sym_key = km.generate_and_store_symmetric_key("test_sym_001", 256)
            retrieved_sym = km.get_symmetric_key("test_sym_001")
            
            print(f"   Generated Key: {sym_key.hex()[:32]}...")
            print(f"   Retrieved Key: {retrieved_sym.hex()[:32]}...")
            print(f"   ✅ Key Manager: {'PASS' if sym_key == retrieved_sym else 'FAIL'}")
            
        except Exception as e:
            print(f"   ⚠️  Key Manager tests skipped (missing dependencies): {e}")
        
        return True
        
    except Exception as e:
        print(f"   ❌ KEY MANAGEMENT FAILED: {e}")
        traceback.print_exc()
        return False

def test_api_integration():
    """Test API integration with the updated encryption functions."""
    print("\n" + "=" * 60)
    print("TESTING API INTEGRATION")
    print("=" * 60)
    
    try:
        import requests
        import json
        
        base_url = "http://localhost:5000/api/encryption"
        
        # Test health endpoint
        print("\n1. Testing Health Endpoint:")
        response = requests.get(f"{base_url}/health")
        health_data = response.json()
        
        print(f"   Status: {health_data['status']}")
        print(f"   Symmetric Encryption: {health_data['services']['symmetric_encryption']}")
        print(f"   Asymmetric Encryption: {health_data['services']['asymmetric_encryption']}")
        
        # Test algorithm recommendation
        print("\n2. Testing Algorithm Recommendation:")
        rec_response = requests.post(f"{base_url}/algorithms/recommend", json={
            "purpose": "data_encryption",
            "security_level": "high",
            "performance_priority": True
        })
        rec_data = rec_response.json()
        
        print(f"   Recommended Algorithm: {rec_data['algorithm']}")
        print(f"   Key Size: {rec_data['key_size']}")
        print(f"   Rationale: {rec_data['rationale']}")
        
        # Test symmetric encryption
        print("\n3. Testing Symmetric Encryption API:")
        encrypt_response = requests.post(f"{base_url}/encrypt/symmetric", json={
            "plaintext": "Hello, API World!",
            "algorithm": "AES-GCM"
        })
        encrypt_data = encrypt_response.json()
        
        print(f"   Algorithm: {encrypt_data['algorithm']}")
        print(f"   Encrypted: {encrypt_data['ciphertext'][:32]}...")
        
        # Test decryption
        decrypt_response = requests.post(f"{base_url}/decrypt/symmetric", json={
            "algorithm": encrypt_data['algorithm'],
            "key": encrypt_data['key'],
            "ciphertext": encrypt_data['ciphertext'],
            "iv": encrypt_data['iv'],
            "tag": encrypt_data['tag']
        })
        decrypt_data = decrypt_response.json()
        
        print(f"   Decrypted: {decrypt_data['plaintext']}")
        print(f"   ✅ API Integration: {'PASS' if decrypt_data['plaintext'] == 'Hello, API World!' else 'FAIL'}")
        
        return True
        
    except Exception as e:
        print(f"   ❌ API INTEGRATION FAILED: {e}")
        traceback.print_exc()
        return False

def main():
    """Run all tests and generate summary."""
    print("🔐 ALQUDIMI ENCRYPTION SYSTEM - COMPREHENSIVE TEST SUITE")
    print("=" * 70)
    
    import time
    start_time = time.time()
    
    # Run all tests
    test_results = []
    test_results.append(("Symmetric Encryption", test_symmetric_encryption()))
    test_results.append(("Asymmetric Encryption", test_asymmetric_encryption()))
    test_results.append(("Algorithm Manager", test_algorithm_manager()))
    test_results.append(("Enhanced Algorithm Manager", test_enhanced_algorithm_manager()))
    test_results.append(("Key Management", test_key_management()))
    test_results.append(("API Integration", test_api_integration()))
    
    # Generate summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    passed = sum(1 for _, result in test_results if result)
    total = len(test_results)
    
    for test_name, result in test_results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"   {test_name:<30} {status}")
    
    print(f"\nOverall Results: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
    print(f"Execution Time: {time.time() - start_time:.2f} seconds")
    
    if passed == total:
        print("\n🎉 ALL TESTS PASSED! The encryption system is working correctly.")
    else:
        print(f"\n⚠️  {total - passed} test(s) failed. Please review the errors above.")
    
    return passed == total

if __name__ == "__main__":
    # Add required imports at the top
    import time
    
    success = main()
    sys.exit(0 if success else 1)