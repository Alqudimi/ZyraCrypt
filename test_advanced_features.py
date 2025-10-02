#!/usr/bin/env python3
"""
Advanced Features Integration Test Suite
Tests all newly implemented advanced cryptographic features
"""

import sys
import os
import time
import json

def test_hybrid_pqc():
    """Test Hybrid Post-Quantum Cryptography"""
    print("=== Testing Hybrid Post-Quantum Cryptography ===")
    
    try:
        from advanced_features.hybrid_pqc_enhanced import HybridPQCEngine, SecurityLevel
        
        # Test different security levels
        for security_level in [128, 192]:
            print(f"Testing security level {security_level}...")
            
            # Initialize engine
            engine = HybridPQCEngine(security_level=security_level)
            
            # Generate hybrid keypair
            public_keys, private_keys = engine.generate_hybrid_keypair()
            
            # Perform hybrid key exchange
            key_material = engine.hybrid_key_exchange(public_keys)
            
            # Verify key material structure
            assert key_material.classical_shared_secret is not None
            assert key_material.pq_shared_secret is not None
            assert key_material.combined_shared_secret is not None
            assert len(key_material.combined_shared_secret) == 32
            
            print(f"  ✓ Security Level {security_level}: Hybrid key exchange successful")
            
            # Test hybrid signatures
            sig_public, sig_private = engine.generate_hybrid_signature_keypair()
            message = b"Test message for hybrid signature"
            
            signatures = engine.hybrid_sign(sig_private, message)
            is_valid = engine.hybrid_verify(sig_public, message, signatures)
            
            assert is_valid
            print(f"  ✓ Security Level {security_level}: Hybrid signatures working")
        
        # Test algorithm info
        info = engine.get_algorithm_info()
        assert 'security_level' in info
        assert 'classical_algorithm' in info
        assert 'pq_algorithm' in info
        
        print("  ✓ Hybrid PQC: All tests passed")
        return True
        
    except Exception as e:
        print(f"  ✗ Hybrid PQC Error: {e}")
        return False

def test_envelope_encryption_kms():
    """Test Enhanced Key Storage with Envelope Encryption"""
    print("\n=== Testing Envelope Encryption & KMS Integration ===")
    
    try:
        from key_management.envelope_encryption_kms import (
            EnvelopeEncryptionManager, SecureKeyStore, KeyStorageLevel
        )
        
        # Initialize envelope encryption manager
        manager = EnvelopeEncryptionManager()
        
        # Test key generation and wrapping
        key_id, wrapped_key = manager.generate_data_encryption_key(
            purpose="test_encryption",
            algorithm="AES-256-GCM",
            security_level=KeyStorageLevel.STANDARD
        )
        
        assert key_id is not None
        assert wrapped_key is not None
        assert wrapped_key.metadata.algorithm == "AES-256-GCM"
        assert wrapped_key.metadata.key_size == 256
        
        print("  ✓ Data encryption key generation successful")
        
        # Test encryption/decryption with wrapped key
        test_data = b"Sensitive data for envelope encryption testing"
        
        encrypted_data = manager.encrypt_with_wrapped_key(wrapped_key, test_data)
        decrypted_data = manager.decrypt_with_wrapped_key(wrapped_key, encrypted_data)
        
        assert decrypted_data == test_data
        print("  ✓ Envelope encryption/decryption successful")
        
        # Test key rotation
        new_key_id, new_wrapped_key = manager.rotate_key(wrapped_key)
        
        assert new_key_id != key_id
        assert new_wrapped_key.metadata.version > wrapped_key.metadata.version
        print("  ✓ Key rotation successful")
        
        # Test secure key store
        key_store = SecureKeyStore("test_keystore")
        key_store.store_key(key_id, wrapped_key)
        
        loaded_key = key_store.load_key(key_id)
        assert loaded_key.metadata.key_id == wrapped_key.metadata.key_id
        
        print("  ✓ Secure key storage successful")
        
        # Cleanup
        key_store.delete_key(key_id)
        
        print("  ✓ Envelope Encryption & KMS: All tests passed")
        return True
        
    except Exception as e:
        print(f"  ✗ Envelope Encryption Error: {e}")
        return False

def test_enhanced_kdf_password():
    """Test Enhanced KDF and Password Schemes"""
    print("\n=== Testing Enhanced KDF and Password Schemes ===")
    
    try:
        from key_management.enhanced_kdf_password import (
            EnhancedKDF, PasswordValidator, SecurePasswordStore,
            KDFAlgorithm, SecurityProfile
        )
        
        # Test KDF algorithms
        kdf = EnhancedKDF()
        password = "TestPassword123!@#"
        
        algorithms = [
            KDFAlgorithm.ARGON2ID,
            KDFAlgorithm.SCRYPT,
            KDFAlgorithm.PBKDF2_SHA256
        ]
        
        for algorithm in algorithms:
            print(f"  Testing {algorithm.value}...")
            
            # Derive key
            derived_material = kdf.derive_key(
                password=password,
                algorithm=algorithm,
                security_profile=SecurityProfile.INTERACTIVE
            )
            
            assert len(derived_material.key) == 32
            assert derived_material.algorithm == algorithm
            
            # Verify password
            is_valid = kdf.verify_derived_key(password, derived_material)
            assert is_valid
            
            # Test wrong password
            is_invalid = kdf.verify_derived_key("WrongPassword", derived_material)
            assert not is_invalid
            
            print(f"    ✓ {algorithm.value}: Key derivation and verification successful")
        
        # Test password validation
        validator = PasswordValidator()
        
        # Test strong password
        strong_password = "MyVerySecurePassword123!@#"
        validation = validator.validate_password(strong_password)
        assert validation['valid']
        print("  ✓ Strong password validation successful")
        
        # Test weak password
        weak_password = "123456"
        validation = validator.validate_password(weak_password)
        assert not validation['valid']
        print("  ✓ Weak password rejection successful")
        
        # Test password generation
        generated_password = validator.generate_secure_password(16)
        validation = validator.validate_password(generated_password)
        assert validation['valid']
        print("  ✓ Secure password generation successful")
        
        # Test secure password store
        password_store = SecurePasswordStore()
        
        test_password = "TestStorePassword123!"
        stored_hash = password_store.hash_password(test_password)
        
        # Verify password
        is_valid = password_store.verify_password(test_password, stored_hash)
        assert is_valid
        
        # Test wrong password
        is_invalid = password_store.verify_password("WrongPassword", stored_hash)
        assert not is_invalid
        
        print("  ✓ Enhanced KDF & Password: All tests passed")
        return True
        
    except Exception as e:
        print(f"  ✗ Enhanced KDF Error: {e}")
        return False

def test_algorithm_agility_versioning():
    """Test Algorithm Agility and Versioning Protocol"""
    print("\n=== Testing Algorithm Agility and Versioning ===")
    
    try:
        from core_cryptography.algorithm_agility_versioning import (
            get_algorithm_registry, create_versioned_encryption, 
            create_migration_manager, AlgorithmType, SecurityLevel
        )
        
        # Test algorithm registry
        registry = get_algorithm_registry()
        
        # Get recommended algorithm
        spec = registry.get_recommended_algorithm(
            AlgorithmType.SYMMETRIC_ENCRYPTION,
            SecurityLevel.LEVEL_256
        )
        
        assert spec is not None
        assert spec.security_level >= SecurityLevel.LEVEL_256
        print("  ✓ Algorithm recommendation successful")
        
        # Test versioned encryption
        versioned_crypto = create_versioned_encryption()
        
        test_data = b"Data for versioned encryption testing"
        
        # Encrypt with current recommended algorithm
        encrypted_data = versioned_crypto.encrypt(test_data)
        
        assert 'context' in encrypted_data
        assert 'format_version' in encrypted_data
        assert encrypted_data['format_version'] == "2.0"
        print("  ✓ Versioned encryption successful")
        
        # Decrypt
        decrypted_data = versioned_crypto.decrypt(encrypted_data)
        assert decrypted_data == test_data
        print("  ✓ Versioned decryption successful")
        
        # Test migration manager
        migration_manager = create_migration_manager()
        
        # Check if migration is needed
        needs_migration, reason = migration_manager.check_migration_needed(encrypted_data)
        print(f"  ✓ Migration check: {needs_migration}, {reason}")
        
        # Test deprecated algorithms list
        deprecated_algos = registry.get_deprecated_algorithms()
        print(f"  ✓ Found {len(deprecated_algos)} deprecated algorithms")
        
        print("  ✓ Algorithm Agility & Versioning: All tests passed")
        return True
        
    except Exception as e:
        print(f"  ✗ Algorithm Agility Error: {e}")
        return False

def test_threshold_multisig():
    """Test Threshold Signatures and Multisig"""
    print("\n=== Testing Threshold Signatures and Multisig ===")
    
    try:
        from advanced_features.threshold_multisig_enhanced import (
            ShamirSecretSharing, ThresholdECDSA, MultisigManager, ThresholdScheme
        )
        
        # Test Shamir's Secret Sharing
        sss = ShamirSecretSharing()
        secret = b"This is a secret key for testing"
        threshold = 3
        total_shares = 5
        
        # Split secret
        shares = sss.split_secret(secret, threshold, total_shares)
        assert len(shares) == total_shares
        print("  ✓ Secret sharing split successful")
        
        # Reconstruct with threshold shares
        reconstructed = sss.reconstruct_secret(shares[:threshold])
        assert reconstructed == secret
        print("  ✓ Secret reconstruction successful")
        
        # Test Threshold ECDSA
        threshold_ecdsa = ThresholdECDSA()
        participants = ["alice", "bob", "charlie", "dave", "eve"]
        
        # Generate threshold keypair
        keypair = threshold_ecdsa.generate_threshold_keypair(
            threshold=3, 
            total_participants=5, 
            participants=participants
        )
        
        assert keypair.threshold == 3
        assert len(keypair.shares) == 5
        print("  ✓ Threshold ECDSA keypair generation successful")
        
        # Test partial signatures
        message = b"Message to be signed with threshold ECDSA"
        partial_signatures = []
        
        for i, participant in enumerate(participants[:threshold]):
            partial_sig = threshold_ecdsa.create_partial_signature(
                keypair, i + 1, message, participant
            )
            partial_signatures.append(partial_sig)
        
        assert len(partial_signatures) == threshold
        print("  ✓ Partial signature creation successful")
        
        # Combine signatures
        final_signature = threshold_ecdsa.combine_partial_signatures(
            keypair, partial_signatures, message
        )
        
        assert final_signature.signature_status.value == "complete"
        print("  ✓ Threshold signature combination successful")
        
        # Verify signature
        is_valid = threshold_ecdsa.verify_threshold_signature(
            keypair, final_signature, message
        )
        assert is_valid
        print("  ✓ Threshold signature verification successful")
        
        # Test Multisig Manager
        multisig_manager = MultisigManager()
        
        # Create multisig setup
        multisig_keypair = multisig_manager.create_multisig_setup(
            participants=participants,
            threshold=3,
            scheme=ThresholdScheme.THRESHOLD_ECDSA
        )
        
        assert multisig_keypair.threshold == 3
        print("  ✓ Multisig setup creation successful")
        
        # Get status
        status = multisig_manager.get_multisig_status(multisig_keypair.key_id)
        assert status['threshold'] == 3
        assert len(status['participants']) == 5
        print("  ✓ Multisig status retrieval successful")
        
        print("  ✓ Threshold Signatures & Multisig: All tests passed")
        return True
        
    except Exception as e:
        print(f"  ✗ Threshold Multisig Error: {e}")
        return False

def test_secure_mpc_enclaves():
    """Test MPC and Secure Enclaves"""
    print("\n=== Testing MPC and Secure Enclaves ===")
    
    try:
        from advanced_features.secure_mpc_enclaves import (
            SecureEnclave, MPCCoordinator, SecureKeyGeneration,
            MPCProtocol, EnclaveType, MPCParticipant
        )
        
        # Test Secure Enclave
        enclave = SecureEnclave(EnclaveType.SOFTWARE_ENCLAVE)
        
        # Store and retrieve secrets
        test_secret = b"Top secret data for enclave testing"
        success = enclave.store_secret("test_key", test_secret)
        assert success
        print("  ✓ Enclave secret storage successful")
        
        retrieved_secret = enclave.retrieve_secret("test_key")
        assert retrieved_secret == test_secret
        print("  ✓ Enclave secret retrieval successful")
        
        # Test secure computation
        def hash_function(data: bytes) -> bytes:
            import hashlib
            return hashlib.sha256(data).digest()
        
        success = enclave.secure_computation(
            hash_function, "test_key", "hash_result"
        )
        assert success
        
        hash_result = enclave.retrieve_secret("hash_result")
        expected_hash = hash_function(test_secret)
        assert hash_result == expected_hash
        print("  ✓ Secure computation successful")
        
        # Get attestation
        attestation = enclave.get_attestation()
        assert 'enclave_id' in attestation
        assert 'measurement' in attestation
        print("  ✓ Enclave attestation successful")
        
        # Test MPC Coordinator
        coordinator = MPCCoordinator()
        
        # Register participants
        participants = ["party_1", "party_2", "party_3"]
        for participant_id in participants:
            participant = MPCParticipant(
                participant_id=participant_id,
                public_key=os.urandom(32),
                capabilities=[MPCProtocol.SECRET_SHARING]
            )
            coordinator.register_participant(participant)
        
        print("  ✓ MPC participants registration successful")
        
        # Create computation
        function_spec = {
            'function': 'secret_reconstruction',
            'threshold': 2
        }
        
        computation_id = coordinator.create_computation(
            MPCProtocol.SECRET_SHARING,
            function_spec,
            participants
        )
        
        assert computation_id is not None
        print("  ✓ MPC computation creation successful")
        
        # Get computation status
        status = coordinator.get_computation_status(computation_id)
        assert status is not None
        assert status['protocol'] == MPCProtocol.SECRET_SHARING.value
        print("  ✓ MPC computation status retrieval successful")
        
        # Test Secure Key Generation
        key_gen = SecureKeyGeneration()
        
        # Generate distributed key
        key_computation_id = key_gen.distributed_key_generation(
            participants=participants,
            threshold=2,
            key_type='ecdsa'
        )
        
        assert key_computation_id is not None
        print("  ✓ Distributed key generation successful")
        
        # Get key info
        key_info = key_gen.get_key_info(key_computation_id)
        assert key_info is not None
        assert key_info['participants'] == participants
        print("  ✓ Key information retrieval successful")
        
        # Clean up enclave
        enclave.clear_secrets()
        print("  ✓ Enclave cleanup successful")
        
        print("  ✓ MPC & Secure Enclaves: All tests passed")
        return True
        
    except Exception as e:
        print(f"  ✗ MPC & Enclaves Error: {e}")
        return False

def test_side_channel_resistance():
    """Test Side-Channel Resistance Features"""
    print("\n=== Testing Side-Channel Resistance ===")
    
    try:
        from advanced_features.hybrid_pqc_enhanced import SideChannelResistant
        from cryptography.hazmat.primitives import constant_time
        
        # Test constant-time comparison
        data1 = b"secret_data_123456789"
        data2 = b"secret_data_123456789"
        data3 = b"different_data_098765"
        
        # Should be equal
        is_equal = SideChannelResistant.constant_time_compare(data1, data2)
        assert is_equal
        print("  ✓ Constant-time comparison (equal) successful")
        
        # Should be different
        is_different = SideChannelResistant.constant_time_compare(data1, data3)
        assert not is_different
        print("  ✓ Constant-time comparison (different) successful")
        
        # Test secure random generation
        random_data = SideChannelResistant.secure_random(32)
        assert len(random_data) == 32
        assert random_data != SideChannelResistant.secure_random(32)  # Should be different
        print("  ✓ Secure random generation successful")
        
        # Test memory zeroing
        sensitive_data = bytearray(b"sensitive_information")
        SideChannelResistant.secure_zero_memory(sensitive_data)
        # After zeroing, all bytes should be 0
        assert all(byte == 0 for byte in sensitive_data)
        print("  ✓ Secure memory zeroing successful")
        
        # Test with cryptography library constant-time functions
        test_bytes1 = b"constant_time_test_data"
        test_bytes2 = b"constant_time_test_data"
        test_bytes3 = b"different_test_data_123"
        
        is_equal_crypto = constant_time.bytes_eq(test_bytes1, test_bytes2)
        assert is_equal_crypto
        
        is_different_crypto = constant_time.bytes_eq(test_bytes1, test_bytes3)
        assert not is_different_crypto
        print("  ✓ Cryptography library constant-time functions working")
        
        print("  ✓ Side-Channel Resistance: All tests passed")
        return True
        
    except Exception as e:
        print(f"  ✗ Side-Channel Resistance Error: {e}")
        return False

def run_comprehensive_test():
    """Run comprehensive test of all advanced features"""
    print("Advanced Encryption System - Enhanced Features Test Suite")
    print("=" * 65)
    
    start_time = time.time()
    
    test_results = []
    
    # Run all tests
    tests = [
        ("Hybrid Post-Quantum Cryptography", test_hybrid_pqc),
        ("Envelope Encryption & KMS", test_envelope_encryption_kms),
        ("Enhanced KDF & Password", test_enhanced_kdf_password),
        ("Algorithm Agility & Versioning", test_algorithm_agility_versioning),
        ("Threshold Signatures & Multisig", test_threshold_multisig),
        ("MPC & Secure Enclaves", test_secure_mpc_enclaves),
        ("Side-Channel Resistance", test_side_channel_resistance)
    ]
    
    for test_name, test_function in tests:
        try:
            result = test_function()
            test_results.append((test_name, result))
        except Exception as e:
            print(f"\n✗ {test_name}: Critical error - {e}")
            test_results.append((test_name, False))
    
    # Print results summary
    print("\n" + "=" * 65)
    print("ADVANCED FEATURES TEST RESULTS:")
    print("=" * 65)
    
    passed = 0
    total = len(test_results)
    
    for test_name, result in test_results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status:<8} {test_name}")
        if result:
            passed += 1
    
    end_time = time.time()
    duration = end_time - start_time
    
    print("=" * 65)
    print(f"Tests completed: {passed}/{total} passed ({passed/total*100:.1f}%)")
    print(f"Total time: {duration:.2f} seconds")
    
    if passed == total:
        print("🎉 ALL ADVANCED FEATURES WORKING PERFECTLY!")
        print("✓ Post-Quantum Cryptography (Hybrid)")
        print("✓ Envelope Encryption with KMS/HSM")
        print("✓ Side-Channel Resistant Operations")
        print("✓ Enhanced KDF and Password Security")
        print("✓ Algorithm Agility and Versioning")
        print("✓ Threshold Signatures and Multisig")
        print("✓ MPC and Secure Enclaves")
        print("\n🔒 Your encryption system is now enterprise-ready with")
        print("   state-of-the-art security features!")
        return True
    else:
        print(f"⚠️  {total - passed} test(s) failed. Please review the errors above.")
        return False

if __name__ == '__main__':
    success = run_comprehensive_test()
    sys.exit(0 if success else 1)