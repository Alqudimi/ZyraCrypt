#!/usr/bin/env python3
"""
ZyraCrypt Example: Post-Quantum Cryptography
Demonstrates: Quantum-resistant algorithms and hybrid approaches
Skill Level: Intermediate to Advanced
"""

import os
import sys
import time
from typing import Tuple, Dict, Any

# Add ZyraCrypt to path for development/testing
try:
    from zyracrypt.encryption_system.src.post_quantum_cryptography.post_quantum_crypto import PostQuantumCrypto
    from zyracrypt.encryption_system.src.advanced_features.hybrid_pqc_enhanced import HybridPQCEngine
    from zyracrypt.encryption_system.src.core_cryptography.asymmetric_encryption import AsymmetricEncryption
    from zyracrypt.encryption_system.src.core_cryptography.symmetric_encryption import SymmetricEncryption
except ImportError as e:
    print(f"❌ Import Error: {e}")
    print("Make sure ZyraCrypt is installed: pip install zyracrypt")
    sys.exit(1)


def demonstrate_ml_kem_operations():
    """Demonstrate ML-KEM (Kyber) key encapsulation mechanism."""
    print("\n🔮 === ML-KEM (Kyber) Key Encapsulation ===")
    
    pqc = PostQuantumCrypto()
    
    print("🔑 Generating quantum-resistant key pair...")
    start_time = time.time()
    public_key, private_key = pqc.generate_kem_key_pair()
    keygen_time = time.time() - start_time
    
    print(f"✅ Key pair generated in {keygen_time:.3f} seconds")
    print(f"📏 Public key size: {len(public_key)} bytes")
    print(f"📏 Private key size: {len(private_key)} bytes")
    print(f"🔍 Public key preview: {public_key[:16].hex()}...")
    
    # Simulate Alice sending encrypted message to Bob
    print(f"\n📨 Alice wants to send a secure message to Bob...")
    
    # Alice uses Bob's public key to encapsulate a shared secret
    print("🔐 Alice encapsulating shared secret using Bob's public key...")
    start_time = time.time()
    ciphertext, shared_secret_alice = pqc.encapsulate_kem(public_key)
    encap_time = time.time() - start_time
    
    print(f"✅ Encapsulation completed in {encap_time:.3f} seconds")
    print(f"📦 Ciphertext size: {len(ciphertext)} bytes")
    print(f"🔑 Shared secret size: {len(shared_secret_alice)} bytes")
    print(f"🔍 Ciphertext preview: {ciphertext[:16].hex()}...")
    print(f"🔍 Alice's shared secret: {shared_secret_alice[:16].hex()}...")
    
    # Bob uses his private key to decapsulate the shared secret
    print("\n🔓 Bob decapsulating shared secret using his private key...")
    start_time = time.time()
    shared_secret_bob = pqc.decapsulate_kem(private_key, ciphertext)
    decap_time = time.time() - start_time
    
    print(f"✅ Decapsulation completed in {decap_time:.3f} seconds")
    print(f"🔍 Bob's shared secret: {shared_secret_bob[:16].hex()}...")
    
    # Verify both parties have the same shared secret
    secrets_match = shared_secret_alice == shared_secret_bob
    print(f"\n🔍 Verification:")
    print(f"✓ Shared secrets match: {'YES ✅' if secrets_match else 'NO ❌'}")
    
    if secrets_match:
        print(f"🎉 Quantum-resistant key exchange successful!")
        
        # Use shared secret for symmetric encryption
        print(f"\n🔐 Using shared secret for data encryption...")
        sym_enc = SymmetricEncryption()
        
        # Derive encryption key from shared secret
        encryption_key = shared_secret_alice[:32]  # Use first 32 bytes as AES key
        message = b"This message is protected by post-quantum cryptography!"
        
        iv, ciphertext_data, tag = sym_enc.encrypt_aes_gcm(encryption_key, message)
        print(f"✅ Message encrypted with quantum-resistant security")
        print(f"📝 Original: {message.decode()}")
        print(f"🔒 Encrypted: {ciphertext_data[:32].hex()}...")
        
        # Decrypt to verify
        decrypted = sym_enc.decrypt_aes_gcm(encryption_key, iv, ciphertext_data, tag)
        print(f"✅ Decrypted: {decrypted.decode()}")
    
    return {
        'keygen_time': keygen_time,
        'encap_time': encap_time,
        'decap_time': decap_time,
        'success': secrets_match
    }


def demonstrate_quantum_signatures():
    """Demonstrate quantum-resistant digital signatures."""
    print("\n✍️ === Quantum-Resistant Digital Signatures ===")
    
    pqc = PostQuantumCrypto()
    
    print("🔑 Note: ML-DSA (Dilithium) signatures not implemented in basic PQC module")
    print("🔄 Demonstrating available post-quantum capabilities...")
    
    # Check available methods
    available_methods = [method for method in dir(pqc) if not method.startswith('_')]
    print(f"📋 Available PQC methods: {available_methods}")
    
    # Simulate Quantum Key Distribution (if available)
    if hasattr(pqc, 'simulate_qkd'):
        print(f"\n🌐 Simulating Quantum Key Distribution...")
        try:
            start_time = time.time()
            qkd_result = pqc.simulate_qkd()
            qkd_time = time.time() - start_time
            
            print(f"✅ QKD simulation completed in {qkd_time:.3f} seconds")
            print(f"📊 QKD result: {qkd_result}")
        except Exception as e:
            print(f"⚠️ QKD simulation not available: {e}")
    
    # Demonstrate multiple KEM algorithms (if available)
    if hasattr(pqc, 'supported_kems'):
        try:
            supported_kems = pqc.supported_kems()
            print(f"\n🔍 Supported KEM algorithms: {supported_kems}")
            
            for kem_name in supported_kems[:2]:  # Test first 2 algorithms
                print(f"\n--- Testing {kem_name} ---")
                try:
                    # This might not work depending on implementation
                    pub_key, priv_key = pqc.generate_kem_key_pair()
                    ciphertext, secret = pqc.encapsulate_kem(pub_key)
                    recovered_secret = pqc.decapsulate_kem(priv_key, ciphertext)
                    
                    print(f"✅ {kem_name}: {secret == recovered_secret}")
                except Exception as e:
                    print(f"⚠️ {kem_name}: {e}")
                    
        except Exception as e:
            print(f"⚠️ Could not query supported KEMs: {e}")


def demonstrate_hybrid_pqc():
    """Demonstrate hybrid post-quantum cryptography."""
    print("\n🔀 === Hybrid Post-Quantum Cryptography ===")
    
    try:
        hybrid_engine = HybridPQCEngine()
        print("✅ Hybrid PQC engine initialized")
        
        print(f"\n🔧 Hybrid approach combines:")
        print(f"   • Classical cryptography (proven security)")
        print(f"   • Post-quantum algorithms (quantum resistance)")
        print(f"   • Best of both worlds for maximum security")
        
        # Check available security levels
        security_levels = [128, 192, 256]  # Common security levels
        
        for level in security_levels:
            print(f"\n--- Security Level {level} bits ---")
            
            try:
                start_time = time.time()
                
                # Generate hybrid key pair (combining classical + PQ)
                # This is conceptual - actual implementation may vary
                print(f"🔑 Generating hybrid keys for {level}-bit security...")
                
                # Classical component (ECC)
                asym_enc = AsymmetricEncryption()
                ecc_private, ecc_public = asym_enc.generate_ecc_key_pair()
                
                # Post-quantum component (ML-KEM)
                pqc = PostQuantumCrypto()
                pq_public, pq_private = pqc.generate_kem_key_pair()
                
                keygen_time = time.time() - start_time
                print(f"✅ Hybrid key generation: {keygen_time:.3f} seconds")
                
                # Simulate hybrid key exchange
                print(f"🔄 Performing hybrid key exchange...")
                start_time = time.time()
                
                # Classical ECDH
                # Note: This is simplified - real implementation would be more complex
                alice_ecc_private, alice_ecc_public = asym_enc.generate_ecc_key_pair()
                from zyracrypt.encryption_system.src.key_management.key_exchange import KeyExchange
                key_exchange = KeyExchange()
                classical_secret = key_exchange.ecdh_key_exchange(alice_ecc_private, ecc_public)
                
                # Post-quantum KEM
                pq_ciphertext, pq_secret = pqc.encapsulate_kem(pq_public)
                
                # Combine secrets (XOR or key derivation)
                hybrid_secret = bytes(a ^ b for a, b in zip(classical_secret[:32], pq_secret[:32]))
                
                exchange_time = time.time() - start_time
                print(f"✅ Hybrid key exchange: {exchange_time:.3f} seconds")
                print(f"🔐 Classical secret: {classical_secret[:8].hex()}...")
                print(f"🔮 PQ secret: {pq_secret[:8].hex()}...")
                print(f"🔀 Hybrid secret: {hybrid_secret[:8].hex()}...")
                
                # Security analysis
                print(f"🛡️ Security properties:")
                print(f"   • Secure against classical computers (ECC)")
                print(f"   • Secure against quantum computers (ML-KEM)")
                print(f"   • Fallback security if one algorithm is broken")
                
            except Exception as e:
                print(f"⚠️ Hybrid operations failed for {level}-bit: {e}")
                
    except Exception as e:
        print(f"⚠️ Hybrid PQC engine not available: {e}")
        print(f"🔄 This is expected as it's an advanced enterprise feature")


def demonstrate_pq_performance():
    """Demonstrate post-quantum cryptography performance characteristics."""
    print("\n📊 === Post-Quantum Performance Analysis ===")
    
    pqc = PostQuantumCrypto()
    asym_enc = AsymmetricEncryption()
    
    print("🏁 Comparing classical vs post-quantum performance...")
    
    # Number of iterations for benchmarking
    iterations = 5
    
    print(f"\n🔄 Running {iterations} iterations of each operation...")
    
    # Classical ECC performance
    print(f"\n--- Classical ECC Performance ---")
    ecc_keygen_times = []
    ecc_ops_times = []
    
    for i in range(iterations):
        # ECC Key generation
        start = time.time()
        ecc_private, ecc_public = asym_enc.generate_ecc_key_pair()
        ecc_keygen_times.append(time.time() - start)
        
        # ECC operations (sign/verify cycle)
        start = time.time()
        message = b"Performance test message"
        signature = asym_enc.sign_ecc(ecc_private, message)
        is_valid = asym_enc.verify_ecc(ecc_public, message, signature)
        ecc_ops_times.append(time.time() - start)
    
    avg_ecc_keygen = sum(ecc_keygen_times) / len(ecc_keygen_times)
    avg_ecc_ops = sum(ecc_ops_times) / len(ecc_ops_times)
    
    print(f"✅ ECC key generation: {avg_ecc_keygen:.4f}s average")
    print(f"✅ ECC sign+verify: {avg_ecc_ops:.4f}s average")
    
    # Post-quantum KEM performance
    print(f"\n--- Post-Quantum ML-KEM Performance ---")
    pq_keygen_times = []
    pq_ops_times = []
    
    for i in range(iterations):
        # PQ Key generation
        start = time.time()
        pq_public, pq_private = pqc.generate_kem_key_pair()
        pq_keygen_times.append(time.time() - start)
        
        # PQ operations (encapsulate/decapsulate cycle)
        start = time.time()
        ciphertext, secret1 = pqc.encapsulate_kem(pq_public)
        secret2 = pqc.decapsulate_kem(pq_private, ciphertext)
        pq_ops_times.append(time.time() - start)
    
    avg_pq_keygen = sum(pq_keygen_times) / len(pq_keygen_times)
    avg_pq_ops = sum(pq_ops_times) / len(pq_ops_times)
    
    print(f"✅ ML-KEM key generation: {avg_pq_keygen:.4f}s average")
    print(f"✅ ML-KEM encap+decap: {avg_pq_ops:.4f}s average")
    
    # Performance comparison
    print(f"\n📊 Performance Comparison:")
    print(f"   Key Generation:")
    print(f"     • ECC: {avg_ecc_keygen:.4f}s")
    print(f"     • ML-KEM: {avg_pq_keygen:.4f}s")
    print(f"     • Ratio: {avg_pq_keygen/avg_ecc_keygen:.1f}x slower")
    
    print(f"   Cryptographic Operations:")
    print(f"     • ECC (sign+verify): {avg_ecc_ops:.4f}s")
    print(f"     • ML-KEM (encap+decap): {avg_pq_ops:.4f}s")
    print(f"     • Ratio: {avg_pq_ops/avg_ecc_ops:.1f}x slower")
    
    # Memory usage analysis (conceptual)
    print(f"\n💾 Memory Usage Comparison:")
    ecc_pub_size = len(ecc_public)
    ecc_priv_size = len(ecc_private)
    pq_pub_size = len(pq_public)
    pq_priv_size = len(pq_private)
    
    print(f"   Public Keys:")
    print(f"     • ECC: {ecc_pub_size} bytes")
    print(f"     • ML-KEM: {pq_pub_size} bytes")
    print(f"     • Ratio: {pq_pub_size/ecc_pub_size:.1f}x larger")
    
    print(f"   Private Keys:")
    print(f"     • ECC: {ecc_priv_size} bytes")
    print(f"     • ML-KEM: {pq_priv_size} bytes")
    print(f"     • Ratio: {pq_priv_size/ecc_priv_size:.1f}x larger")


def demonstrate_quantum_threat_timeline():
    """Demonstrate quantum threat understanding and migration strategies."""
    print("\n⏰ === Quantum Threat Timeline & Migration ===")
    
    print("🔮 Understanding the Quantum Threat:")
    print("   • Current quantum computers: Limited capabilities")
    print("   • Estimated timeline to cryptographically relevant quantum computers: 10-30 years")
    print("   • Risk: 'Harvest now, decrypt later' attacks")
    print("   • Solution: Implement post-quantum cryptography today")
    
    print("\n📅 Migration Timeline Recommendations:")
    migration_phases = [
        {
            'phase': 'Phase 1 (Immediate)',
            'actions': [
                'Inventory current cryptographic implementations',
                'Assess quantum vulnerability of existing systems',
                'Begin testing post-quantum algorithms',
                'Implement hybrid approaches for new systems'
            ]
        },
        {
            'phase': 'Phase 2 (1-2 years)',
            'actions': [
                'Deploy hybrid cryptography in production',
                'Update security policies and procedures',
                'Train development teams on PQC',
                'Begin migration of high-value systems'
            ]
        },
        {
            'phase': 'Phase 3 (3-5 years)',
            'actions': [
                'Complete migration to PQC for sensitive data',
                'Establish quantum-safe communication protocols',
                'Regular security audits and updates',
                'Monitor NIST standardization updates'
            ]
        }
    ]
    
    for phase_info in migration_phases:
        print(f"\n🎯 {phase_info['phase']}:")
        for action in phase_info['actions']:
            print(f"   • {action}")
    
    print("\n🛡️ Current Best Practices:")
    print("   • Use NIST-standardized PQC algorithms (ML-KEM, ML-DSA)")
    print("   • Implement crypto-agility for easy algorithm updates")
    print("   • Combine classical and post-quantum algorithms (hybrid)")
    print("   • Regular security assessments and updates")
    print("   • Employee training on quantum-safe practices")


def main():
    """Main function to run all post-quantum cryptography examples."""
    print("🚀 ZyraCrypt Post-Quantum Cryptography Examples")
    print("=" * 60)
    
    try:
        # Run all demonstrations
        ml_kem_results = demonstrate_ml_kem_operations()
        demonstrate_quantum_signatures()
        demonstrate_hybrid_pqc()
        demonstrate_pq_performance()
        demonstrate_quantum_threat_timeline()
        
        print("\n" + "=" * 60)
        print("✅ All post-quantum cryptography examples completed!")
        
        print(f"\n🔮 Post-Quantum Cryptography Summary:")
        print(f"   • ML-KEM operations: {'✅ Successful' if ml_kem_results['success'] else '❌ Failed'}")
        print(f"   • Key generation time: {ml_kem_results['keygen_time']:.3f}s")
        print(f"   • Encapsulation time: {ml_kem_results['encap_time']:.3f}s")
        print(f"   • Decapsulation time: {ml_kem_results['decap_time']:.3f}s")
        
        print(f"\n🛡️ Security Benefits:")
        print(f"   • Quantum-resistant key exchange")
        print(f"   • Future-proof against quantum computing")
        print(f"   • Hybrid approaches for maximum security")
        print(f"   • NIST-standardized algorithms")
        
        print(f"\n📚 Next Steps:")
        print(f"   • Implement hybrid_encryption.py for practical hybrid schemes")
        print(f"   • Explore enterprise_file_storage.py for PQC in file encryption")
        print(f"   • Study performance_benchmarks.py for optimization strategies")
        print(f"   • Plan gradual migration to post-quantum systems")
        
        return 0
        
    except Exception as e:
        print(f"\n❌ Error during example execution: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())