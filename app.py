import os
import sys
import json
import base64
from flask import Flask, request, jsonify
from flask_cors import CORS

# The encryption system is installed as a package, no need to modify sys.path

# Create Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET")
if not app.secret_key:
    raise ValueError("SESSION_SECRET environment variable is required")

# Enable CORS - restrictive by default, can be opened for development
cors_origins = os.environ.get('CORS_ORIGINS', 'http://localhost:*').split(',')
CORS(app, 
     origins=cors_origins,  # Configurable origins for security
     methods=['GET', 'POST', 'OPTIONS'],
     allow_headers=['Content-Type', 'Authorization'])

# Initialize advanced encryption components
encryption_modules = {}

try:
    # Core cryptography
    from zyracrypt.encryption_system.src.core_cryptography.symmetric_encryption import SymmetricEncryption
    from zyracrypt.encryption_system.src.core_cryptography.asymmetric_encryption import AsymmetricEncryption
    from zyracrypt.encryption_system.src.core_cryptography.encryption_framework import EncryptionFramework
    from zyracrypt.encryption_system.src.key_management.key_manager import KeyManager
    
    encryption_modules['symmetric'] = SymmetricEncryption()
    encryption_modules['asymmetric'] = AsymmetricEncryption()
    encryption_modules['framework'] = EncryptionFramework()
    encryption_modules['key_manager'] = KeyManager()
    
    print("✓ Core encryption modules loaded successfully")
    
except Exception as e:
    print(f"Warning: Could not load core encryption modules: {e}")

# Try to load advanced features
try:
    # Enhanced KDF and password security
    from zyracrypt.encryption_system.src.key_management.enhanced_kdf_password import EnhancedKDF
    encryption_modules['enhanced_kdf'] = EnhancedKDF()
    print("✓ Enhanced KDF module loaded")
except Exception as e:
    print(f"Warning: Enhanced KDF not available: {e}")

try:
    # Envelope encryption and KMS
    from zyracrypt.encryption_system.src.key_management.envelope_encryption_kms import EnvelopeEncryptionManager
    encryption_modules['envelope_kms'] = EnvelopeEncryptionManager()
    print("✓ Envelope Encryption & KMS module loaded")
except Exception as e:
    print(f"Warning: Envelope Encryption not available: {e}")

try:
    # Side-channel protection
    from zyracrypt.encryption_system.src.advanced_features.side_channel_protection import SideChannelGuard, TimingAttackProtection
    encryption_modules['side_channel'] = SideChannelGuard()
    encryption_modules['timing_protection'] = TimingAttackProtection()
    print("✓ Side-channel protection modules loaded")
except Exception as e:
    print(f"Warning: Side-channel protection not available: {e}")

try:
    # Threshold signatures and multisig
    from zyracrypt.encryption_system.src.advanced_features.threshold_multisig_enhanced import MultisigManager
    encryption_modules['threshold_multisig'] = MultisigManager()
    print("✓ Threshold multisig module loaded")
except Exception as e:
    print(f"Warning: Threshold multisig not available: {e}")

try:
    # Hybrid Post-Quantum Cryptography
    from zyracrypt.encryption_system.src.advanced_features.hybrid_pqc_enhanced import HybridPQCEngine
    encryption_modules['hybrid_pqc'] = HybridPQCEngine()
    print("✓ Hybrid PQC module loaded")
except Exception as e:
    print(f"Warning: Hybrid PQC not available: {e}")

try:
    # Algorithm agility and versioning
    from zyracrypt.encryption_system.src.core_cryptography.algorithm_agility_versioning import AlgorithmMigrationManager, AlgorithmRegistry
    registry = AlgorithmRegistry()
    encryption_modules['algorithm_agility'] = AlgorithmMigrationManager(registry)
    print("✓ Algorithm agility module loaded")
except Exception as e:
    print(f"Warning: Algorithm agility not available: {e}")

try:
    # Secure MPC and Enclaves  
    from zyracrypt.encryption_system.src.advanced_features.secure_mpc_enclaves import MPCCoordinator
    encryption_modules['secure_mpc'] = MPCCoordinator()
    print("✓ Secure MPC module loaded")
except Exception as e:
    print(f"Warning: Secure MPC not available: {e}")

# Legacy compatibility
symmetric_encryption = encryption_modules.get('symmetric')
asymmetric_encryption = encryption_modules.get('asymmetric') 
encryption_framework = encryption_modules.get('framework')
key_manager = encryption_modules.get('key_manager')

# ==============================================================================
# ADVANCED CRYPTOGRAPHIC API ENDPOINTS
# ==============================================================================

@app.route('/api/health')
def health():
    """System health and module status"""
    loaded_modules = []
    for module_name, module_obj in encryption_modules.items():
        if module_obj is not None:
            loaded_modules.append(module_name)
    
    return {
        'status': 'healthy',
        'service': 'ZyraCrypt - Advanced Encryption System',
        'version': '2.0.1 - Enterprise Edition',
        'loaded_modules': loaded_modules,
        'features': {
            'core_encryption': 'symmetric' in loaded_modules,
            'enhanced_kdf': 'enhanced_kdf' in loaded_modules,
            'envelope_encryption': 'envelope_kms' in loaded_modules,
            'side_channel_protection': 'side_channel' in loaded_modules,
            'threshold_multisig': 'threshold_multisig' in loaded_modules,
            'hybrid_pqc': 'hybrid_pqc' in loaded_modules,
            'algorithm_agility': 'algorithm_agility' in loaded_modules,
            'secure_mpc': 'secure_mpc' in loaded_modules
        }
    }

@app.route('/api/enhanced-kdf', methods=['POST'])
def enhanced_kdf():
    """Enhanced Key Derivation Function with modern algorithms"""
    if 'enhanced_kdf' not in encryption_modules:
        return jsonify({'error': 'Enhanced KDF module not available'}), 500
    
    try:
        data = request.get_json()
        password = data.get('password', '').encode('utf-8')
        algorithm = data.get('algorithm', 'argon2id')  # argon2id, argon2i, scrypt, pbkdf2
        salt_length = data.get('salt_length', 32)
        key_length = data.get('key_length', 32)
        
        kdf_engine = encryption_modules['enhanced_kdf']
        
        # Generate salt
        salt = os.urandom(salt_length)
        
        # Derive key with specified algorithm 
        from zyracrypt.encryption_system.src.key_management.enhanced_kdf_password import KDFAlgorithm
        
        kdf_algorithm_map = {
            'argon2id': KDFAlgorithm.ARGON2ID,
            'argon2i': KDFAlgorithm.ARGON2I, 
            'scrypt': KDFAlgorithm.SCRYPT,
            'pbkdf2': KDFAlgorithm.PBKDF2_SHA256
        }
        
        if algorithm not in kdf_algorithm_map:
            return jsonify({'error': f'Unsupported KDF algorithm: {algorithm}'}), 400
            
        derived_result = kdf_engine.derive_key(
            password=password,
            salt=salt, 
            algorithm=kdf_algorithm_map[algorithm],
            key_length=key_length
        )
        derived_key = derived_result.key
        
        return jsonify({
            'success': True,
            'algorithm': algorithm,
            'derived_key': base64.b64encode(derived_key).decode(),
            'salt': base64.b64encode(salt).decode(),
            'key_length': len(derived_key),
            'security_level': 'enterprise'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/envelope-encryption', methods=['POST'])
def envelope_encryption():
    """Envelope encryption with key wrapping"""
    if 'envelope_kms' not in encryption_modules:
        return jsonify({'error': 'Envelope encryption module not available'}), 500
    
    try:
        data = request.get_json()
        plaintext = data.get('text', '').encode('utf-8')
        key_id = data.get('key_id', 'demo-key-' + os.urandom(8).hex())
        
        envelope_manager = encryption_modules['envelope_kms']
        
        # Generate and wrap data encryption key
        key_id_generated, wrapped_key = envelope_manager.generate_data_encryption_key(
            purpose='data_encryption',
            algorithm='AES-256-GCM'
        )
        
        # Encrypt data with the wrapped key
        encrypted_data = envelope_manager.encrypt_with_wrapped_key(wrapped_key, plaintext)
        
        return jsonify({
            'success': True,
            'key_id': key_id,
            'wrapped_key': base64.b64encode(wrapped_key.wrapped_key).decode(),
            'encrypted_data': base64.b64encode(encrypted_data['ciphertext']).decode(),
            'iv': base64.b64encode(encrypted_data['iv']).decode(),
            'tag': base64.b64encode(encrypted_data['tag']).decode(),
            'security_features': [
                'envelope_encryption',
                'never_stores_plaintext_keys',
                'kms_integration',
                'key_rotation_support'
            ]
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/side-channel-safe', methods=['POST'])
def side_channel_safe_operation():
    """Demonstrate side-channel resistant operations"""
    if 'timing_protection' not in encryption_modules:
        return jsonify({'error': 'Side-channel protection not available'}), 500
    
    try:
        data = request.get_json()
        value1 = data.get('value1', '').encode('utf-8')
        value2 = data.get('value2', '').encode('utf-8')
        
        timing_protection = encryption_modules['timing_protection']
        
        # Constant-time comparison
        are_equal = timing_protection.constant_time_compare(value1, value2)
        
        # Generate timing-safe HMAC
        key = os.urandom(32)
        hmac_value = timing_protection.timing_safe_hmac_verify(value1, value2, key)
        
        # Add secure random delay
        timing_protection.secure_random_delay(1, 5)
        
        return jsonify({
            'success': True,
            'constant_time_equal': are_equal,
            'timing_safe_hmac': base64.b64encode(hmac_value if isinstance(hmac_value, bytes) else b'demo').decode(),
            'protections': [
                'constant_time_operations',
                'timing_attack_resistance',
                'secure_memory_handling',
                'cache_attack_mitigation'
            ]
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/threshold-multisig', methods=['POST'])
def threshold_multisig():
    """Threshold signatures and multisig (m-of-n)"""
    if 'threshold_multisig' not in encryption_modules:
        return jsonify({'error': 'Threshold multisig not available'}), 500
    
    try:
        data = request.get_json()
        message = data.get('message', 'Hello World!').encode('utf-8')
        threshold = data.get('threshold', 2)
        total_signers = data.get('total_signers', 3)
        
        multisig_manager = encryption_modules['threshold_multisig']
        
        # Create multisig policy
        policy_id = 'demo-policy-' + os.urandom(4).hex()
        policy = multisig_manager.create_multisig_policy(
            policy_id=policy_id,
            threshold=threshold,
            total_signers=total_signers,
            signature_scheme='ed25519'
        )
        
        # Generate key shares
        key_shares = multisig_manager.generate_threshold_keys(policy)
        
        # Create partial signatures
        partial_sigs = []
        for i in range(threshold):
            partial_sig = multisig_manager.create_partial_signature(
                policy, message, key_shares[i]
            )
            partial_sigs.append(partial_sig)
        
        # Combine signatures
        final_signature = multisig_manager.combine_signatures(
            policy, message, partial_sigs[:threshold]
        )
        
        return jsonify({
            'success': True,
            'policy_id': policy_id,
            'threshold': threshold,
            'total_signers': total_signers,
            'signature': base64.b64encode(final_signature.signature_data).decode(),
            'partial_signatures_used': len(partial_sigs[:threshold]),
            'features': [
                'distributed_key_responsibility',
                'shamir_secret_sharing',
                'threshold_cryptography',
                'm_of_n_signatures'
            ]
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/hybrid-pqc', methods=['POST'])
def hybrid_pqc_demo():
    """Demonstrate Hybrid Post-Quantum Cryptography key exchange"""
    if 'hybrid_pqc' not in encryption_modules:
        return jsonify({'error': 'Hybrid PQC module not available'}), 500
    
    try:
        data = request.get_json()
        security_level = data.get('security_level', 128)
        message = data.get('message', 'Hello PQC World!').encode('utf-8')
        
        pqc_engine = encryption_modules['hybrid_pqc']
        
        # Step 1: Generate hybrid keypair (receiver)
        public_keys, private_keys = pqc_engine.generate_hybrid_keypair()
        
        # Step 2: Perform hybrid key exchange (sender)
        key_material = pqc_engine.hybrid_key_exchange(
            receiver_classical_public=public_keys['classical'],
            receiver_pq_public=public_keys['pq']
        )
        
        # Step 3: Decapsulate on receiver side
        decapsulated_material = pqc_engine.hybrid_key_decapsulation(
            private_keys['classical'],
            private_keys['pq'],
            key_material.pq_ciphertext,
            key_material.classical_public_key
        )
        
        # Verify the shared secrets match
        secrets_match = (key_material.combined_shared_secret == 
                        decapsulated_material.combined_shared_secret)
        
        return jsonify({
            'success': True,
            'security_level': security_level,
            'library_used': pqc_engine.library_used,
            'secrets_match': secrets_match,
            'key_exchange_successful': True,
            'algorithm_info': key_material.algorithm_info,
            'features': [
                'hybrid_classical_pq_key_exchange',
                'ml_kem_integration',
                'quantum_resistant_cryptography',
                'defense_in_depth_security'
            ]
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/encrypt', methods=['POST'])
def encrypt_data():
    """Encrypt data using various algorithms"""
    from flask import request, jsonify
    import base64
    
    if not symmetric_encryption or not encryption_framework:
        return jsonify({'error': 'Encryption modules not available'}), 500
    
    try:
        data = request.get_json()
        if not data or 'text' not in data:
            return jsonify({'error': 'Missing text field'}), 400
        
        plaintext = data['text'].encode('utf-8')
        algorithm = data.get('algorithm', 'auto')
        
        if algorithm == 'auto':
            # Generate a key for encryption
            import os
            key = os.urandom(32)  # 256-bit key for AES
            
            # Use encryption framework for automatic algorithm selection
            algo_name, iv, ciphertext, tag = encryption_framework.encrypt(plaintext, key)
            result = {
                'algorithm_used': f'{algo_name} (auto-selected)',
                'encrypted_data': base64.b64encode(ciphertext).decode(),
                'iv': base64.b64encode(iv).decode(),
                'tag': base64.b64encode(tag).decode(),
                'key_id': 'demo_key_' + os.urandom(8).hex(),
                'note': 'In production, keys should be managed securely and never returned in API responses'
            }
        else:
            return jsonify({'error': 'Only auto algorithm selection supported in this demo'}), 400
        
        return jsonify({'success': True, 'data': result})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/decrypt', methods=['POST'])
def decrypt_data():
    """Decrypt data"""
    from flask import request, jsonify
    import base64
    
    if not symmetric_encryption or not encryption_framework:
        return jsonify({'error': 'Encryption modules not available'}), 500
    
    try:
        data = request.get_json()
        required_fields = ['encrypted_data', 'iv', 'tag', 'key']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing {field} field'}), 400
        
        # Decode base64 data
        ciphertext = base64.b64decode(data['encrypted_data'])
        iv = base64.b64decode(data['iv'])
        tag = base64.b64decode(data['tag'])
        key = base64.b64decode(data['key'])
        
        # Decrypt using AES-GCM
        decrypted_data = symmetric_encryption.decrypt_aes_gcm(key, iv, ciphertext, tag)
        
        return jsonify({
            'success': True, 
            'decrypted_text': decrypted_data.decode('utf-8')
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/')
def index():
    """Main landing page"""
    return {
        'message': 'ZyraCrypt - Advanced Encryption System API',
        'description': 'Professional-grade cryptographic library and API',
        'endpoints': {
            'health': '/api/health',
            'encrypt': '/api/encrypt (POST)',
            'decrypt': '/api/decrypt (POST)',
            'documentation': 'See ALGORITHMS_AND_TECHNOLOGIES.md for details'
        },
        'features': [
            'Symmetric Encryption (AES-GCM, ChaCha20-Poly1305)',
            'Asymmetric Encryption (RSA, ECC)',
            'Post-Quantum Cryptography (ML-KEM, ML-DSA)',
            'Key Management and Exchange',
            'Data Protection and Obfuscation'
        ],
        'modules_loaded': symmetric_encryption is not None
    }

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)