"""
Test suite for newly implemented features:
- Secure Multi-Party Computation
- Homomorphic Encryption
- White-Box Cryptography
"""

import sys
import os

# Test imports
from advanced_features.secure_multi_party_computation import (
    SecureMultiPartyComputation,
    private_sum,
    private_intersection,
    private_average
)
from advanced_features.homomorphic_encryption import (
    HomomorphicEncryption,
    create_homomorphic_system,
    SecureVotingSystem,
    PrivateDataAnalytics
)
from advanced_features.white_box_cryptography import (
    WhiteBoxCryptography,
    DRMProtection,
    protect_key
)


def test_mpc_private_sum():
    """Test MPC private sum computation."""
    print("\n=== Testing MPC Private Sum ===")
    
    # Three parties with private values
    private_values = [10, 20, 30]
    
    # Compute sum without revealing individual values
    result = private_sum(*private_values)
    
    print(f"Private values: [hidden, hidden, hidden]")
    print(f"Computed sum: {result}")
    print(f"Expected sum: {sum(private_values)}")
    
    assert result == sum(private_values), "Private sum incorrect"
    print("✓ MPC private sum works correctly!")
    return True


def test_mpc_private_intersection():
    """Test MPC private set intersection."""
    print("\n=== Testing MPC Private Set Intersection ===")
    
    # Two parties with private sets
    set_a = {"alice", "bob", "charlie", "david"}
    set_b = {"bob", "charlie", "eve", "frank"}
    
    # Compute intersection without revealing non-common elements
    intersection = private_intersection(set_a, set_b)
    
    print(f"Set A size: {len(set_a)}")
    print(f"Set B size: {len(set_b)}")
    print(f"Intersection: {intersection}")
    
    expected = set_a & set_b
    assert intersection == expected, f"Expected {expected}, got {intersection}"
    print("✓ MPC private set intersection works correctly!")
    return True


def test_mpc_secure_voting():
    """Test MPC secure voting."""
    print("\n=== Testing MPC Secure Voting ===")
    
    mpc = SecureMultiPartyComputation()
    
    # 10 voters, 3 candidates
    candidates = ["Alice", "Bob", "Charlie"]
    votes = [0, 1, 0, 2, 1, 0, 1, 1, 0, 2]  # candidate indices
    
    # Compute vote counts without revealing individual votes
    results = mpc.secure_voting(votes, candidates)
    
    print(f"Total voters: {len(votes)}")
    print(f"Vote results: {results}")
    
    # Verify counts
    expected = {"Alice": 4, "Bob": 4, "Charlie": 2}
    assert results == expected, f"Expected {expected}, got {results}"
    print("✓ MPC secure voting works correctly!")
    return True


def test_mpc_secure_average():
    """Test MPC secure average computation."""
    print("\n=== Testing MPC Secure Average ===")
    
    # Five parties with private salaries
    salaries = [50000, 60000, 55000, 70000, 65000]
    
    # Compute average without revealing individual salaries
    avg = private_average(*salaries)
    
    print(f"Number of parties: {len(salaries)}")
    print(f"Computed average: ${avg:,.2f}")
    print(f"Expected average: ${sum(salaries) / len(salaries):,.2f}")
    
    expected_avg = sum(salaries) / len(salaries)
    assert abs(avg - expected_avg) < 0.01, "Average computation incorrect"
    print("✓ MPC secure average works correctly!")
    return True


def test_homomorphic_encryption_basic():
    """Test basic homomorphic encryption operations."""
    print("\n=== Testing Homomorphic Encryption (Basic) ===")
    
    # Create HE system with smaller key for testing
    he = HomomorphicEncryption(key_size=512)
    public_key, private_key = he.generate_keypair()
    
    # Encrypt two numbers
    m1, m2 = 15, 25
    c1 = he.encrypt_for_computation(m1, public_key)
    c2 = he.encrypt_for_computation(m2, public_key)
    
    print(f"Encrypted {m1} and {m2}")
    
    # Add encrypted numbers
    c_sum = he.add_encrypted(c1, c2)
    decrypted_sum = he.decrypt_computation_result(c_sum, private_key)
    
    print(f"Homomorphic addition: {m1} + {m2} = {decrypted_sum}")
    assert decrypted_sum == (m1 + m2), "Homomorphic addition failed"
    
    # Scalar multiplication
    scalar = 3
    c_mult = he.multiply_encrypted(c1, scalar)
    decrypted_mult = he.decrypt_computation_result(c_mult, private_key)
    
    print(f"Scalar multiplication: {scalar} * {m1} = {decrypted_mult}")
    assert decrypted_mult == (scalar * m1), "Scalar multiplication failed"
    
    print("✓ Homomorphic encryption basic operations work correctly!")
    return True


def test_homomorphic_voting():
    """Test secure voting with homomorphic encryption."""
    print("\n=== Testing Homomorphic Encryption Voting ===")
    
    voting = SecureVotingSystem(key_size=512)
    
    # 7 voters cast encrypted votes (1 = yes, 0 = no)
    votes = [1, 1, 0, 1, 1, 0, 1]
    
    print(f"Total voters: {len(votes)}")
    
    for vote in votes:
        voting.cast_vote(vote)
    
    # Tally without decrypting individual votes
    total_yes = voting.tally_votes()
    
    print(f"Yes votes: {total_yes}")
    print(f"No votes: {len(votes) - total_yes}")
    
    expected_yes = sum(votes)
    assert total_yes == expected_yes, f"Expected {expected_yes} yes votes, got {total_yes}"
    print("✓ Homomorphic voting works correctly!")
    return True


def test_homomorphic_data_analytics():
    """Test privacy-preserving data analytics."""
    print("\n=== Testing Homomorphic Data Analytics ===")
    
    analytics = PrivateDataAnalytics(key_size=512)
    
    # Private dataset
    values = [100, 200, 150, 175, 225]
    
    print(f"Dataset size: {len(values)}")
    
    # Compute sum on encrypted data
    encrypted_sum = analytics.compute_encrypted_sum(values)
    print(f"Encrypted sum: {encrypted_sum}")
    
    expected_sum = sum(values)
    assert encrypted_sum == expected_sum, "Encrypted sum incorrect"
    
    # Compute average on encrypted data
    encrypted_avg = analytics.compute_encrypted_average(values)
    print(f"Encrypted average: {encrypted_avg}")
    
    expected_avg = sum(values) / len(values)
    assert abs(encrypted_avg - expected_avg) < 0.01, "Encrypted average incorrect"
    
    # Compute weighted sum
    weights = [1, 2, 1, 3, 1]
    weighted_sum = analytics.compute_weighted_sum(values, weights)
    print(f"Weighted sum: {weighted_sum}")
    
    expected_weighted = sum(v * w for v, w in zip(values, weights))
    assert weighted_sum == expected_weighted, "Weighted sum incorrect"
    
    print("✓ Homomorphic data analytics works correctly!")
    return True


def test_white_box_encryption():
    """Test white-box encryption."""
    print("\n=== Testing White-Box Encryption ===")
    
    wb_crypto = WhiteBoxCryptography()
    
    # Create white-box protected key
    original_key = b"my_secret_key123"
    wb_key_id = wb_crypto.create_white_box_key(original_key)
    
    print(f"Created white-box key: {wb_key_id[:16]}...")
    
    # Encrypt with white-box key
    plaintext = b"sensitive data to protect"
    ciphertext = wb_crypto.encrypt_white_box(plaintext, wb_key_id)
    
    print(f"Encrypted {len(plaintext)} bytes -> {len(ciphertext)} bytes")
    
    # Decrypt with white-box key
    decrypted = wb_crypto.decrypt_white_box(ciphertext, wb_key_id)
    
    print(f"Decrypted successfully")
    
    assert decrypted == plaintext, "White-box encryption/decryption failed"
    print("✓ White-box encryption works correctly!")
    return True


def test_white_box_key_obfuscation():
    """Test key obfuscation."""
    print("\n=== Testing White-Box Key Obfuscation ===")
    
    # Original key
    original_key = b"super_secret_key_12345678901234"
    
    print(f"Original key length: {len(original_key)} bytes")
    
    # Obfuscate key
    obfuscated_key, deobfuscation_data = protect_key(original_key)
    
    print(f"Obfuscated key length: {len(obfuscated_key)} bytes")
    print(f"Deobfuscation data length: {len(deobfuscation_data)} bytes")
    
    # Verify obfuscation changed the key
    assert obfuscated_key != original_key, "Key not obfuscated"
    
    # Deobfuscate
    wb_crypto = WhiteBoxCryptography()
    recovered_key = wb_crypto.deobfuscate_key_storage(obfuscated_key, deobfuscation_data)
    
    print(f"Recovered key matches original")
    
    assert recovered_key == original_key, "Key deobfuscation failed"
    print("✓ White-box key obfuscation works correctly!")
    return True


def test_white_box_drm():
    """Test DRM protection using white-box crypto."""
    print("\n=== Testing White-Box DRM Protection ===")
    
    drm = DRMProtection()
    
    # Protect content key
    content_id = "movie_12345"
    content_key = b"content_encryption_key_123456789"  # 32 bytes
    
    wb_key_id = drm.protect_content_key(content_id, content_key)
    
    print(f"Protected content key for: {content_id}")
    
    # Encrypt content
    content = b"This is the protected movie content" * 10
    encrypted_content = drm.encrypt_content(content_id, content)
    
    print(f"Encrypted content: {len(content)} bytes -> {len(encrypted_content)} bytes")
    
    # Decrypt content using protected key
    decrypted_content = drm.decrypt_content(content_id, encrypted_content)
    
    assert decrypted_content == content, "DRM protection failed"
    print("✓ White-box DRM protection works correctly!")
    return True


def test_white_box_export_import():
    """Test white-box key export and import."""
    print("\n=== Testing White-Box Key Export/Import ===")
    
    wb_crypto = WhiteBoxCryptography()
    
    # Create and export key
    original_key = b"test_key_1234567"
    wb_key_id = wb_crypto.create_white_box_key(original_key)
    
    exported = wb_crypto.export_white_box_key(wb_key_id)
    
    print(f"Exported white-box key")
    print(f"Export data fields: {list(exported.keys())}")
    
    # Create new instance and import
    wb_crypto2 = WhiteBoxCryptography()
    imported_key_id = wb_crypto2.import_white_box_key(exported)
    
    print(f"Imported white-box key")
    
    # Test encryption with imported key
    plaintext = b"test data for import/export"
    ciphertext = wb_crypto2.encrypt_white_box(plaintext, imported_key_id)
    decrypted = wb_crypto2.decrypt_white_box(ciphertext, imported_key_id)
    
    assert decrypted == plaintext, "Export/import failed"
    print("✓ White-box key export/import works correctly!")
    return True


def run_all_tests():
    """Run all tests for new features."""
    print("=" * 60)
    print("Testing Newly Implemented Features")
    print("=" * 60)
    
    tests = [
        # MPC tests
        ("MPC Private Sum", test_mpc_private_sum),
        ("MPC Private Set Intersection", test_mpc_private_intersection),
        ("MPC Secure Voting", test_mpc_secure_voting),
        ("MPC Secure Average", test_mpc_secure_average),
        
        # Homomorphic Encryption tests
        ("Homomorphic Encryption Basic", test_homomorphic_encryption_basic),
        ("Homomorphic Voting", test_homomorphic_voting),
        ("Homomorphic Data Analytics", test_homomorphic_data_analytics),
        
        # White-Box Cryptography tests
        ("White-Box Encryption", test_white_box_encryption),
        ("White-Box Key Obfuscation", test_white_box_key_obfuscation),
        ("White-Box DRM", test_white_box_drm),
        ("White-Box Export/Import", test_white_box_export_import),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
        except Exception as e:
            print(f"\n✗ {test_name} FAILED: {e}")
            import traceback
            traceback.print_exc()
            failed += 1
    
    print("\n" + "=" * 60)
    print(f"Test Results: {passed} passed, {failed} failed out of {len(tests)} total")
    print("=" * 60)
    
    if failed == 0:
        print("\n🎉 All new feature tests passed successfully!")
        return True
    else:
        print(f"\n⚠️  {failed} test(s) failed")
        return False


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
