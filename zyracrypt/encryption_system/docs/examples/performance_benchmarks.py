#!/usr/bin/env python3
"""
ZyraCrypt Example: Performance Benchmarks
Demonstrates: Speed testing, optimization techniques, and performance analysis
Skill Level: Advanced
"""

import os
import sys
import time
import gc
import statistics
from typing import List, Dict, Any, Callable
import tracemalloc

# Add ZyraCrypt to path for development/testing
try:
    from zyracrypt.encryption_system.src.core_cryptography.symmetric_encryption import SymmetricEncryption
    from zyracrypt.encryption_system.src.core_cryptography.asymmetric_encryption import AsymmetricEncryption
    from zyracrypt.encryption_system.src.core_cryptography.encryption_framework import EncryptionFramework
    from zyracrypt.encryption_system.src.key_management.key_manager import KeyManager
    from zyracrypt.encryption_system.src.key_management.enhanced_kdf_password import (
        EnhancedKDF, KDFAlgorithm, SecurityProfile
    )
    from zyracrypt.encryption_system.src.post_quantum_cryptography.post_quantum_crypto import PostQuantumCrypto
except ImportError as e:
    print(f"❌ Import Error: {e}")
    print("Make sure ZyraCrypt is installed: pip install zyracrypt")
    sys.exit(1)


class PerformanceBenchmark:
    """Performance benchmarking utility for ZyraCrypt operations."""
    
    def __init__(self):
        self.results = {}
        
    def benchmark_function(self, name: str, func: Callable, iterations: int = 10, 
                          warmup: int = 2) -> Dict[str, Any]:
        """Benchmark a function with multiple iterations."""
        print(f"\n🏃‍♂️ Benchmarking {name} ({iterations} iterations, {warmup} warmup)...")
        
        # Warmup runs
        for _ in range(warmup):
            try:
                func()
            except:
                pass
        
        # Force garbage collection before benchmarking
        gc.collect()
        
        # Benchmark runs
        times = []
        memory_peaks = []
        
        for i in range(iterations):
            # Start memory tracking
            tracemalloc.start()
            
            start_time = time.perf_counter()
            try:
                result = func()
                success = True
            except Exception as e:
                result = None
                success = False
                print(f"   ❌ Iteration {i+1} failed: {e}")
            
            end_time = time.perf_counter()
            
            # Get memory usage
            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            
            if success:
                execution_time = end_time - start_time
                times.append(execution_time)
                memory_peaks.append(peak)
                print(f"   ✅ Iteration {i+1}: {execution_time:.4f}s, {peak/1024:.1f}KB peak memory")
        
        if not times:
            return {'error': 'All iterations failed'}
        
        # Calculate statistics
        stats = {
            'name': name,
            'iterations': len(times),
            'min_time': min(times),
            'max_time': max(times),
            'mean_time': statistics.mean(times),
            'median_time': statistics.median(times),
            'std_dev': statistics.stdev(times) if len(times) > 1 else 0,
            'total_time': sum(times),
            'avg_memory_peak': statistics.mean(memory_peaks) if memory_peaks else 0,
            'max_memory_peak': max(memory_peaks) if memory_peaks else 0
        }
        
        print(f"   📊 Results: avg={stats['mean_time']:.4f}s, std={stats['std_dev']:.4f}s, mem={stats['avg_memory_peak']/1024:.1f}KB")
        
        self.results[name] = stats
        return stats


def benchmark_symmetric_encryption():
    """Benchmark symmetric encryption algorithms with different data sizes."""
    print("\n🔐 === Symmetric Encryption Benchmarks ===")
    
    benchmark = PerformanceBenchmark()
    sym_enc = SymmetricEncryption()
    key = os.urandom(32)  # 256-bit key
    
    # Test different data sizes
    data_sizes = [
        (100, "100 bytes"),
        (1024, "1 KB"),
        (10 * 1024, "10 KB"),
        (100 * 1024, "100 KB"),
        (1024 * 1024, "1 MB")
    ]
    
    algorithms = [
        ('AES-GCM', lambda data: sym_enc.encrypt_aes_gcm(key, data)),
        ('ChaCha20-Poly1305', lambda data: sym_enc.encrypt_chacha20_poly1305(key, data))
    ]
    
    for size_bytes, size_name in data_sizes:
        test_data = os.urandom(size_bytes)
        print(f"\n--- Testing with {size_name} ---")
        
        for alg_name, encrypt_func in algorithms:
            benchmark.benchmark_function(
                f"{alg_name}_{size_name.replace(' ', '_')}",
                lambda: encrypt_func(test_data),
                iterations=5 if size_bytes <= 10*1024 else 3
            )
    
    # Calculate throughput
    print(f"\n📊 Throughput Analysis:")
    for name, stats in benchmark.results.items():
        if 'bytes' in name or 'KB' in name or 'MB' in name:
            # Extract size from name
            if '100_bytes' in name:
                size = 100
            elif '1_KB' in name:
                size = 1024
            elif '10_KB' in name:
                size = 10 * 1024
            elif '100_KB' in name:
                size = 100 * 1024
            elif '1_MB' in name:
                size = 1024 * 1024
            else:
                continue
                
            throughput = size / stats['mean_time']
            print(f"   • {name}: {throughput / 1024:.1f} KB/s")


def benchmark_asymmetric_encryption():
    """Benchmark asymmetric encryption operations."""
    print("\n🔑 === Asymmetric Encryption Benchmarks ===")
    
    benchmark = PerformanceBenchmark()
    asym_enc = AsymmetricEncryption()
    
    # RSA benchmarks
    print(f"\n--- RSA Operations ---")
    
    rsa_key_sizes = [2048, 3072, 4096]
    for key_size in rsa_key_sizes:
        # Key generation
        benchmark.benchmark_function(
            f"RSA_{key_size}_keygen",
            lambda: asym_enc.generate_rsa_key_pair(key_size),
            iterations=3
        )
        
        # Generate keys for encryption benchmarks
        private_key, public_key = asym_enc.generate_rsa_key_pair(key_size)
        test_data = b"Test message for RSA encryption benchmark!"
        
        # Encryption
        benchmark.benchmark_function(
            f"RSA_{key_size}_encrypt",
            lambda: asym_enc.encrypt_rsa_oaep(public_key, test_data),
            iterations=5
        )
        
        # Decryption
        ciphertext = asym_enc.encrypt_rsa_oaep(public_key, test_data)
        benchmark.benchmark_function(
            f"RSA_{key_size}_decrypt",
            lambda: asym_enc.decrypt_rsa_oaep(private_key, ciphertext),
            iterations=5
        )
    
    # ECC benchmarks
    print(f"\n--- ECC Operations ---")
    
    # Key generation
    benchmark.benchmark_function(
        "ECC_P256_keygen",
        lambda: asym_enc.generate_ecc_key_pair(),
        iterations=10
    )
    
    # Generate keys for signing benchmarks
    ecc_private, ecc_public = asym_enc.generate_ecc_key_pair()
    test_message = b"Test message for ECC signature benchmark!"
    
    # Signing
    benchmark.benchmark_function(
        "ECC_P256_sign",
        lambda: asym_enc.sign_ecc(ecc_private, test_message),
        iterations=10
    )
    
    # Verification
    signature = asym_enc.sign_ecc(ecc_private, test_message)
    benchmark.benchmark_function(
        "ECC_P256_verify",
        lambda: asym_enc.verify_ecc(ecc_public, test_message, signature),
        iterations=10
    )


def benchmark_key_derivation():
    """Benchmark key derivation functions."""
    print("\n🔐 === Key Derivation Function Benchmarks ===")
    
    benchmark = PerformanceBenchmark()
    enhanced_kdf = EnhancedKDF()
    
    password = b"benchmark_password_123!"
    salt = os.urandom(32)
    
    # Test different KDF algorithms and security profiles
    test_cases = [
        (KDFAlgorithm.ARGON2ID, SecurityProfile.INTERACTIVE),
        (KDFAlgorithm.ARGON2ID, SecurityProfile.SENSITIVE),
        (KDFAlgorithm.SCRYPT, SecurityProfile.INTERACTIVE),
        (KDFAlgorithm.SCRYPT, SecurityProfile.SENSITIVE),
        (KDFAlgorithm.PBKDF2_SHA256, SecurityProfile.INTERACTIVE),
        (KDFAlgorithm.PBKDF2_SHA256, SecurityProfile.SENSITIVE),
    ]
    
    for algorithm, profile in test_cases:
        name = f"{algorithm.value}_{profile.value}"
        
        try:
            benchmark.benchmark_function(
                name,
                lambda: enhanced_kdf.derive_key(
                    password=password,
                    salt=salt,
                    algorithm=algorithm,
                    security_profile=profile,
                    key_length=32
                ),
                iterations=3  # KDF is slow, fewer iterations
            )
        except Exception as e:
            print(f"⚠️ Skipping {name}: {e}")


def benchmark_post_quantum():
    """Benchmark post-quantum cryptography operations."""
    print("\n🔮 === Post-Quantum Cryptography Benchmarks ===")
    
    benchmark = PerformanceBenchmark()
    pqc = PostQuantumCrypto()
    
    # ML-KEM key generation
    benchmark.benchmark_function(
        "ML-KEM_keygen",
        lambda: pqc.generate_kem_key_pair(),
        iterations=5
    )
    
    # Generate keys for encapsulation benchmarks
    public_key, private_key = pqc.generate_kem_key_pair()
    
    # ML-KEM encapsulation
    benchmark.benchmark_function(
        "ML-KEM_encapsulate",
        lambda: pqc.encapsulate_kem(public_key),
        iterations=10
    )
    
    # ML-KEM decapsulation
    ciphertext, _ = pqc.encapsulate_kem(public_key)
    benchmark.benchmark_function(
        "ML-KEM_decapsulate",
        lambda: pqc.decapsulate_kem(private_key, ciphertext),
        iterations=10
    )


def benchmark_framework_intelligence():
    """Benchmark the encryption framework's algorithm selection."""
    print("\n🤖 === Encryption Framework Intelligence Benchmarks ===")
    
    benchmark = PerformanceBenchmark()
    framework = EncryptionFramework()
    key = os.urandom(32)
    
    # Test framework with different data sizes
    data_sizes = [
        (100, "100_bytes"),
        (1024, "1_KB"),
        (10 * 1024, "10_KB"),
        (100 * 1024, "100_KB")
    ]
    
    for size_bytes, size_name in data_sizes:
        test_data = os.urandom(size_bytes)
        
        benchmark.benchmark_function(
            f"Framework_auto_{size_name}",
            lambda: framework.encrypt(test_data, key),
            iterations=5
        )
        
        # Compare with manual algorithm selection
        result = framework.encrypt(test_data, key)
        selected_algorithm = result[0]
        
        print(f"   🤖 Framework selected {selected_algorithm} for {size_name}")


def benchmark_memory_usage():
    """Benchmark memory usage patterns."""
    print("\n💾 === Memory Usage Analysis ===")
    
    # Test memory usage for different operations
    test_cases = [
        ("Small encryption (100 bytes)", lambda: encrypt_small_data()),
        ("Large encryption (1 MB)", lambda: encrypt_large_data()),
        ("Key generation (RSA-2048)", lambda: generate_rsa_keys()),
        ("Post-quantum operations", lambda: pq_operations())
    ]
    
    for name, operation in test_cases:
        print(f"\n--- {name} ---")
        
        # Measure memory before
        gc.collect()
        tracemalloc.start()
        
        try:
            operation()
            current, peak = tracemalloc.get_traced_memory()
            
            print(f"✅ Current memory: {current / 1024:.1f} KB")
            print(f"📊 Peak memory: {peak / 1024:.1f} KB")
            
        except Exception as e:
            print(f"❌ Operation failed: {e}")
        finally:
            tracemalloc.stop()


def encrypt_small_data():
    """Helper function for memory testing."""
    sym_enc = SymmetricEncryption()
    key = os.urandom(32)
    data = os.urandom(100)
    return sym_enc.encrypt_aes_gcm(key, data)


def encrypt_large_data():
    """Helper function for memory testing."""
    sym_enc = SymmetricEncryption()
    key = os.urandom(32)
    data = os.urandom(1024 * 1024)  # 1 MB
    return sym_enc.encrypt_aes_gcm(key, data)


def generate_rsa_keys():
    """Helper function for memory testing."""
    asym_enc = AsymmetricEncryption()
    return asym_enc.generate_rsa_key_pair(2048)


def pq_operations():
    """Helper function for memory testing."""
    pqc = PostQuantumCrypto()
    public_key, private_key = pqc.generate_kem_key_pair()
    ciphertext, secret = pqc.encapsulate_kem(public_key)
    return pqc.decapsulate_kem(private_key, ciphertext)


def generate_performance_report(results: Dict[str, Any]):
    """Generate a comprehensive performance report."""
    print("\n📋 === Performance Report ===")
    
    # Group results by category
    categories = {
        'Symmetric Encryption': [k for k in results.keys() if any(alg in k for alg in ['AES', 'ChaCha20'])],
        'Asymmetric Encryption': [k for k in results.keys() if any(alg in k for alg in ['RSA', 'ECC'])],
        'Key Derivation': [k for k in results.keys() if any(alg in k for alg in ['argon2', 'scrypt', 'pbkdf2'])],
        'Post-Quantum': [k for k in results.keys() if 'ML-KEM' in k],
        'Framework': [k for k in results.keys() if 'Framework' in k]
    }
    
    for category, test_names in categories.items():
        if not test_names:
            continue
            
        print(f"\n🏷️ {category}:")
        
        for test_name in sorted(test_names):
            if test_name in results:
                stats = results[test_name]
                print(f"   • {test_name}: {stats['mean_time']:.4f}s ±{stats['std_dev']:.4f}s")
        
        # Find fastest and slowest in category
        if len(test_names) > 1:
            category_results = {k: results[k] for k in test_names if k in results}
            if category_results:
                fastest = min(category_results.items(), key=lambda x: x[1]['mean_time'])
                slowest = max(category_results.items(), key=lambda x: x[1]['mean_time'])
                
                print(f"     ⚡ Fastest: {fastest[0]} ({fastest[1]['mean_time']:.4f}s)")
                print(f"     🐌 Slowest: {slowest[0]} ({slowest[1]['mean_time']:.4f}s)")
                print(f"     📊 Speed ratio: {slowest[1]['mean_time'] / fastest[1]['mean_time']:.1f}x")


def optimization_recommendations():
    """Provide optimization recommendations based on benchmarks."""
    print("\n🚀 === Optimization Recommendations ===")
    
    recommendations = [
        {
            'category': 'Algorithm Selection',
            'tips': [
                'Use AES-GCM for small to medium data (< 100KB)',
                'Consider ChaCha20-Poly1305 for software-only environments',
                'Use ECC instead of RSA for better performance',
                'Implement hybrid post-quantum for future-proofing'
            ]
        },
        {
            'category': 'Key Management',
            'tips': [
                'Cache encryption objects to avoid reinitializtion',
                'Use Argon2id with Interactive profile for user passwords',
                'Use HKDF for deriving multiple keys from one master key',
                'Implement key rotation policies with gradual migration'
            ]
        },
        {
            'category': 'Memory Optimization',
            'tips': [
                'Process large files in chunks to limit memory usage',
                'Use secure memory cleanup after operations',
                'Monitor memory peaks in production environments',
                'Consider memory-mapped files for very large datasets'
            ]
        },
        {
            'category': 'Performance Tuning',
            'tips': [
                'Use the encryption framework for automatic optimization',
                'Batch multiple operations when possible',
                'Profile your specific use case and workload',
                'Enable hardware acceleration where available'
            ]
        }
    ]
    
    for rec in recommendations:
        print(f"\n🎯 {rec['category']}:")
        for tip in rec['tips']:
            print(f"   • {tip}")


def main():
    """Main function to run all performance benchmarks."""
    print("🚀 ZyraCrypt Performance Benchmarks")
    print("=" * 50)
    print("⚠️ Note: Benchmarks may take several minutes to complete...")
    
    start_time = time.time()
    
    try:
        # Run all benchmarks
        benchmark_symmetric_encryption()
        benchmark_asymmetric_encryption()
        benchmark_key_derivation()
        benchmark_post_quantum()
        benchmark_framework_intelligence()
        benchmark_memory_usage()
        
        total_time = time.time() - start_time
        
        print(f"\n" + "=" * 50)
        print(f"✅ All benchmarks completed in {total_time:.1f} seconds!")
        
        # Generate comprehensive report
        benchmark = PerformanceBenchmark()
        generate_performance_report(benchmark.results)
        optimization_recommendations()
        
        print(f"\n📊 System Information:")
        print(f"   • Python version: {sys.version.split()[0]}")
        print(f"   • Platform: {sys.platform}")
        print(f"   • Total benchmark time: {total_time:.1f} seconds")
        
        print(f"\n📚 Next Steps:")
        print(f"   • Use these benchmarks to optimize your specific use case")
        print(f"   • Monitor performance in production environments")
        print(f"   • Regular benchmarking with new versions")
        print(f"   • Consider hardware acceleration for high-throughput needs")
        
        return 0
        
    except Exception as e:
        print(f"\n❌ Error during benchmark execution: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())