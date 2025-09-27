#!/usr/bin/env python3
"""
ZyraCrypt Example: REST API Usage
Demonstrates: ZyraCrypt REST API integration and usage patterns
Skill Level: Intermediate
"""

import os
import sys
import time
import json
import requests
import subprocess
import signal
from typing import Dict, Any, Optional

# API Configuration
API_BASE_URL = "http://localhost:5000"
API_ENDPOINTS = {
    'health': '/api/health',
    'encrypt': '/api/encrypt',
    'decrypt': '/api/decrypt',
    'generate_key': '/api/generate-key',
    'derive_key': '/api/derive-key'
}


class ZyraCryptAPIClient:
    """Client for interacting with ZyraCrypt REST API."""
    
    def __init__(self, base_url: str = API_BASE_URL):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'ZyraCrypt-API-Client/1.0'
        })
    
    def _make_request(self, method: str, endpoint: str, data: Optional[Dict] = None) -> Dict[str, Any]:
        """Make HTTP request to API endpoint."""
        url = f"{self.base_url}{endpoint}"
        
        try:
            if method.upper() == 'GET':
                response = self.session.get(url)
            elif method.upper() == 'POST':
                response = self.session.post(url, json=data)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            print(f"❌ API request failed: {e}")
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_detail = e.response.json()
                    print(f"   Error details: {error_detail}")
                except:
                    print(f"   Response text: {e.response.text}")
            raise
    
    def health_check(self) -> Dict[str, Any]:
        """Check API health status."""
        return self._make_request('GET', API_ENDPOINTS['health'])
    
    def encrypt_text(self, text: str, algorithm: str = "auto") -> Dict[str, Any]:
        """Encrypt text using specified algorithm."""
        data = {
            "text": text,
            "algorithm": algorithm
        }
        return self._make_request('POST', API_ENDPOINTS['encrypt'], data)
    
    def generate_key(self, key_type: str = "aes_256") -> Dict[str, Any]:
        """Generate encryption key."""
        data = {"key_type": key_type}
        return self._make_request('POST', API_ENDPOINTS['generate_key'], data)
    
    def derive_key(self, password: str, algorithm: str = "argon2id") -> Dict[str, Any]:
        """Derive key from password."""
        data = {
            "password": password,
            "algorithm": algorithm
        }
        return self._make_request('POST', API_ENDPOINTS['derive_key'], data)


def check_server_running(client: ZyraCryptAPIClient) -> bool:
    """Check if ZyraCrypt API server is running."""
    try:
        response = client.health_check()
        return response.get('status') == 'healthy'
    except:
        return False


def start_api_server() -> Optional[subprocess.Popen]:
    """Start the ZyraCrypt API server if not running."""
    print("🚀 Starting ZyraCrypt API server...")
    
    # Set required environment variables
    env = os.environ.copy()
    if 'SESSION_SECRET' not in env:
        env['SESSION_SECRET'] = os.urandom(32).hex()
        print("🔑 Generated SESSION_SECRET for demo")
    
    try:
        # Start server in background
        process = subprocess.Popen(
            [sys.executable, 'main.py'],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=os.setsid if hasattr(os, 'setsid') else None
        )
        
        # Wait for server to start
        print("⏳ Waiting for server to start...")
        for i in range(10):
            time.sleep(1)
            client = ZyraCryptAPIClient()
            if check_server_running(client):
                print("✅ API server started successfully!")
                return process
            print(f"   Attempt {i+1}/10...")
        
        print("❌ Server failed to start within timeout")
        process.terminate()
        return None
        
    except Exception as e:
        print(f"❌ Failed to start server: {e}")
        return None


def demonstrate_health_check():
    """Demonstrate API health check endpoint."""
    print("\n💓 === API Health Check ===")
    
    client = ZyraCryptAPIClient()
    
    try:
        start_time = time.time()
        health_response = client.health_check()
        response_time = time.time() - start_time
        
        print(f"✅ Health check successful!")
        print(f"📊 Response: {json.dumps(health_response, indent=2)}")
        print(f"⏱️ Response time: {response_time:.3f} seconds")
        
        # Verify expected fields
        expected_fields = ['status', 'timestamp', 'version']
        for field in expected_fields:
            if field in health_response:
                print(f"✓ Field '{field}': {health_response[field]}")
            else:
                print(f"⚠️ Missing field: {field}")
                
    except Exception as e:
        print(f"❌ Health check failed: {e}")


def demonstrate_text_encryption():
    """Demonstrate text encryption via API."""
    print("\n🔐 === Text Encryption via API ===")
    
    client = ZyraCryptAPIClient()
    
    # Test messages
    test_messages = [
        "Hello, ZyraCrypt API!",
        "This is a longer message to test encryption performance and handling of different text lengths.",
        "🔒 Unicode test: 你好世界 🌍 Emoji test! 🚀"
    ]
    
    algorithms = ["auto", "aes_gcm", "chacha20_poly1305"]
    
    for algorithm in algorithms:
        print(f"\n--- Testing {algorithm.upper()} algorithm ---")
        
        for i, message in enumerate(test_messages, 1):
            print(f"\n📝 Test message {i}: {message[:50]}{'...' if len(message) > 50 else ''}")
            
            try:
                start_time = time.time()
                response = client.encrypt_text(message, algorithm)
                request_time = time.time() - start_time
                
                print(f"✅ Encryption successful!")
                print(f"🤖 Selected algorithm: {response.get('algorithm', 'unknown')}")
                print(f"📏 Original length: {len(message)} chars")
                print(f"📏 Encrypted data length: {len(response.get('encrypted_data', ''))}")
                print(f"⏱️ Request time: {request_time:.3f} seconds")
                
                # Show limited encrypted data preview
                encrypted_preview = response.get('encrypted_data', '')[:100]
                print(f"🔒 Encrypted preview: {encrypted_preview}...")
                
                # Check for security metadata
                if 'metadata' in response:
                    metadata = response['metadata']
                    print(f"📊 Encryption metadata:")
                    for key, value in metadata.items():
                        print(f"   • {key}: {value}")
                
            except Exception as e:
                print(f"❌ Encryption failed: {e}")


def demonstrate_key_generation():
    """Demonstrate key generation via API."""
    print("\n🔑 === Key Generation via API ===")
    
    client = ZyraCryptAPIClient()
    
    key_types = ["aes_128", "aes_256", "chacha20", "rsa_2048", "ecc_p256"]
    
    for key_type in key_types:
        print(f"\n--- Generating {key_type.upper()} key ---")
        
        try:
            start_time = time.time()
            response = client.generate_key(key_type)
            generation_time = time.time() - start_time
            
            print(f"✅ Key generation successful!")
            print(f"🔑 Key type: {response.get('key_type', 'unknown')}")
            print(f"📏 Key length: {response.get('key_length', 'unknown')} bits")
            print(f"⏱️ Generation time: {generation_time:.3f} seconds")
            
            # Show key preview (for demo - never do this in production!)
            if 'key_preview' in response:
                print(f"👁️ Key preview: {response['key_preview']}...")
            
            # Security information
            if 'security_info' in response:
                security = response['security_info']
                print(f"🛡️ Security information:")
                for key, value in security.items():
                    print(f"   • {key}: {value}")
            
        except Exception as e:
            print(f"❌ Key generation failed: {e}")


def demonstrate_key_derivation():
    """Demonstrate password-based key derivation via API."""
    print("\n🔐 === Password-Based Key Derivation via API ===")
    
    client = ZyraCryptAPIClient()
    
    # Test passwords and algorithms
    test_cases = [
        ("simple_password", "argon2id"),
        ("complex_P@ssw0rd!123", "argon2id"),
        ("long_passphrase_with_multiple_words_for_security", "scrypt"),
        ("unicode_密码_🔒", "pbkdf2")
    ]
    
    for password, algorithm in test_cases:
        print(f"\n--- Testing {algorithm.upper()} with password length {len(password)} ---")
        
        try:
            start_time = time.time()
            response = client.derive_key(password, algorithm)
            derivation_time = time.time() - start_time
            
            print(f"✅ Key derivation successful!")
            print(f"🔐 Algorithm: {response.get('algorithm', 'unknown')}")
            print(f"📏 Derived key length: {response.get('key_length', 'unknown')} bits")
            print(f"⏱️ Derivation time: {derivation_time:.3f} seconds")
            
            # Show security parameters
            if 'parameters' in response:
                params = response['parameters']
                print(f"⚙️ KDF parameters:")
                for key, value in params.items():
                    print(f"   • {key}: {value}")
            
            # Security strength indicator
            if 'security_level' in response:
                level = response['security_level']
                print(f"🛡️ Security level: {level}")
            
        except Exception as e:
            print(f"❌ Key derivation failed: {e}")


def demonstrate_api_error_handling():
    """Demonstrate API error handling and edge cases."""
    print("\n⚠️ === API Error Handling ===")
    
    client = ZyraCryptAPIClient()
    
    # Test cases that should produce errors
    error_test_cases = [
        {
            'name': 'Invalid algorithm',
            'action': lambda: client.encrypt_text("test", "invalid_algorithm"),
            'expected': 'algorithm not supported'
        },
        {
            'name': 'Empty text encryption',
            'action': lambda: client.encrypt_text("", "aes_gcm"),
            'expected': 'empty input'
        },
        {
            'name': 'Invalid key type',
            'action': lambda: client.generate_key("invalid_key_type"),
            'expected': 'key type not supported'
        },
        {
            'name': 'Weak password',
            'action': lambda: client.derive_key("123", "argon2id"),
            'expected': 'password too weak'
        }
    ]
    
    for test_case in error_test_cases:
        print(f"\n🧪 Testing: {test_case['name']}")
        
        try:
            response = test_case['action']()
            print(f"⚠️ Expected error but got response: {response}")
            
        except requests.exceptions.HTTPError as e:
            print(f"✅ Caught expected HTTP error: {e.response.status_code}")
            try:
                error_detail = e.response.json()
                print(f"📝 Error details: {error_detail}")
            except:
                print(f"📝 Error text: {e.response.text}")
                
        except Exception as e:
            print(f"❌ Unexpected error type: {e}")


def demonstrate_performance_testing():
    """Demonstrate API performance testing."""
    print("\n📊 === API Performance Testing ===")
    
    client = ZyraCryptAPIClient()
    
    # Performance test configurations
    test_configs = [
        {'size': 100, 'iterations': 10, 'name': 'Small messages'},
        {'size': 1000, 'iterations': 5, 'name': 'Medium messages'},
        {'size': 10000, 'iterations': 3, 'name': 'Large messages'}
    ]
    
    for config in test_configs:
        print(f"\n--- {config['name']} ({config['size']} bytes, {config['iterations']} iterations) ---")
        
        # Generate test message
        test_message = "x" * config['size']
        times = []
        
        for i in range(config['iterations']):
            try:
                start_time = time.time()
                response = client.encrypt_text(test_message)
                request_time = time.time() - start_time
                times.append(request_time)
                
                print(f"  Iteration {i+1}: {request_time:.3f}s")
                
            except Exception as e:
                print(f"  Iteration {i+1}: Failed - {e}")
        
        if times:
            avg_time = sum(times) / len(times)
            min_time = min(times)
            max_time = max(times)
            
            print(f"📊 Performance Results:")
            print(f"   • Average: {avg_time:.3f}s")
            print(f"   • Minimum: {min_time:.3f}s")
            print(f"   • Maximum: {max_time:.3f}s")
            print(f"   • Throughput: {config['size'] / avg_time:.0f} bytes/second")


def main():
    """Main function to run all API usage examples."""
    print("🚀 ZyraCrypt REST API Usage Examples")
    print("=" * 50)
    
    # Check if server is running, start if necessary
    client = ZyraCryptAPIClient()
    server_process = None
    
    if not check_server_running(client):
        print("⚠️ API server not running, attempting to start...")
        server_process = start_api_server()
        if not server_process:
            print("❌ Could not start API server. Please start manually:")
            print("   export SESSION_SECRET='your-secret-key'")
            print("   python main.py")
            return 1
    else:
        print("✅ API server is already running")
    
    try:
        # Run all demonstrations
        demonstrate_health_check()
        demonstrate_text_encryption()
        demonstrate_key_generation()
        demonstrate_key_derivation()
        demonstrate_api_error_handling()
        demonstrate_performance_testing()
        
        print("\n" + "=" * 50)
        print("✅ All API usage examples completed successfully!")
        
        print("\n🌐 API Integration Best Practices:")
        print("   • Always check server health before operations")
        print("   • Handle HTTP errors gracefully")
        print("   • Implement proper authentication for production")
        print("   • Use HTTPS in production environments")
        print("   • Monitor API performance and response times")
        print("   • Implement rate limiting and request validation")
        print("   • Log security events and access patterns")
        
        print("\n📚 Next Steps:")
        print("   • Deploy API server with proper production configuration")
        print("   • Implement client-side caching for better performance")
        print("   • Add authentication and authorization layers")
        print("   • Set up monitoring and alerting for the API")
        
        return 0
        
    except KeyboardInterrupt:
        print("\n⏹️ Examples interrupted by user")
        return 1
        
    except Exception as e:
        print(f"\n❌ Error during example execution: {e}")
        import traceback
        traceback.print_exc()
        return 1
        
    finally:
        # Clean up server process if we started it
        if server_process:
            print("\n🛑 Stopping API server...")
            try:
                if hasattr(os, 'killpg'):
                    os.killpg(os.getpgid(server_process.pid), signal.SIGTERM)
                else:
                    server_process.terminate()
                server_process.wait(timeout=5)
                print("✅ API server stopped")
            except:
                print("⚠️ Could not cleanly stop API server")


if __name__ == "__main__":
    sys.exit(main())