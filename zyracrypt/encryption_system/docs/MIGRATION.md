# Migration Guide

This guide helps you migrate between versions of the Advanced Encryption System, including breaking changes, new features, and best practices for smooth transitions.

## Table of Contents

1. [Version Overview](#version-overview)
2. [Migration from 1.x to 2.x](#migration-from-1x-to-2x)
3. [Automated Migration Tools](#automated-migration-tools)
4. [Breaking Changes](#breaking-changes)
5. [Feature Updates](#feature-updates)
6. [Configuration Changes](#configuration-changes)
7. [Best Practices](#best-practices)
8. [Rollback Procedures](#rollback-procedures)

## Version Overview

### Version History

| Version | Release Date | Type | Description |
|---------|--------------|------|-------------|
| 1.0.0   | Dec 2024     | Initial | Core symmetric/asymmetric encryption |
| 2.0.0   | Sep 2025     | Major   | Enterprise features, post-quantum crypto |
| 2.1.0   | Nov 2025     | Minor   | Performance optimizations (planned) |
| 3.0.0   | Q2 2026      | Major   | Cloud-native features (planned) |

### Compatibility Matrix

| Migration Path | Difficulty | Estimated Time | Breaking Changes |
|----------------|------------|----------------|------------------|
| 1.0.x → 2.0.x  | Medium     | 2-4 hours      | Import paths, API changes |
| 2.0.x → 2.1.x  | Easy       | 30 minutes     | None (backward compatible) |
| 2.x → 3.0.x    | High       | 1-2 days       | Architecture changes |

## Migration from 1.x to 2.x

### Overview

Version 2.0 introduces significant enhancements while maintaining core functionality. Major changes include:

- **New module structure** with enhanced organization
- **Enterprise features** for advanced use cases
- **Post-quantum cryptography** for future-proofing
- **Enhanced key management** with lifecycle support
- **Improved performance** and security features

### Step-by-Step Migration

#### Step 1: Backup Current Implementation

```bash
# Backup your current project
cp -r your_project your_project_backup

# Document current configuration
python -c "
import your_crypto_module
print('Current library version:', getattr(your_crypto_module, '__version__', 'unknown'))
"
```

#### Step 2: Update Dependencies

```bash
# Update to version 2.0
cd alqudimi_encryption_system
git pull origin main
pip install -r requirements.txt

# Or install specific version
pip install alqudimi-encryption-system==2.0.0
```

#### Step 3: Update Import Statements

**Before (v1.x):**
```python
from alqudimi_crypto import symmetric_encrypt, asymmetric_encrypt
from alqudimi_crypto.keys import generate_key
```

**After (v2.x):**
```python
import os
import sys

# Setup library path (if not installed as package)
encryption_root = os.path.join(os.path.dirname(__file__), 'alqudimi_encryption_system')
encryption_src = os.path.join(encryption_root, 'encryption_system', 'src')
sys.path.insert(0, encryption_root)
sys.path.insert(0, encryption_src)

from core_cryptography.symmetric_encryption import SymmetricEncryption
from core_cryptography.asymmetric_encryption import AsymmetricEncryption
from key_management.key_generator import KeyGenerator
```

#### Step 4: Update API Calls

**Symmetric Encryption Changes:**

*Before (v1.x):*
```python
# Old API
ciphertext = symmetric_encrypt(plaintext, key, algorithm='AES')
```

*After (v2.x):*
```python
# New API
symmetric = SymmetricEncryption()
iv = os.urandom(12)
ciphertext, tag = symmetric.encrypt_aes_gcm(key, iv, plaintext)
```

**Key Generation Changes:**

*Before (v1.x):*
```python
# Old API
key = generate_key(256)  # Generate 256-bit key
```

*After (v2.x):*
```python
# New API
key_generator = KeyGenerator()
key = key_generator.generate_symmetric_key(256)
```

#### Step 5: Update Configuration

**Before (v1.x):**
```python
# Configuration in v1.x
config = {
    'algorithm': 'AES-256',
    'mode': 'GCM',
    'key_size': 256
}
```

**After (v2.x):**
```python
# Enhanced configuration in v2.x
from core_cryptography.encryption_framework import EncryptionFramework

framework = EncryptionFramework()
# Configuration is now algorithm-specific and automatic
```

#### Step 6: Test Migration

```python
#!/usr/bin/env python3
"""Migration validation script."""

import os
import sys

# Setup paths for v2.x
encryption_root = os.path.join(os.path.dirname(__file__), 'alqudimi_encryption_system')
encryption_src = os.path.join(encryption_root, 'encryption_system', 'src')
sys.path.insert(0, encryption_root)
sys.path.insert(0, encryption_src)

def test_migration():
    """Test that migration was successful."""
    try:
        # Test core functionality
        from core_cryptography.symmetric_encryption import SymmetricEncryption
        from core_cryptography.encryption_framework import EncryptionFramework
        
        # Test encryption
        symmetric = SymmetricEncryption()
        framework = EncryptionFramework()
        
        key = os.urandom(32)
        plaintext = b"Migration test data"
        
        # Test new API
        algorithm, iv, ciphertext, tag = framework.encrypt(plaintext, key)
        decrypted = symmetric.decrypt_aes_gcm(key, iv, ciphertext, tag)
        
        assert decrypted == plaintext
        print("✓ Migration successful!")
        print(f"✓ Algorithm used: {algorithm}")
        
        return True
        
    except Exception as e:
        print(f"✗ Migration failed: {e}")
        return False

if __name__ == "__main__":
    test_migration()
```

## Automated Migration Tools

### Migration Script

```python
#!/usr/bin/env python3
"""Automated migration script for v1.x to v2.x."""

import os
import re
import shutil
from pathlib import Path

class MigrationTool:
    """Automated migration from v1.x to v2.x."""
    
    def __init__(self, project_path: str):
        self.project_path = Path(project_path)
        self.backup_path = Path(f"{project_path}_backup")
    
    def create_backup(self):
        """Create backup of current project."""
        if self.backup_path.exists():
            shutil.rmtree(self.backup_path)
        shutil.copytree(self.project_path, self.backup_path)
        print(f"✓ Backup created at {self.backup_path}")
    
    def update_imports(self):
        """Update import statements in Python files."""
        import_mapping = {
            r'from alqudimi_crypto import symmetric_encrypt': 
                'from core_cryptography.symmetric_encryption import SymmetricEncryption',
            r'from alqudimi_crypto import asymmetric_encrypt':
                'from core_cryptography.asymmetric_encryption import AsymmetricEncryption',
            r'from alqudimi_crypto.keys import generate_key':
                'from key_management.key_generator import KeyGenerator',
        }
        
        python_files = list(self.project_path.rglob("*.py"))
        
        for file_path in python_files:
            with open(file_path, 'r') as f:
                content = f.read()
            
            modified = False
            for old_import, new_import in import_mapping.items():
                if re.search(old_import, content):
                    content = re.sub(old_import, new_import, content)
                    modified = True
            
            if modified:
                with open(file_path, 'w') as f:
                    f.write(content)
                print(f"✓ Updated imports in {file_path}")
    
    def add_path_setup(self):
        """Add path setup code to main files."""
        main_files = ['main.py', 'app.py', '__init__.py']
        
        path_setup = '''import os
import sys

# Setup encryption library path
encryption_root = os.path.join(os.path.dirname(__file__), 'alqudimi_encryption_system')
encryption_src = os.path.join(encryption_root, 'encryption_system', 'src')
sys.path.insert(0, encryption_root)
sys.path.insert(0, encryption_src)

'''
        
        for main_file in main_files:
            file_path = self.project_path / main_file
            if file_path.exists():
                with open(file_path, 'r') as f:
                    content = f.read()
                
                # Check if path setup already exists
                if 'alqudimi_encryption_system' not in content:
                    # Add path setup at the beginning
                    content = path_setup + content
                    
                    with open(file_path, 'w') as f:
                        f.write(content)
                    print(f"✓ Added path setup to {file_path}")
    
    def update_api_calls(self):
        """Update API calls to new format."""
        api_mapping = {
            r'symmetric_encrypt\(([^,]+),\s*([^,]+)(?:,\s*algorithm=[^)]+)?\)':
                r'SymmetricEncryption().encrypt_aes_gcm(\2, os.urandom(12), \1)',
            r'generate_key\((\d+)\)':
                r'KeyGenerator().generate_symmetric_key(\1)',
        }
        
        python_files = list(self.project_path.rglob("*.py"))
        
        for file_path in python_files:
            with open(file_path, 'r') as f:
                content = f.read()
            
            modified = False
            for old_api, new_api in api_mapping.items():
                if re.search(old_api, content):
                    content = re.sub(old_api, new_api, content)
                    modified = True
            
            if modified:
                with open(file_path, 'w') as f:
                    f.write(content)
                print(f"✓ Updated API calls in {file_path}")
    
    def migrate(self):
        """Run complete migration."""
        print("Starting migration from v1.x to v2.x...")
        
        self.create_backup()
        self.add_path_setup()
        self.update_imports()
        self.update_api_calls()
        
        print("\n✓ Migration completed!")
        print(f"  Backup available at: {self.backup_path}")
        print("  Please test your application and run validation script.")

# Usage
if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python migrate.py <project_path>")
        sys.exit(1)
    
    project_path = sys.argv[1]
    migrator = MigrationTool(project_path)
    migrator.migrate()
```

### Configuration Migration

```python
def migrate_configuration(old_config_path: str, new_config_path: str):
    """Migrate configuration from v1.x to v2.x format."""
    
    import json
    
    # Load old configuration
    with open(old_config_path, 'r') as f:
        old_config = json.load(f)
    
    # Map to new configuration structure
    new_config = {
        'encryption': {
            'symmetric': {
                'default_algorithm': 'AES-256-GCM',
                'key_size': old_config.get('key_size', 256)
            },
            'asymmetric': {
                'rsa_key_size': old_config.get('rsa_key_size', 2048),
                'ecc_curve': old_config.get('ecc_curve', 'secp256r1')
            }
        },
        'key_management': {
            'derivation_algorithm': 'ARGON2ID',
            'key_rotation_interval': old_config.get('key_rotation_days', 90)
        },
        'security': {
            'side_channel_protection': True,
            'secure_memory': True
        }
    }
    
    # Save new configuration
    with open(new_config_path, 'w') as f:
        json.dump(new_config, f, indent=2)
    
    print(f"✓ Configuration migrated from {old_config_path} to {new_config_path}")
```

## Breaking Changes

### Import Path Changes

| v1.x Import | v2.x Import |
|-------------|-------------|
| `from alqudimi_crypto import *` | `from core_cryptography.* import *` |
| `from alqudimi_crypto.keys import *` | `from key_management.* import *` |
| `from alqudimi_crypto.utils import *` | `from data_protection.* import *` |

### API Method Changes

| v1.x Method | v2.x Method | Notes |
|-------------|-------------|-------|
| `symmetric_encrypt(data, key)` | `SymmetricEncryption().encrypt_aes_gcm(key, iv, data)` | Now returns tuple |
| `asymmetric_encrypt(data, key)` | `AsymmetricEncryption().encrypt_rsa_oaep(key, data)` | Explicit padding |
| `generate_key(size)` | `KeyGenerator().generate_symmetric_key(size)` | Object-oriented |
| `derive_key(password, salt)` | `EnhancedKDF().derive_key(password, salt, algorithm)` | Algorithm selection |

### Return Value Changes

**Symmetric Encryption:**
```python
# v1.x - returned single value
ciphertext = symmetric_encrypt(plaintext, key)

# v2.x - returns tuple with authentication
ciphertext, tag = symmetric.encrypt_aes_gcm(key, iv, plaintext)
```

**Key Generation:**
```python
# v1.x - returned bytes
key = generate_key(256)

# v2.x - may return key objects
key_result = kdf.derive_key(password, salt, algorithm)
actual_key = key_result.key
```

### Configuration Schema Changes

**v1.x Configuration:**
```json
{
  "algorithm": "AES-256",
  "mode": "GCM",
  "key_size": 256,
  "rsa_key_size": 2048
}
```

**v2.x Configuration:**
```json
{
  "encryption": {
    "symmetric": {
      "default_algorithm": "AES-256-GCM",
      "key_size": 256
    },
    "asymmetric": {
      "rsa_key_size": 2048,
      "ecc_curve": "secp256r1"
    }
  },
  "key_management": {
    "derivation_algorithm": "ARGON2ID"
  }
}
```

## Feature Updates

### New Features in v2.x

#### 1. Enhanced Key Management

```python
# New key lifecycle management
from key_management.enhanced_key_manager import EnhancedKeyManager

key_manager = EnhancedKeyManager()

# Generate keys with metadata
key_info = key_manager.generate_key_with_metadata(
    algorithm="AES-256",
    purpose="data_encryption",
    expiry_days=365
)

# Automatic key rotation
rotated_key = key_manager.rotate_key(key_info.key_id)
```

#### 2. Post-Quantum Cryptography

```python
# New post-quantum algorithms
from advanced_features.hybrid_pqc_enhanced import HybridPQCEngine

pqc = HybridPQCEngine()

# Quantum-resistant key exchange
public_keys, private_keys = pqc.generate_hybrid_keypair()
key_material = pqc.hybrid_key_exchange(
    public_keys['classical'], 
    public_keys['pq']
)
```

#### 3. Advanced Security Features

```python
# New side-channel protection
from advanced_features.side_channel_protection import TimingAttackProtection

protection = TimingAttackProtection()

# Constant-time operations
is_equal = protection.constant_time_compare(value1, value2)
hmac_result = protection.timing_safe_hmac_verify(data, expected, key)
```

### Migration Strategy for New Features

#### Gradual Migration Approach

1. **Phase 1**: Update basic encryption operations
2. **Phase 2**: Migrate to enhanced key management
3. **Phase 3**: Add post-quantum cryptography
4. **Phase 4**: Implement advanced security features

```python
# Phase 1: Basic migration
def migrate_basic_encryption():
    # Replace old symmetric encryption
    pass

# Phase 2: Enhanced key management
def migrate_key_management():
    # Upgrade to new key manager
    pass

# Phase 3: Add post-quantum
def add_post_quantum():
    # Implement hybrid PQC
    pass

# Phase 4: Advanced security
def add_advanced_security():
    # Add side-channel protection
    pass
```

## Configuration Changes

### Environment Variables

**New in v2.x:**
```bash
# Required for Flask API
export SESSION_SECRET="your-secure-secret-key"

# Optional CORS configuration
export CORS_ORIGINS="http://localhost:*"

# Optional performance tuning
export CRYPTO_HARDWARE_ACCELERATION="true"
export CRYPTO_MEMORY_POOL_SIZE="64MB"
```

### Configuration Files

**Recommended v2.x structure:**
```yaml
# crypto_config.yaml
encryption:
  symmetric:
    default_algorithm: "AES-256-GCM"
    hardware_acceleration: true
  
  asymmetric:
    rsa_key_size: 2048
    ecc_curve: "secp256r1"
  
  post_quantum:
    enable_hybrid: true
    security_level: 128

key_management:
  derivation:
    algorithm: "ARGON2ID"
    memory_cost: 65536
    time_cost: 3
  
  rotation:
    auto_rotate: true
    rotation_interval_days: 90

security:
  side_channel_protection: true
  secure_memory: true
  audit_logging: true
```

## Best Practices

### Migration Best Practices

#### 1. Incremental Migration

```python
class CompatibilityLayer:
    """Compatibility layer for gradual migration."""
    
    def __init__(self):
        # Try v2.x imports first
        try:
            from core_cryptography.symmetric_encryption import SymmetricEncryption
            self.use_v2 = True
            self.symmetric = SymmetricEncryption()
        except ImportError:
            # Fall back to v1.x
            import alqudimi_crypto
            self.use_v2 = False
            self.symmetric = alqudimi_crypto
    
    def encrypt(self, plaintext: bytes, key: bytes) -> tuple:
        """Unified encryption interface."""
        if self.use_v2:
            iv = os.urandom(12)
            ciphertext, tag = self.symmetric.encrypt_aes_gcm(key, iv, plaintext)
            return (iv, ciphertext, tag)
        else:
            # v1.x compatibility
            ciphertext = self.symmetric.symmetric_encrypt(plaintext, key)
            return (None, ciphertext, None)
```

#### 2. Testing Strategy

```python
def test_migration_compatibility():
    """Test that migration maintains data compatibility."""
    
    # Test data encrypted with v1.x
    v1_encrypted_data = load_v1_test_data()
    
    # Ensure v2.x can decrypt v1.x data
    v2_crypto = SymmetricEncryption()
    
    for test_case in v1_encrypted_data:
        try:
            decrypted = decrypt_v1_data_with_v2(test_case)
            assert decrypted == test_case['original']
            print(f"✓ v1.x data compatible with v2.x")
        except Exception as e:
            print(f"✗ Compatibility issue: {e}")
```

#### 3. Data Migration

```python
def migrate_encrypted_data():
    """Migrate existing encrypted data to new format."""
    
    # Load data encrypted with v1.x
    old_data = load_encrypted_database()
    
    # Decrypt with v1.x keys and re-encrypt with v2.x
    for record in old_data:
        # Decrypt with v1.x
        plaintext = decrypt_v1(record['ciphertext'], record['key'])
        
        # Re-encrypt with v2.x
        symmetric = SymmetricEncryption()
        iv = os.urandom(12)
        new_ciphertext, tag = symmetric.encrypt_aes_gcm(
            record['key'], iv, plaintext
        )
        
        # Update database record
        update_record(record['id'], {
            'ciphertext': new_ciphertext,
            'iv': iv,
            'tag': tag,
            'version': '2.0'
        })
```

#### 4. Rollback Preparation

```python
class MigrationManager:
    """Manage migration with rollback capability."""
    
    def __init__(self):
        self.backup_data = {}
        self.migration_log = []
    
    def backup_before_migration(self):
        """Create backup before migration."""
        # Backup current encryption setup
        self.backup_data['keys'] = export_current_keys()
        self.backup_data['config'] = export_current_config()
        self.backup_data['encrypted_data'] = export_encrypted_data()
    
    def migrate_with_rollback(self):
        """Migrate with ability to rollback."""
        try:
            self.backup_before_migration()
            self.perform_migration()
            self.verify_migration()
        except Exception as e:
            print(f"Migration failed: {e}")
            self.rollback()
            raise
    
    def rollback(self):
        """Rollback migration if it fails."""
        print("Rolling back migration...")
        restore_keys(self.backup_data['keys'])
        restore_config(self.backup_data['config'])
        restore_encrypted_data(self.backup_data['encrypted_data'])
        print("✓ Rollback completed")
```

## Rollback Procedures

### Automated Rollback

```bash
#!/bin/bash
# rollback_migration.sh

echo "Rolling back migration from v2.x to v1.x..."

# Restore backup
if [ -d "project_backup" ]; then
    rm -rf current_project
    mv project_backup current_project
    echo "✓ Code restored from backup"
else
    echo "✗ No backup found"
    exit 1
fi

# Restore dependencies
pip install alqudimi-encryption-system==1.0.0
echo "✓ Dependencies restored"

# Verify rollback
python -c "
try:
    import alqudimi_crypto
    print('✓ Rollback successful')
except ImportError:
    print('✗ Rollback failed')
"
```

### Manual Rollback Steps

1. **Stop services using the library**
2. **Restore backup copy of your project**
3. **Downgrade library version**
4. **Restore old configuration files**
5. **Verify functionality with old tests**
6. **Resume services**

### Data Rollback

```python
def rollback_data_migration():
    """Rollback data that was migrated to v2.x format."""
    
    # Find records with v2.x format
    v2_records = find_records_by_version('2.0')
    
    for record in v2_records:
        if has_v1_backup(record['id']):
            # Restore v1.x format from backup
            restore_v1_record(record['id'])
        else:
            # Convert v2.x format back to v1.x
            convert_v2_to_v1(record)
    
    print("✓ Data rollback completed")
```

## Getting Help

### Migration Support

- **Documentation**: Check [troubleshooting guide](TROUBLESHOOTING.md)
- **Community**: Ask questions in GitHub Discussions
- **Issues**: Report migration bugs on GitHub Issues
- **Professional Services**: Enterprise migration support available

### Migration Checklist

- [ ] Create complete backup of current system
- [ ] Test migration in development environment
- [ ] Update import statements
- [ ] Modify API calls to new format
- [ ] Update configuration files
- [ ] Test all functionality thoroughly
- [ ] Prepare rollback procedures
- [ ] Document changes for your team
- [ ] Monitor performance after migration
- [ ] Plan for future migrations

---

*This migration guide is updated with each release. For the latest migration information, check the release notes and documentation.*