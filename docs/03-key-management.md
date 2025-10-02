# دليل إدارة المفاتيح

## مقدمة

إدارة المفاتيح الصحيحة هي أساس أي نظام تشفير آمن. يوفر ZyraCrypt أدوات متقدمة لتوليد المفاتيح، تخزينها، تدويرها، وإدارتها بشكل آمن.

## توليد المفاتيح

### 1. توليد مفاتيح عشوائية

```python
import os

# توليد مفتاح عشوائي آمن
key_256_bit = os.urandom(32)  # 256 بت
key_128_bit = os.urandom(16)  # 128 بت

print(f"مفتاح 256 بت: {key_256_bit.hex()}")
```

### 2. اشتقاق المفاتيح من كلمات المرور

#### استخدام Argon2 (الأفضل)

```python
from key_management.key_generator import KeyGenerator

# إنشاء مولد المفاتيح
key_gen = KeyGenerator()

# كلمة المرور
password = "كلمة-مرور-قوية-جداً-2024!"

# اشتقاق المفتاح باستخدام Argon2
key_material = key_gen.derive_key_from_password(
    password=password,
    algorithm="argon2",
    key_length=32  # 32 بايت
)

# استخدام المفتاح
key = key_material['key']
salt = key_material['salt']  # احفظ الملح للاستخدام لاحقاً
```

#### استخدام Scrypt

```python
# اشتقاق المفتاح باستخدام Scrypt
key_material = key_gen.derive_key_from_password(
    password=password,
    algorithm="scrypt",
    key_length=32
)

key = key_material['key']
salt = key_material['salt']
```

#### استخدام PBKDF2

```python
# اشتقاق المفتاح باستخدام PBKDF2
key_material = key_gen.derive_key_from_password(
    password=password,
    algorithm="pbkdf2",
    key_length=32
)

key = key_material['key']
salt = key_material['salt']
```

### 3. اشتقاق المفاتيح المتقدم مع Enhanced KDF

```python
from key_management.enhanced_kdf_password import (
    EnhancedKDF, KDFAlgorithm, SecurityProfile
)

# إنشاء KDF محسّن
kdf = EnhancedKDF()

# اشتقاق مفتاح بملف أمني محدد
derived_material = kdf.derive_key(
    password="كلمة-مرور-معقدة-123!@#",
    algorithm=KDFAlgorithm.ARGON2ID,
    security_profile=SecurityProfile.INTERACTIVE  # للتطبيقات التفاعلية
)

# الحصول على المفتاح المشتق
key = derived_material.key
salt = derived_material.salt
algorithm = derived_material.algorithm

print(f"المفتاح المشتق: {key.hex()}")
print(f"الخوارزمية: {algorithm.value}")
```

## تخزين المفاتيح الآمن

### 1. التخزين البسيط

```python
from key_management.secure_key_store import SecureKeyStore

# إنشاء مخزن مفاتيح
key_store = SecureKeyStore("my_keystore")

# تخزين مفتاح
key_id = "database_encryption_key"
key_data = {
    'key': os.urandom(32),
    'created_at': '2024-01-01',
    'purpose': 'تشفير قاعدة البيانات'
}

key_store.store_key(key_id, key_data)

# استرجاع المفتاح
retrieved_key = key_store.retrieve_key(key_id)
print(f"المفتاح المسترجع: {retrieved_key['key'].hex()}")

# حذف المفتاح
key_store.delete_key(key_id)
```

### 2. التخزين مع التشفير بالمغلف (Envelope Encryption)

```python
from key_management.envelope_encryption_kms import (
    EnvelopeEncryptionManager, 
    KeyStorageLevel
)

# إنشاء مدير التشفير بالمغلف
manager = EnvelopeEncryptionManager()

# توليد مفتاح تشفير البيانات (DEK)
key_id, wrapped_key = manager.generate_data_encryption_key(
    purpose="user_data_encryption",
    algorithm="AES-256-GCM",
    security_level=KeyStorageLevel.HIGH_SECURITY
)

print(f"معرّف المفتاح: {key_id}")
print(f"نوع المفتاح: {wrapped_key.metadata.key_type}")
print(f"مستوى الأمان: {wrapped_key.metadata.security_level}")

# تشفير البيانات باستخدام المفتاح المغلف
sensitive_data = b"بيانات حساسة جداً للحماية"
encrypted_data = manager.encrypt_with_wrapped_key(wrapped_key, sensitive_data)

# فك التشفير
decrypted_data = manager.decrypt_with_wrapped_key(wrapped_key, encrypted_data)
print(f"البيانات: {decrypted_data.decode('utf-8')}")
```

### 3. مخزن المفاتيح الآمن مع ميتاداتا

```python
from key_management.envelope_encryption_kms import SecureKeyStore

# إنشاء مخزن محسّن
secure_store = SecureKeyStore("production_keys")

# تخزين مفتاح مع معلومات كاملة
key_id = "api_encryption_key_v1"
secure_store.store_key(key_id, wrapped_key)

# قائمة جميع المفاتيح
all_keys = secure_store.list_keys()
for key in all_keys:
    print(f"المفتاح: {key}")

# تحميل مفتاح
loaded_key = secure_store.load_key(key_id)
print(f"تم تحميل المفتاح: {loaded_key.metadata.key_id}")

# الحصول على معلومات المفتاح
info = secure_store.get_key_info(key_id)
print(f"تاريخ الإنشاء: {info['created_at']}")
print(f"آخر استخدام: {info['last_used']}")
```

## تدوير المفاتيح (Key Rotation)

تدوير المفاتيح بشكل منتظم هو ممارسة أمنية مهمة:

```python
from key_management.envelope_encryption_kms import EnvelopeEncryptionManager

manager = EnvelopeEncryptionManager()

# المفتاح الحالي
old_key_id = "encryption_key_v1"
old_wrapped_key = secure_store.load_key(old_key_id)

# تدوير المفتاح
new_key_id, new_wrapped_key = manager.rotate_key(old_wrapped_key)

print(f"المفتاح القديم: {old_key_id} (إصدار {old_wrapped_key.metadata.version})")
print(f"المفتاح الجديد: {new_key_id} (إصدار {new_wrapped_key.metadata.version})")

# إعادة تشفير البيانات بالمفتاح الجديد
def re_encrypt_data(old_encrypted_data, old_key, new_key):
    # فك التشفير بالمفتاح القديم
    plaintext = manager.decrypt_with_wrapped_key(old_key, old_encrypted_data)
    
    # إعادة التشفير بالمفتاح الجديد
    new_encrypted = manager.encrypt_with_wrapped_key(new_key, plaintext)
    
    return new_encrypted

# استخدام الدالة
new_encrypted_data = re_encrypt_data(
    encrypted_data, 
    old_wrapped_key, 
    new_wrapped_key
)
```

## إدارة كلمات المرور

### 1. التحقق من قوة كلمة المرور

```python
from key_management.enhanced_kdf_password import PasswordValidator

validator = PasswordValidator()

# كلمات مرور للاختبار
passwords = [
    "123456",                          # ضعيفة جداً
    "password",                        # ضعيفة
    "MyPassword2024",                  # متوسطة
    "MyV3ry$tr0ng-P@ssw0rd!2024"      # قوية
]

for pwd in passwords:
    result = validator.validate_password(pwd)
    
    print(f"\nكلمة المرور: {pwd}")
    print(f"صالحة: {result['valid']}")
    print(f"القوة: {result['strength']}")
    print(f"النقاط: {result['score']}/100")
    
    if not result['valid']:
        print(f"الأخطاء: {', '.join(result['errors'])}")
```

### 2. توليد كلمات مرور آمنة

```python
from key_management.enhanced_kdf_password import PasswordValidator

validator = PasswordValidator()

# توليد كلمة مرور قوية
strong_password = validator.generate_secure_password(
    length=24,  # 24 حرف
    use_symbols=True,
    use_numbers=True,
    use_uppercase=True,
    use_lowercase=True
)

print(f"كلمة مرور تم توليدها: {strong_password}")

# التحقق من القوة
validation = validator.validate_password(strong_password)
print(f"القوة: {validation['strength']}")
print(f"النقاط: {validation['score']}/100")
```

### 3. تخزين كلمات المرور

```python
from key_management.enhanced_kdf_password import SecurePasswordStore

# إنشاء مخزن كلمات المرور
password_store = SecurePasswordStore()

# تخزين كلمة مرور
user_password = "كلمة-مرور-المستخدم-123!"
hashed_password = password_store.hash_password(user_password)

print(f"Hash المخزن: {hashed_password[:50]}...")

# التحقق من كلمة المرور
is_correct = password_store.verify_password(user_password, hashed_password)
print(f"كلمة المرور صحيحة: {is_correct}")

# محاولة خاطئة
is_wrong = password_store.verify_password("wrong-password", hashed_password)
print(f"كلمة مرور خاطئة: {is_wrong}")
```

## إدارة المفاتيح الكاملة

### استخدام KeyManager الموحد

```python
from key_management.key_manager import KeyManager

# إنشاء مدير المفاتيح الشامل
key_manager = KeyManager()

# توليد مفتاح من كلمة مرور
password = "كلمة-مرور-رئيسية-2024!"
derived_key = key_manager.key_generator.derive_key_from_password(
    password=password,
    algorithm="argon2"
)

# تخزين المفتاح
key_id = "master_encryption_key"
key_manager.key_store.store_key(key_id, derived_key)

# استرجاع واستخدام المفتاح
stored_key = key_manager.key_store.retrieve_key(key_id)
encryption_key = stored_key['key']

# استخدام المفتاح للتشفير
from core_cryptography.encryption_framework import EncryptionFramework

framework = EncryptionFramework()
plaintext = b"بيانات سرية"
algo, iv, ciphertext, tag = framework.encrypt(plaintext, encryption_key, "AES-GCM")
```

## أفضل الممارسات

### ✅ افعل هذا

```python
# 1. استخدم Argon2 لاشتقاق المفاتيح من كلمات المرور
key_material = key_gen.derive_key_from_password(
    password=password,
    algorithm="argon2"
)

# 2. احفظ الملح (Salt) مع البيانات المشفرة
stored_data = {
    'salt': salt,
    'ciphertext': ciphertext,
    'iv': iv,
    'tag': tag
}

# 3. دوّر المفاتيح بانتظام (كل 90 يوم مثلاً)
if days_since_creation > 90:
    new_key = rotate_key(old_key)

# 4. استخدم مستويات أمان مختلفة حسب الحساسية
high_security_key = manager.generate_data_encryption_key(
    purpose="financial_data",
    security_level=KeyStorageLevel.HIGH_SECURITY
)
```

### ❌ لا تفعل هذا

```python
# 1. لا تخزن كلمات المرور كنص عادي
password = "my_password"  # ❌ خطير!

# 2. لا تستخدم مفاتيح ضعيفة
weak_key = b"1234"  # ❌ قصير جداً!

# 3. لا تعيد استخدام الملح
salt = b"same_salt_always"  # ❌ يجب أن يكون عشوائي!

# 4. لا تخزن المفاتيح في الكود
API_KEY = "hardcoded_key_123"  # ❌ خطير جداً!
```

## سيناريوهات عملية

### سيناريو 1: تطبيق ويب مع تشفير البيانات

```python
from key_management.key_manager import KeyManager
from core_cryptography.encryption_framework import EncryptionFramework

class UserDataEncryptor:
    def __init__(self, master_password):
        self.key_manager = KeyManager()
        self.framework = EncryptionFramework()
        
        # اشتقاق مفتاح رئيسي
        key_data = self.key_manager.key_generator.derive_key_from_password(
            password=master_password,
            algorithm="argon2"
        )
        self.master_key = key_data['key']
    
    def encrypt_user_data(self, user_id, data):
        # تشفير بيانات المستخدم
        algo, iv, ciphertext, tag = self.framework.encrypt(
            data.encode('utf-8'),
            self.master_key,
            "AES-GCM"
        )
        
        return {
            'user_id': user_id,
            'algorithm': algo,
            'iv': iv.hex(),
            'ciphertext': ciphertext.hex(),
            'tag': tag.hex()
        }
    
    def decrypt_user_data(self, encrypted_data):
        # فك تشفير بيانات المستخدم
        decrypted = self.framework.decrypt(
            encrypted_data['algorithm'],
            self.master_key,
            bytes.fromhex(encrypted_data['iv']),
            bytes.fromhex(encrypted_data['ciphertext']),
            bytes.fromhex(encrypted_data['tag'])
        )
        
        return decrypted.decode('utf-8')

# الاستخدام
encryptor = UserDataEncryptor("master-password-2024!")
encrypted = encryptor.encrypt_user_data("user_123", "بيانات حساسة")
decrypted = encryptor.decrypt_user_data(encrypted)
```

---

**التالي**: [الميزات المتقدمة](04-advanced-features.md)
