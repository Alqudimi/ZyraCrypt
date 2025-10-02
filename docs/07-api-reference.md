# مرجع API الكامل

## مقدمة

هذا المرجع الشامل لجميع الوحدات والدوال في مكتبة ZyraCrypt.

## core_cryptography

### EncryptionFramework

الواجهة الرئيسية للتشفير وفك التشفير.

#### `__init__()`

```python
framework = EncryptionFramework()
```

إنشاء كائن إطار التشفير.

#### `encrypt(data, key, encryption_type="auto", associated_data=None)`

تشفير البيانات.

**المعاملات:**
- `data` (bytes): البيانات للتشفير
- `key` (bytes): مفتاح التشفير (32 بايت لـ AES-256)
- `encryption_type` (str): نوع التشفير ("auto", "AES-GCM", "ChaCha20")
- `associated_data` (bytes, optional): بيانات إضافية محمية

**القيمة المرجعة:**
- tuple: (algorithm, iv, ciphertext, tag)

**مثال:**
```python
algo, iv, ciphertext, tag = framework.encrypt(
    b"بيانات سرية", 
    key, 
    "AES-GCM"
)
```

#### `decrypt(algo_name, key, iv_nonce, ciphertext, tag=b"", associated_data=None)`

فك تشفير البيانات.

**المعاملات:**
- `algo_name` (str): اسم الخوارزمية
- `key` (bytes): مفتاح فك التشفير
- `iv_nonce` (bytes): IV أو Nonce
- `ciphertext` (bytes): النص المشفر
- `tag` (bytes): علامة المصادقة (لـ AES-GCM)
- `associated_data` (bytes, optional): البيانات الإضافية

**القيمة المرجعة:**
- bytes: البيانات الأصلية

---

### SymmetricEncryption

تشفير متماثل باستخدام AES و ChaCha20.

#### `encrypt_aes_gcm(key, plaintext, associated_data=None)`

تشفير باستخدام AES-256-GCM.

**المعاملات:**
- `key` (bytes): مفتاح 32 بايت
- `plaintext` (bytes): النص الأصلي
- `associated_data` (bytes, optional): بيانات إضافية

**القيمة المرجعة:**
- tuple: (iv, ciphertext, tag)

#### `decrypt_aes_gcm(key, iv, ciphertext, tag, associated_data=None)`

فك تشفير AES-256-GCM.

#### `encrypt_chacha20_poly1305(key, plaintext, associated_data=None)`

تشفير باستخدام ChaCha20-Poly1305.

**القيمة المرجعة:**
- tuple: (nonce, ciphertext)

#### `decrypt_chacha20_poly1305(key, nonce, ciphertext, associated_data=None)`

فك تشفير ChaCha20-Poly1305.

---

### AsymmetricEncryption

تشفير غير متماثل باستخدام RSA و ECDSA.

#### `generate_rsa_keypair(key_size=2048)`

توليد زوج مفاتيح RSA.

**المعاملات:**
- `key_size` (int): حجم المفتاح (2048, 3072, 4096)

**القيمة المرجعة:**
- tuple: (private_key, public_key)

#### `encrypt_rsa(public_key, plaintext)`

تشفير باستخدام RSA.

#### `decrypt_rsa(private_key, ciphertext)`

فك تشفير RSA.

#### `generate_ecdsa_keypair(curve="P-256")`

توليد زوج مفاتيح ECDSA.

**المعاملات:**
- `curve` (str): المنحنى ("P-256", "P-384", "P-521")

#### `sign_ecdsa(private_key, message)`

توقيع رسالة باستخدام ECDSA.

#### `verify_ecdsa(public_key, message, signature)`

التحقق من توقيع ECDSA.

---

## key_management

### KeyManager

مدير شامل للمفاتيح.

#### `__init__()`

```python
key_manager = KeyManager()
```

**الخصائص:**
- `key_generator`: مولد المفاتيح
- `key_store`: مخزن المفاتيح
- `key_exchange`: تبادل المفاتيح

---

### KeyGenerator

توليد واشتقاق المفاتيح.

#### `derive_key_from_password(password, algorithm="argon2", key_length=32, salt=None)`

اشتقاق مفتاح من كلمة مرور.

**المعاملات:**
- `password` (str): كلمة المرور
- `algorithm` (str): الخوارزمية ("argon2", "scrypt", "pbkdf2")
- `key_length` (int): طول المفتاح بالبايتات
- `salt` (bytes, optional): الملح (يتم توليده تلقائياً)

**القيمة المرجعة:**
- dict: {'key': bytes, 'salt': bytes, 'algorithm': str}

---

### EnhancedKDF

اشتقاق مفاتيح محسّن.

#### `derive_key(password, algorithm, security_profile=SecurityProfile.INTERACTIVE)`

اشتقاق مفتاح مع ملف أمني.

**المعاملات:**
- `password` (str): كلمة المرور
- `algorithm` (KDFAlgorithm): الخوارزمية
- `security_profile` (SecurityProfile): الملف الأمني

**القيمة المرجعة:**
- DerivedKeyMaterial

**الثوابت:**

```python
class KDFAlgorithm(Enum):
    ARGON2ID = "argon2id"
    SCRYPT = "scrypt"
    PBKDF2_SHA256 = "pbkdf2_sha256"
    PBKDF2_SHA512 = "pbkdf2_sha512"
    HKDF = "hkdf"

class SecurityProfile(Enum):
    INTERACTIVE = "interactive"      # للتطبيقات التفاعلية
    MODERATE = "moderate"            # للخوادم
    SENSITIVE = "sensitive"          # للبيانات الحساسة
    PARANOID = "paranoid"           # لأقصى أمان
```

#### `verify_derived_key(password, derived_material)`

التحقق من كلمة المرور.

---

### PasswordValidator

التحقق من قوة كلمات المرور.

#### `validate_password(password, min_length=12)`

التحقق من قوة كلمة المرور.

**القيمة المرجعة:**
```python
{
    'valid': bool,
    'strength': str,  # 'weak', 'fair', 'good', 'strong', 'very_strong'
    'score': int,     # 0-100
    'errors': list
}
```

#### `generate_secure_password(length=16, use_symbols=True, use_numbers=True, use_uppercase=True, use_lowercase=True)`

توليد كلمة مرور آمنة.

---

### EnvelopeEncryptionManager

إدارة التشفير بالمغلف.

#### `generate_data_encryption_key(purpose, algorithm="AES-256-GCM", security_level=KeyStorageLevel.STANDARD)`

توليد مفتاح تشفير بيانات.

**المعاملات:**
- `purpose` (str): الغرض من المفتاح
- `algorithm` (str): الخوارزمية
- `security_level` (KeyStorageLevel): مستوى الأمان

**القيمة المرجعة:**
- tuple: (key_id, wrapped_key)

**الثوابت:**

```python
class KeyStorageLevel(Enum):
    STANDARD = "standard"
    HIGH_SECURITY = "high_security"
    CRITICAL = "critical"
    HSM_BACKED = "hsm_backed"
```

#### `encrypt_with_wrapped_key(wrapped_key, plaintext)`

تشفير باستخدام مفتاح مغلف.

#### `decrypt_with_wrapped_key(wrapped_key, ciphertext)`

فك تشفير باستخدام مفتاح مغلف.

#### `rotate_key(old_wrapped_key)`

تدوير المفتاح.

**القيمة المرجعة:**
- tuple: (new_key_id, new_wrapped_key)

---

## advanced_features

### ShamirSecretSharing

مشاركة السر بطريقة شامير.

#### `split_secret(secret, threshold, total_shares)`

تقسيم سر إلى أجزاء.

**المعاملات:**
- `secret` (bytes): السر
- `threshold` (int): عدد الأجزاء المطلوبة لإعادة البناء
- `total_shares` (int): إجمالي عدد الأجزاء

**القيمة المرجعة:**
- list[SecretShare]

#### `reconstruct_secret(shares)`

إعادة بناء السر من الأجزاء.

**المعاملات:**
- `shares` (list): قائمة الأجزاء (على الأقل threshold)

**القيمة المرجعة:**
- bytes: السر الأصلي

---

### ThresholdECDSA

التوقيع العتبي ECDSA.

#### `generate_threshold_keypair(threshold, total_participants, participants)`

توليد زوج مفاتيح عتبي.

**المعاملات:**
- `threshold` (int): عدد التوقيعات المطلوبة
- `total_participants` (int): إجمالي المشاركين
- `participants` (list): قائمة معرّفات المشاركين

**القيمة المرجعة:**
- ThresholdKeypair

#### `create_partial_signature(keypair, share_index, message, participant_id)`

إنشاء توقيع جزئي.

#### `combine_partial_signatures(keypair, partial_signatures, message)`

دمج التوقيعات الجزئية.

**القيمة المرجعة:**
- ThresholdSignature

#### `verify_threshold_signature(keypair, signature, message)`

التحقق من التوقيع العتبي.

---

### SecureEnclave

المكان الآمن للحسابات.

#### `__init__(enclave_type=EnclaveType.SOFTWARE_ENCLAVE)`

```python
enclave = SecureEnclave(EnclaveType.SOFTWARE_ENCLAVE)
```

**الثوابت:**

```python
class EnclaveType(Enum):
    SOFTWARE_ENCLAVE = "software"
    HARDWARE_ENCLAVE = "hardware"
    TEE_ENCLAVE = "tee"  # Trusted Execution Environment
```

#### `store_secret(secret_id, secret_data)`

تخزين سر في المكان الآمن.

#### `retrieve_secret(secret_id)`

استرجاع سر.

#### `secure_computation(computation_function, input_secret_id, output_secret_id)`

تنفيذ حساب آمن.

#### `get_attestation()`

الحصول على شهادة المكان الآمن.

#### `clear_secrets()`

مسح جميع الأسرار.

---

### HybridPQCEngine

التشفير الهجين الكمي.

#### `__init__(security_level=SecurityLevel.LEVEL_128)`

```python
engine = HybridPQCEngine(security_level=128)
```

**الثوابت:**

```python
class SecurityLevel(IntEnum):
    LEVEL_128 = 128
    LEVEL_192 = 192
    LEVEL_256 = 256
```

#### `generate_hybrid_keypair()`

توليد أزواج مفاتيح هجينة.

**القيمة المرجعة:**
- tuple: (public_keys, private_keys)

#### `hybrid_key_exchange(public_keys)`

تبادل مفتاح هجين.

**القيمة المرجعة:**
- HybridKeyMaterial

#### `generate_hybrid_signature_keypair()`

توليد مفاتيح توقيع هجينة.

#### `hybrid_sign(private_keys, message)`

توقيع هجين.

**القيمة المرجعة:**
- HybridSignature

#### `hybrid_verify(public_keys, message, signatures)`

التحقق من التوقيع الهجين.

#### `get_algorithm_info()`

معلومات الخوارزميات.

---

### SideChannelGuard

الحماية من الهجمات الجانبية.

#### `constant_time_compare(a, b)` (static)

مقارنة آمنة بوقت ثابت.

```python
is_equal = SideChannelGuard.constant_time_compare(secret1, secret2)
```

#### `secure_random(length)` (static)

توليد بيانات عشوائية آمنة.

```python
random_bytes = SideChannelGuard.secure_random(32)
```

#### `secure_zero_memory(data)` (static)

مسح آمن من الذاكرة.

```python
SideChannelGuard.secure_zero_memory(sensitive_data)
```

---

## post_quantum_cryptography

### PostQuantumCryptographyUnit

وحدة التشفير الكمي.

#### `generate_keypair_kem(algorithm)`

توليد مفاتيح KEM.

**المعاملات:**
- `algorithm` (str): "Kyber512", "Kyber768", "Kyber1024"

**القيمة المرجعة:**
- tuple: (public_key, private_key)

#### `encapsulate_kem(algorithm, public_key)`

تغليف مفتاح.

**القيمة المرجعة:**
- tuple: (encapsulated_key, shared_secret)

#### `decapsulate_kem(algorithm, private_key, encapsulated_key)`

فك تغليف مفتاح.

**القيمة المرجعة:**
- bytes: shared_secret

#### `generate_keypair_signature(algorithm)`

توليد مفاتيح التوقيع.

**المعاملات:**
- `algorithm` (str): "Dilithium2", "Dilithium3", "Dilithium5"

#### `sign(algorithm, signing_key, message)`

توقيع رسالة.

#### `verify(algorithm, verifying_key, message, signature)`

التحقق من توقيع.

---

## specialized_security

### FileEncryptionManager

إدارة تشفير الملفات.

#### `encrypt_file(input_path, output_path, key)`

تشفير ملف.

#### `decrypt_file(encrypted_path, output_path, key)`

فك تشفير ملف.

---

### SecureSessionManager

إدارة الجلسات الآمنة.

#### `create_session(user_data, expiry_minutes=60)`

إنشاء جلسة.

**القيمة المرجعة:**
- str: session_token

#### `get_session(session_token)`

الحصول على بيانات الجلسة.

#### `delete_session(session_token)`

حذف جلسة.

---

## أنواع البيانات

### WrappedKey

```python
@dataclass
class WrappedKey:
    metadata: KeyMetadata
    encrypted_key: bytes
    key_encryption_key_id: str
```

### ThresholdKeypair

```python
@dataclass
class ThresholdKeypair:
    key_id: str
    threshold: int
    total_participants: int
    shares: List[SecretShare]
    public_verification_key: bytes
```

### HybridKeyMaterial

```python
@dataclass
class HybridKeyMaterial:
    classical_shared_secret: bytes
    pq_shared_secret: bytes
    combined_shared_secret: bytes
    algorithm_info: Dict[str, Any]
```

---

**التالي**: [أفضل الممارسات الأمنية](08-security-best-practices.md)
