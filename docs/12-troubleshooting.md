# دليل استكشاف الأخطاء وحلولها

## مقدمة

هذا الدليل يساعدك في حل المشاكل الشائعة التي قد تواجهها عند استخدام ZyraCrypt.

## أخطاء التشفير

### خطأ: Invalid key size

```
ValueError: Invalid key size (got X bytes, expected 32)
```

**السبب**: المفتاح ليس بالطول المطلوب.

**الحل**:

```python
import os

# ❌ خطأ
key = b"short_key"  # قصير جداً

# ✅ صحيح: استخدم 32 بايت لـ AES-256
key = os.urandom(32)

# أو اشتق من كلمة مرور
from key_management.key_generator import KeyGenerator
key_gen = KeyGenerator()
key_data = key_gen.derive_key_from_password(
    password="كلمة-مرور-قوية",
    algorithm="argon2",
    key_length=32
)
key = key_data['key']
```

### خطأ: Authentication tag verification failed

```
cryptography.exceptions.InvalidTag: Authentication tag verification failed
```

**السبب**: البيانات المشفرة أو المفتاح أو IV تم تعديلها.

**الحل**:

```python
# تأكد من:
# 1. استخدام نفس المفتاح للتشفير وفك التشفير
# 2. استخدام نفس IV
# 3. عدم تعديل ciphertext أو tag

# ✅ صحيح
from core_cryptography.encryption_framework import EncryptionFramework

framework = EncryptionFramework()
key = os.urandom(32)

# التشفير
algo, iv, ciphertext, tag = framework.encrypt(data, key, "AES-GCM")

# حفظ جميع المكونات
encrypted_package = {
    'algorithm': algo,
    'iv': iv.hex(),
    'ciphertext': ciphertext.hex(),
    'tag': tag.hex()
}

# فك التشفير - استخدم نفس المكونات بالضبط
decrypted = framework.decrypt(
    encrypted_package['algorithm'],
    key,
    bytes.fromhex(encrypted_package['iv']),
    bytes.fromhex(encrypted_package['ciphertext']),
    bytes.fromhex(encrypted_package['tag'])
)
```

### خطأ: Nonce reuse

```
Warning: Nonce reused with the same key!
```

**السبب**: إعادة استخدام نفس IV/Nonce مع نفس المفتاح.

**الحل**:

```python
# ❌ خطأ: إعادة استخدام IV
iv = b"same_iv_always"
for data in messages:
    framework.encrypt(data, key, "AES-GCM")  # خطير!

# ✅ صحيح: IV جديد لكل عملية (تلقائي)
for data in messages:
    algo, iv, ciphertext, tag = framework.encrypt(data, key, "AES-GCM")
    # IV مختلف في كل مرة
```

## أخطاء إدارة المفاتيح

### خطأ: Password too weak

```
ValueError: Password does not meet strength requirements
```

**الحل**:

```python
from key_management.enhanced_kdf_password import PasswordValidator

validator = PasswordValidator()

# فحص قوة كلمة المرور
password = "كلمة-مرور-ضعيفة"
result = validator.validate_password(password)

if not result['valid']:
    print(f"الأخطاء: {result['errors']}")
    # الأخطاء: ['كلمة المرور قصيرة جداً', 'تفتقر لأحرف خاصة', ...]

# ✅ توليد كلمة مرور قوية
strong_password = validator.generate_secure_password(
    length=20,
    use_symbols=True,
    use_numbers=True
)

print(f"كلمة مرور قوية: {strong_password}")
```

### خطأ: KeyError - Session not found

```
KeyError: Session ID xxx not found
```

**السبب**: الجلسة منتهية أو محذوفة.

**الحل**:

```python
from specialized_security.secure_session_manager import SecureSessionManager

session_manager = SecureSessionManager()

# إنشاء جلسة
session_id = session_manager.create_session()

try:
    # محاولة الوصول للجلسة
    data = session_manager.get_session_data(session_id)
except KeyError:
    # الجلسة غير موجودة - إنشاء جلسة جديدة
    session_id = session_manager.create_session()
    data = session_manager.get_session_data(session_id)
```

## أخطاء الأمان المتخصص

### خطأ: Data too large to embed in image

```
ValueError: Data is too large to embed in the image
```

**السبب**: البيانات أكبر من السعة المتاحة في الصورة.

**الحل**:

```python
from specialized_security.steganography_unit import SteganographyUnit
from PIL import Image

stego = SteganographyUnit()

# حساب السعة المتاحة
def get_image_capacity(image_path):
    img = Image.open(image_path)
    width, height = img.size
    # 3 بتات لكل بكسل (RGB)
    bits = width * height * 3
    bytes_capacity = bits // 8
    # طرح حجم الفاصل
    return bytes_capacity - len(b"#####END#####")

capacity = get_image_capacity('photo.jpg')
data = b"بيانات كبيرة..."

if len(data) > capacity:
    print(f"⚠️ البيانات ({len(data)} بايت) أكبر من السعة ({capacity} بايت)")
    
    # الحل 1: ضغط البيانات
    from data_protection.compression_unit import CompressionUnit
    compressor = CompressionUnit()
    compressed = compressor.compress(data)
    
    if len(compressed) <= capacity:
        print(f"✓ الضغط نجح: {len(compressed)} بايت")
        stego.embed_data('photo.jpg', compressed, 'stego.jpg')
    
    # الحل 2: استخدم صورة أكبر
    # أو الحل 3: قسم البيانات على عدة صور
```

### خطأ: No embedded data or delimiter not found

```
ValueError: No embedded data or delimiter not found
```

**السبب**: الصورة لا تحتوي على بيانات مخفية أو تم تعديلها.

**الحل**:

```python
try:
    extracted = stego.extract_data('image.jpg')
except ValueError as e:
    print(f"خطأ: {e}")
    print("تأكد من:")
    print("  1. الصورة تحتوي على بيانات مخفية")
    print("  2. الصورة لم يتم تعديلها بعد الإخفاء")
    print("  3. استخدام نفس الصورة التي تم الإخفاء فيها")
```

## أخطاء التوقيعات العتبية

### خطأ: Insufficient signatures

```
ValueError: Need at least X signatures, got Y
```

**السبب**: عدد التوقيعات أقل من العتبة المطلوبة.

**الحل**:

```python
from advanced_features.threshold_multisig_enhanced import ThresholdECDSA

threshold_ecdsa = ThresholdECDSA()

# نظام 3 من 5
participants = ["p1", "p2", "p3", "p4", "p5"]
keypair = threshold_ecdsa.generate_threshold_keypair(
    threshold=3,
    total_participants=5,
    participants=participants
)

message = b"معاملة مهمة"
partial_sigs = []

# جمع التوقيعات
for i in range(2):  # فقط 2 توقيعات - غير كافي!
    sig = threshold_ecdsa.create_partial_signature(
        keypair, i + 1, message, participants[i]
    )
    partial_sigs.append(sig)

try:
    # محاولة الدمج
    final_sig = threshold_ecdsa.combine_partial_signatures(
        keypair, partial_sigs, message
    )
except ValueError as e:
    print(f"خطأ: {e}")
    print(f"مطلوب {keypair.threshold} توقيعات، متوفر {len(partial_sigs)}")
    
    # الحل: جمع المزيد من التوقيعات
    for i in range(2, keypair.threshold):
        sig = threshold_ecdsa.create_partial_signature(
            keypair, i + 1, message, participants[i]
        )
        partial_sigs.append(sig)
    
    # الآن يمكن الدمج
    final_sig = threshold_ecdsa.combine_partial_signatures(
        keypair, partial_sigs, message
    )
    print("✓ تم دمج التوقيعات بنجاح")
```

## أخطاء التشفير الكمي

### خطأ: liboqs not installed

```
ImportError: No module named 'oqs'
```

**السبب**: مكتبة liboqs-python غير مثبتة.

**الحل**:

```bash
# تثبيت liboqs-python
pip install liboqs-python

# أو إعادة تثبيت ZyraCrypt
pip install -e .
```

### خطأ: Invalid algorithm for PQC

```
ValueError: Algorithm 'XYZ' not supported
```

**الحل**:

```python
from post_quantum_cryptography.post_quantum_cryptography_unit import (
    PostQuantumCryptographyUnit
)

pqc = PostQuantumCryptographyUnit()

# ✅ الخوارزميات المدعومة
kem_algorithms = ["Kyber512", "Kyber768", "Kyber1024"]
signature_algorithms = ["Dilithium2", "Dilithium3", "Dilithium5"]

# استخدم واحدة من المدعومة
public_key, private_key = pqc.generate_keypair_kem("Kyber768")
```

## أخطاء الأداء

### مشكلة: التشفير بطيء جداً

**السبب المحتمل**: استخدام Argon2 بإعدادات عالية جداً.

**الحل**:

```python
from key_management.enhanced_kdf_password import (
    EnhancedKDF, KDFAlgorithm, SecurityProfile
)

kdf = EnhancedKDF()

# ❌ بطيء: إعدادات Paranoid
slow_key = kdf.derive_key(
    password="password",
    algorithm=KDFAlgorithm.ARGON2ID,
    security_profile=SecurityProfile.PARANOID  # بطيء جداً!
)

# ✅ أسرع: إعدادات Interactive
fast_key = kdf.derive_key(
    password="password",
    algorithm=KDFAlgorithm.ARGON2ID,
    security_profile=SecurityProfile.INTERACTIVE  # مناسب للتطبيقات
)

# أو استخدم Scrypt إذا كان الأداء حرجاً
faster_key = kdf.derive_key(
    password="password",
    algorithm=KDFAlgorithm.SCRYPT,
    security_profile=SecurityProfile.MODERATE
)
```

### مشكلة: استهلاك ذاكرة عالي

**الحل**:

```python
# معالجة ملفات كبيرة بأجزاء
def encrypt_large_file_chunked(input_file, output_file, key, chunk_size=1024*1024):
    """تشفير ملف كبير على أجزاء (1MB لكل جزء)"""
    from core_cryptography.encryption_framework import EncryptionFramework
    
    framework = EncryptionFramework()
    
    with open(input_file, 'rb') as f_in:
        with open(output_file, 'wb') as f_out:
            chunk_num = 0
            while True:
                chunk = f_in.read(chunk_size)
                if not chunk:
                    break
                
                # تشفير كل جزء
                algo, iv, ciphertext, tag = framework.encrypt(
                    chunk, key, "AES-GCM"
                )
                
                # حفظ الجزء المشفر
                f_out.write(len(iv).to_bytes(4, 'big'))
                f_out.write(iv)
                f_out.write(len(tag).to_bytes(4, 'big'))
                f_out.write(tag)
                f_out.write(len(ciphertext).to_bytes(4, 'big'))
                f_out.write(ciphertext)
                
                chunk_num += 1
                print(f"تم تشفير الجزء {chunk_num}")

# الاستخدام
key = os.urandom(32)
encrypt_large_file_chunked('large_file.bin', 'large_file.enc', key)
```

## مشاكل التثبيت

### مشكلة: Dependency conflicts

```
ERROR: pip's dependency resolver does not currently take into account all the packages that are installed
```

**الحل**:

```bash
# 1. إنشاء بيئة افتراضية جديدة
python -m venv zyracrypt_env
source zyracrypt_env/bin/activate  # Linux/Mac
# أو
zyracrypt_env\Scripts\activate  # Windows

# 2. تحديث pip
pip install --upgrade pip

# 3. تثبيت ZyraCrypt
pip install -e .

# 4. إذا استمرت المشكلة، ثبت التبعيات يدوياً
pip install cryptography>=46.0.2
pip install pynacl>=1.6.0
pip install argon2-cffi>=25.1.0
pip install liboqs-python>=0.14.1
pip install pillow>=11.3.0
pip install flask>=3.1.2
pip install flask-cors>=6.0.1
pip install flask-sqlalchemy>=3.1.1
```

### مشكلة: Import errors

```
ImportError: cannot import name 'X' from 'module'
```

**الحل**:

```python
# تحقق من التثبيت
import sys
print(sys.path)

# تحقق من إصدار المكتبات
import cryptography
print(f"cryptography version: {cryptography.__version__}")

# إعادة تثبيت
# pip uninstall zyracrypt
# pip install -e .
```

## الأخطاء الشائعة والحلول السريعة

### جدول الأخطاء

| الخطأ | السبب | الحل السريع |
|-------|-------|-------------|
| `ValueError: Invalid key size` | مفتاح بطول خاطئ | `key = os.urandom(32)` |
| `InvalidTag` | تعديل البيانات المشفرة | تحقق من المفتاح والـ IV |
| `KeyError: Session not found` | جلسة منتهية | أنشئ جلسة جديدة |
| `Data too large to embed` | البيانات أكبر من الصورة | ضغط البيانات أو صورة أكبر |
| `Insufficient signatures` | توقيعات قليلة | اجمع المزيد من التوقيعات |
| `ImportError: oqs` | liboqs غير مثبت | `pip install liboqs-python` |

## نصائح للتصحيح

### تفعيل السجلات

```python
import logging

# تفعيل السجلات التفصيلية
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# استخدام المكتبة
from core_cryptography.encryption_framework import EncryptionFramework

framework = EncryptionFramework()
# سترى سجلات مفصلة عن العمليات
```

### اختبار المكونات

```python
def test_encryption_basic():
    """اختبار التشفير الأساسي"""
    from core_cryptography.encryption_framework import EncryptionFramework
    import os
    
    framework = EncryptionFramework()
    key = os.urandom(32)
    data = b"test data"
    
    try:
        # التشفير
        algo, iv, ciphertext, tag = framework.encrypt(data, key, "AES-GCM")
        print(f"✓ التشفير نجح")
        
        # فك التشفير
        decrypted = framework.decrypt(algo, key, iv, ciphertext, tag)
        
        # التحقق
        assert data == decrypted, "البيانات لا تتطابق!"
        print(f"✓ فك التشفير نجح")
        print(f"✓ الاختبار نجح")
        
        return True
    except Exception as e:
        print(f"❌ الاختبار فشل: {e}")
        return False

# تشغيل الاختبار
test_encryption_basic()
```

## الحصول على المساعدة

إذا واجهت مشكلة لم تُذكر هنا:

1. **راجع السجلات**: فعّل `logging.DEBUG`
2. **تحقق من الإصدارات**: تأكد من تحديث المكتبات
3. **اختبر مكون واحد**: عزل المشكلة
4. **راجع الوثائق**: [مرجع API](07-api-reference.md)
5. **تحقق من الأمثلة**: [أمثلة عملية](06-examples.md)

---

**التالي**: [الأسئلة الشائعة](13-faq.md)
