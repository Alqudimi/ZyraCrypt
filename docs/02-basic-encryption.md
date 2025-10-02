# دليل التشفير الأساسي

## مقدمة

يوفر ZyraCrypt مجموعة شاملة من خوارزميات التشفير المتماثل وغير المتماثل. في هذا الدليل، سنتعلم كيفية استخدام الوظائف الأساسية للتشفير.

## التشفير المتماثل (Symmetric Encryption)

التشفير المتماثل يستخدم نفس المفتاح للتشفير وفك التشفير.

### 1. التشفير باستخدام AES-GCM

AES-GCM هو معيار التشفير الأكثر أماناً وشيوعاً:

```python
from core_cryptography.encryption_framework import EncryptionFramework

# إنشاء كائن التشفير
framework = EncryptionFramework()

# المفتاح (يجب أن يكون 32 بايت لـ AES-256)
key = b"مفتاح-سري-32-بايت-للتشفير!!"

# البيانات للتشفير
plaintext = b"رسالة سرية جداً"

# التشفير
algorithm, iv, ciphertext, tag = framework.encrypt(
    plaintext, 
    key, 
    "AES-GCM"
)

print(f"الخوارزمية: {algorithm}")
print(f"IV: {iv.hex()}")
print(f"النص المشفر: {ciphertext.hex()}")
print(f"العلامة (Tag): {tag.hex()}")

# فك التشفير
decrypted = framework.decrypt(algorithm, key, iv, ciphertext, tag)
print(f"النص الأصلي: {decrypted.decode('utf-8')}")
```

### 2. التشفير باستخدام ChaCha20-Poly1305

ChaCha20 هو خوارزمية حديثة وسريعة جداً:

```python
from core_cryptography.encryption_framework import EncryptionFramework

framework = EncryptionFramework()

# مفتاح 32 بايت
key = b"مفتاح-chacha20-32-بايت-هنا!!"
plaintext = b"بيانات مهمة للحماية"

# التشفير بـ ChaCha20
algorithm, nonce, ciphertext, _ = framework.encrypt(
    plaintext, 
    key, 
    "ChaCha20"
)

# فك التشفير
decrypted = framework.decrypt(algorithm, key, nonce, ciphertext)
print(f"البيانات: {decrypted.decode('utf-8')}")
```

### 3. الاختيار التلقائي للخوارزمية

يمكن للمكتبة اختيار الخوارزمية الأفضل تلقائياً:

```python
# استخدم "auto" للاختيار التلقائي
algorithm, iv, ciphertext, tag = framework.encrypt(
    plaintext, 
    key, 
    "auto"  # الاختيار التلقائي
)

# المكتبة ستختار الأفضل حسب حجم البيانات
```

## التشفير غير المتماثل (Asymmetric Encryption)

يستخدم زوج من المفاتيح: عام وخاص.

### 1. التشفير بـ RSA

```python
from core_cryptography.asymmetric_encryption import AsymmetricEncryption

# إنشاء كائن التشفير غير المتماثل
asymmetric = AsymmetricEncryption()

# توليد زوج مفاتيح RSA
private_key, public_key = asymmetric.generate_rsa_keypair(key_size=2048)

# البيانات للتشفير (يجب أن تكون صغيرة لـ RSA)
data = b"رسالة قصيرة"

# التشفير بالمفتاح العام
ciphertext = asymmetric.encrypt_rsa(public_key, data)

# فك التشفير بالمفتاح الخاص
decrypted = asymmetric.decrypt_rsa(private_key, ciphertext)
print(f"البيانات الأصلية: {decrypted.decode('utf-8')}")
```

### 2. التوقيع الرقمي بـ ECDSA

```python
from core_cryptography.asymmetric_encryption import AsymmetricEncryption

asymmetric = AsymmetricEncryption()

# توليد زوج مفاتيح ECDSA
private_key, public_key = asymmetric.generate_ecdsa_keypair(curve="P-256")

# الرسالة للتوقيع
message = b"وثيقة مهمة تحتاج توقيع"

# التوقيع
signature = asymmetric.sign_ecdsa(private_key, message)
print(f"التوقيع: {signature.hex()}")

# التحقق من التوقيع
is_valid = asymmetric.verify_ecdsa(public_key, message, signature)
print(f"التوقيع صحيح: {is_valid}")
```

### 3. تبادل المفاتيح بـ ECDH

```python
from key_management.key_exchange import KeyExchange

key_exchange = KeyExchange()

# الطرف الأول (أليس)
alice_private, alice_public = key_exchange.generate_ecdh_keypair()

# الطرف الثاني (بوب)
bob_private, bob_public = key_exchange.generate_ecdh_keypair()

# أليس تحسب المفتاح المشترك
alice_shared = key_exchange.compute_ecdh_shared_secret(
    alice_private, 
    bob_public
)

# بوب يحسب نفس المفتاح المشترك
bob_shared = key_exchange.compute_ecdh_shared_secret(
    bob_private, 
    alice_public
)

# يجب أن يكون المفتاحان متطابقين
print(f"المفاتيح متطابقة: {alice_shared == bob_shared}")
```

## التشفير مع بيانات إضافية مرتبطة (AEAD)

يمكنك إضافة بيانات إضافية غير مشفرة لكن محمية:

```python
from core_cryptography.encryption_framework import EncryptionFramework

framework = EncryptionFramework()

key = b"مفتاح-32-بايت-للتشفير-aead!"
plaintext = b"محتوى سري"
associated_data = b"معلومات-هوية-المرسل"  # غير مشفرة لكن محمية

# التشفير مع البيانات الإضافية
algorithm, iv, ciphertext, tag = framework.encrypt(
    plaintext, 
    key, 
    "AES-GCM",
    associated_data=associated_data
)

# فك التشفير (يجب تقديم نفس البيانات الإضافية)
decrypted = framework.decrypt(
    algorithm, 
    key, 
    iv, 
    ciphertext, 
    tag,
    associated_data=associated_data
)
```

## أفضل الممارسات

### 1. توليد المفاتيح الآمنة

```python
import os

# استخدم os.urandom لتوليد مفاتيح عشوائية آمنة
key_32_bytes = os.urandom(32)  # لـ AES-256
key_16_bytes = os.urandom(16)  # لـ AES-128
```

### 2. إدارة IV/Nonce

```python
# ⚠️ لا تفعل هذا:
# iv = b"same_iv_always"  # خطأ! لا تعيد استخدام IV

# ✅ افعل هذا:
# كل عملية تشفير تولد IV جديد تلقائياً
```

### 3. حفظ البيانات المشفرة

```python
import json
import base64

# حفظ النتائج
encrypted_data = {
    'algorithm': algorithm,
    'iv': base64.b64encode(iv).decode('utf-8'),
    'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
    'tag': base64.b64encode(tag).decode('utf-8')
}

# حفظ في ملف
with open('encrypted.json', 'w') as f:
    json.dump(encrypted_data, f)

# قراءة من ملف
with open('encrypted.json', 'r') as f:
    loaded_data = json.load(f)
    
# فك التشفير
decrypted = framework.decrypt(
    loaded_data['algorithm'],
    key,
    base64.b64decode(loaded_data['iv']),
    base64.b64decode(loaded_data['ciphertext']),
    base64.b64decode(loaded_data['tag'])
)
```

## مقارنة الخوارزميات

| الخوارزمية | السرعة | الأمان | الاستخدام المفضل |
|-----------|--------|--------|------------------|
| AES-256-GCM | سريع جداً | عالي جداً | البيانات الحساسة |
| ChaCha20-Poly1305 | أسرع | عالي جداً | الأجهزة المحمولة |
| RSA-2048 | بطيء | عالي | تشفير المفاتيح |
| ECDSA | سريع | عالي جداً | التوقيعات |

## الأخطاء الشائعة وحلولها

### خطأ: Invalid key size

```python
# ❌ خطأ
key = b"short"  # قصير جداً

# ✅ صحيح
key = os.urandom(32)  # 32 بايت لـ AES-256
```

### خطأ: Invalid tag

```python
# ❌ تعديل البيانات المشفرة يسبب فشل التحقق
ciphertext_modified = ciphertext + b"hack"

# ✅ استخدم البيانات الأصلية دون تعديل
```

## أمثلة متقدمة

### تشفير ملف كامل

```python
from core_cryptography.encryption_framework import EncryptionFramework
import os

def encrypt_file(input_path, output_path, key):
    framework = EncryptionFramework()
    
    # قراءة الملف
    with open(input_path, 'rb') as f:
        plaintext = f.read()
    
    # التشفير
    algorithm, iv, ciphertext, tag = framework.encrypt(
        plaintext, key, "AES-GCM"
    )
    
    # حفظ النتائج
    with open(output_path, 'wb') as f:
        # حفظ الميتاداتا أولاً
        f.write(algorithm.encode('utf-8').ljust(20))
        f.write(len(iv).to_bytes(4, 'big'))
        f.write(iv)
        f.write(tag)
        f.write(ciphertext)
    
    print(f"تم تشفير {input_path} إلى {output_path}")

# الاستخدام
key = os.urandom(32)
encrypt_file('document.pdf', 'document.pdf.enc', key)
```

---

**التالي**: [إدارة المفاتيح](03-key-management.md)
