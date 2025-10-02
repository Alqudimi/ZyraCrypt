# دليل التشفير ما بعد الكم (Post-Quantum Cryptography)

## مقدمة

مع تطور الحوسبة الكمية، أصبحت خوارزميات التشفير التقليدية عرضة للاختراق. يوفر ZyraCrypt دعماً للتشفير المستقبلي الآمن من الحواسيب الكمية.

## ما هو التشفير الكمي؟

التشفير ما بعد الكم (PQC) هو مجموعة من الخوارزميات التشفيرية المصممة لتكون مقاومة لهجمات الحواسيب الكمية المستقبلية.

### لماذا نحتاجه؟

- **حواسيب كمية قادمة**: ستتمكن من كسر RSA و ECDSA
- **البيانات طويلة الأمد**: البيانات المشفرة اليوم قد تُخترق غداً
- **"حصد الآن، فك لاحقاً"**: المهاجمون يخزنون البيانات المشفرة لفكها مستقبلاً

## خوارزميات PQC المدعومة

### 1. Kyber (تبادل المفاتيح)

Kyber هو خوارزمية آمنة لتبادل المفاتيح (KEM - Key Encapsulation Mechanism).

```python
from post_quantum_cryptography.post_quantum_cryptography_unit import (
    PostQuantumCryptographyUnit
)

# إنشاء وحدة PQC
pqc_unit = PostQuantumCryptographyUnit()

# اختيار خوارزمية Kyber
pqc_algorithm = "Kyber512"  # أو Kyber768 أو Kyber1024

# توليد زوج مفاتيح
public_key, private_key = pqc_unit.generate_keypair_kem(pqc_algorithm)

print(f"حجم المفتاح العام: {len(public_key)} بايت")
print(f"حجم المفتاح الخاص: {len(private_key)} بايت")

# تغليف مفتاح مشترك (من قبل المرسل)
encapsulated_key, shared_secret_sender = pqc_unit.encapsulate_kem(
    pqc_algorithm, 
    public_key
)

print(f"\nالمفتاح المغلف: {len(encapsulated_key)} بايت")
print(f"السر المشترك (مرسل): {shared_secret_sender.hex()[:40]}...")

# فك تغليف المفتاح (من قبل المستقبل)
shared_secret_receiver = pqc_unit.decapsulate_kem(
    pqc_algorithm, 
    private_key, 
    encapsulated_key
)

print(f"السر المشترك (مستقبل): {shared_secret_receiver.hex()[:40]}...")
print(f"\nالأسرار متطابقة: {shared_secret_sender == shared_secret_receiver}")
```

### 2. Dilithium (التوقيعات الرقمية)

Dilithium هو خوارزمية آمنة للتوقيعات الرقمية.

```python
from post_quantum_cryptography.post_quantum_cryptography_unit import (
    PostQuantumCryptographyUnit
)

pqc_unit = PostQuantumCryptographyUnit()

# اختيار خوارزمية Dilithium
signature_algorithm = "Dilithium2"  # أو Dilithium3 أو Dilithium5

# توليد زوج مفاتيح للتوقيع
signing_key, verifying_key = pqc_unit.generate_keypair_signature(
    signature_algorithm
)

print(f"مفتاح التوقيع: {len(signing_key)} بايت")
print(f"مفتاح التحقق: {len(verifying_key)} بايت")

# توقيع رسالة
message = b"وثيقة مهمة تحتاج توقيع كمي آمن"
signature = pqc_unit.sign(signature_algorithm, signing_key, message)

print(f"\nالتوقيع: {len(signature)} بايت")
print(f"التوقيع (hex): {signature.hex()[:60]}...")

# التحقق من التوقيع
is_valid = pqc_unit.verify(
    signature_algorithm, 
    verifying_key, 
    message, 
    signature
)

print(f"\nالتوقيع صحيح: {is_valid} ✓")

# محاولة بتوقيع خاطئ
fake_signature = signature[:-10] + b"1234567890"
is_invalid = pqc_unit.verify(
    signature_algorithm, 
    verifying_key, 
    message, 
    fake_signature
)

print(f"توقيع معدّل صحيح: {is_invalid} (يجب أن يكون False)")
```

## التشفير الهجين (Hybrid Cryptography)

يجمع التشفير الهجين بين الخوارزميات التقليدية والكمية لأقصى أمان.

### لماذا الهجين؟

- **أمان مزدوج**: حماية من الحواسيب التقليدية والكمية
- **الانتقال التدريجي**: استخدام PQC مع بقاء الأنظمة التقليدية
- **ثقة متعددة**: عدم الاعتماد على خوارزمية واحدة فقط

### تبادل المفاتيح الهجين

```python
from advanced_features.hybrid_pqc_enhanced import HybridPQCEngine, SecurityLevel

# إنشاء محرك التشفير الهجين
engine = HybridPQCEngine(security_level=SecurityLevel.LEVEL_128)

# توليد أزواج مفاتيح هجينة
public_keys, private_keys = engine.generate_hybrid_keypair()

print("المفاتيح الهجينة:")
print(f"  مفتاح كلاسيكي (ECDH): موجود")
print(f"  مفتاح كمي (Kyber): موجود")

# تبادل مفتاح هجين
key_material = engine.hybrid_key_exchange(public_keys)

print(f"\nالسر الكلاسيكي: {len(key_material.classical_shared_secret)} بايت")
print(f"السر الكمي: {len(key_material.pq_shared_secret)} بايت")
print(f"السر المدمج: {len(key_material.combined_shared_secret)} بايت")
print(f"السر المدمج (hex): {key_material.combined_shared_secret.hex()}")
```

### التوقيع الهجين

```python
from advanced_features.hybrid_pqc_enhanced import HybridPQCEngine

engine = HybridPQCEngine(security_level=SecurityLevel.LEVEL_192)

# توليد أزواج مفاتيح هجينة للتوقيع
sig_public, sig_private = engine.generate_hybrid_signature_keypair()

print("مفاتيح التوقيع الهجينة:")
print(f"  مفتاح كلاسيكي (ECDSA): موجود")
print(f"  مفتاح كمي (Dilithium): موجود")

# التوقيع
message = b"عقد مهم يحتاج أمان مستقبلي"
signatures = engine.hybrid_sign(sig_private, message)

print(f"\nالتوقيع الكلاسيكي: {len(signatures.classical_signature)} بايت")
print(f"التوقيع الكمي: {len(signatures.pq_signature)} بايت")

# التحقق
is_valid = engine.hybrid_verify(sig_public, message, signatures)
print(f"التوقيع الهجين صحيح: {is_valid} ✓")
```

### معلومات الخوارزميات

```python
# الحصول على معلومات الخوارزميات المستخدمة
info = engine.get_algorithm_info()

print("\nمعلومات التشفير الهجين:")
print(f"  مستوى الأمان: {info['security_level']} بت")
print(f"  الخوارزمية الكلاسيكية: {info['classical_algorithm']}")
print(f"  الخوارزمية الكمية: {info['pq_algorithm']}")
print(f"  دالة دمج المفاتيح: {info['kdf']}")
```

## مستويات الأمان

ZyraCrypt يدعم عدة مستويات أمان:

| المستوى | قوة كلاسيكية | قوة كمية | الاستخدام |
|---------|--------------|---------|-----------|
| 128-bit | ECDH P-256 | Kyber512 | الأنظمة العامة |
| 192-bit | ECDH P-384 | Kyber768 | البيانات الحساسة |
| 256-bit | ECDH P-521 | Kyber1024 | سري للغاية |

### اختيار مستوى الأمان

```python
from advanced_features.hybrid_pqc_enhanced import HybridPQCEngine

# مستوى أمان قياسي (128-bit)
engine_standard = HybridPQCEngine(security_level=128)

# مستوى أمان عالي (192-bit)
engine_high = HybridPQCEngine(security_level=192)

# مستوى أمان فائق (256-bit) - للبيانات طويلة الأمد جداً
engine_ultra = HybridPQCEngine(security_level=256)
```

## حالات استخدام عملية

### 1. تأمين الاتصالات طويلة الأمد

```python
from advanced_features.hybrid_pqc_enhanced import HybridPQCEngine
from core_cryptography.encryption_framework import EncryptionFramework

# إعداد التشفير الهجين
hybrid_engine = HybridPQCEngine(security_level=192)
framework = EncryptionFramework()

# توليد مفاتيح للطرفين
alice_public, alice_private = hybrid_engine.generate_hybrid_keypair()
bob_public, bob_private = hybrid_engine.generate_hybrid_keypair()

# أليس تشفر رسالة لبوب
message = b"رسالة سرية مستقبلية الأمان"

# تبادل مفتاح هجين
key_material = hybrid_engine.hybrid_key_exchange(bob_public)
shared_secret = key_material.combined_shared_secret

# استخدام السر المشترك للتشفير المتماثل
algo, iv, ciphertext, tag = framework.encrypt(
    message, 
    shared_secret, 
    "AES-GCM"
)

print("تم تشفير الرسالة بأمان هجين كمي!")
```

### 2. توقيع المستندات الرسمية

```python
from advanced_features.hybrid_pqc_enhanced import HybridPQCEngine
import json
from datetime import datetime

# إعداد التوقيع الهجين
engine = HybridPQCEngine(security_level=192)

# توليد مفاتيح التوقيع
public_key, private_key = engine.generate_hybrid_signature_keypair()

# المستند
document = {
    'type': 'عقد رسمي',
    'parties': ['الطرف الأول', 'الطرف الثاني'],
    'date': datetime.now().isoformat(),
    'terms': 'شروط العقد هنا...',
    'amount': '100,000 ريال'
}

# تحويل المستند إلى بايتات
document_bytes = json.dumps(document, ensure_ascii=False).encode('utf-8')

# توقيع المستند
signatures = engine.hybrid_sign(private_key, document_bytes)

# حفظ المستند الموقع
signed_document = {
    'document': document,
    'classical_signature': signatures.classical_signature.hex(),
    'pq_signature': signatures.pq_signature.hex(),
    'timestamp': signatures.timestamp
}

print("تم توقيع المستند بأمان هجين!")
print(f"الطابع الزمني: {signed_document['timestamp']}")

# لاحقاً: التحقق من التوقيع
is_valid = engine.hybrid_verify(public_key, document_bytes, signatures)
print(f"المستند صحيح: {is_valid} ✓")
```

### 3. تشفير النسخ الاحتياطية طويلة الأمد

```python
from advanced_features.hybrid_pqc_enhanced import HybridPQCEngine
from core_cryptography.encryption_framework import EncryptionFramework
import os

def create_quantum_safe_backup(data, backup_name):
    """إنشاء نسخة احتياطية آمنة كمياً"""
    
    # إعداد أمان فائق (256-bit)
    engine = HybridPQCEngine(security_level=256)
    framework = EncryptionFramework()
    
    # توليد مفاتيح هجينة
    public_keys, private_keys = engine.generate_hybrid_keypair()
    
    # تبادل مفتاح
    key_material = engine.hybrid_key_exchange(public_keys)
    encryption_key = key_material.combined_shared_secret
    
    # تشفير البيانات
    algo, iv, ciphertext, tag = framework.encrypt(
        data,
        encryption_key,
        "AES-GCM"
    )
    
    # حفظ النسخة الاحتياطية
    backup_data = {
        'name': backup_name,
        'algorithm': algo,
        'iv': iv.hex(),
        'ciphertext': ciphertext.hex(),
        'tag': tag.hex(),
        'private_keys': {
            'classical': private_keys.classical_private.hex(),
            'pq': private_keys.pq_private.hex()
        }
    }
    
    return backup_data

# الاستخدام
important_data = b"بيانات مهمة جداً للحفظ 100 سنة"
backup = create_quantum_safe_backup(important_data, "backup_2024")

print(f"تم إنشاء نسخة احتياطية آمنة كمياً: {backup['name']}")
```

## الأداء والاعتبارات

### مقارنة الأداء

| الخوارزمية | سرعة توليد المفاتيح | سرعة التشفير | حجم المفتاح |
|-----------|---------------------|--------------|-------------|
| RSA-2048 | بطيء | بطيء | كبير جداً |
| ECDH P-256 | سريع | سريع | صغير |
| Kyber512 | سريع | سريع جداً | متوسط |
| Dilithium2 | متوسط | سريع | كبير |
| هجين | متوسط | سريع | كبير |

### نصائح للأداء

```python
# ✅ استخدم المستوى المناسب لاحتياجاتك
# لتطبيقات الويب: 128-bit
engine_web = HybridPQCEngine(security_level=128)

# للبيانات الحساسة: 192-bit
engine_sensitive = HybridPQCEngine(security_level=192)

# للأرشيف طويل الأمد: 256-bit
engine_archive = HybridPQCEngine(security_level=256)

# ✅ أعد استخدام المفاتيح عند الإمكان
# ❌ لا تولد مفاتيح جديدة لكل رسالة
```

## أفضل الممارسات

### 1. استخدم الأمان الهجين دائماً

```python
# ✅ هجين = أمان مضاعف
hybrid_engine = HybridPQCEngine(security_level=192)

# ❌ كمي فقط = مخاطرة
# pqc_only = PostQuantumCryptographyUnit()
```

### 2. خطط للمستقبل

```python
# للبيانات التي ستبقى مشفرة > 10 سنوات
# استخدم مستوى أمان أعلى
if data_lifetime_years > 10:
    security_level = 256
else:
    security_level = 192
```

### 3. احتفظ بنسخ احتياطية من المفاتيح

```python
# ✅ احفظ المفاتيح بشكل آمن ومنفصل
import json

def backup_keys(public_keys, private_keys, backup_file):
    keys_data = {
        'public': {
            'classical': public_keys.classical_public.hex(),
            'pq': public_keys.pq_public.hex()
        },
        'private': {
            'classical': private_keys.classical_private.hex(),
            'pq': private_keys.pq_private.hex()
        }
    }
    
    with open(backup_file, 'w') as f:
        json.dump(keys_data, f)
```

---

**التالي**: [أمثلة عملية](06-examples.md)
