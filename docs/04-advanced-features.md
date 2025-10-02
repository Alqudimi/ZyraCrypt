# دليل الميزات المتقدمة

## مقدمة

يوفر ZyraCrypt مجموعة من الميزات المتقدمة التي تلبي احتياجات الأمان على مستوى المؤسسات، بما في ذلك التوقيعات العتبية، الحوسبة متعددة الأطراف، والأمان المعزز ضد الهجمات الجانبية.

## 1. التوقيعات العتبية (Threshold Signatures)

التوقيعات العتبية تتطلب عدد معين من المشاركين للتوقيع على رسالة.

### مشاركة السر بطريقة شامير (Shamir's Secret Sharing)

```python
from advanced_features.threshold_multisig_enhanced import ShamirSecretSharing

# إنشاء كائن مشاركة السر
sss = ShamirSecretSharing()

# السر الأصلي (مثلاً مفتاح تشفير)
secret = b"مفتاح-تشفير-سري-جداً-32-بايت"

# تقسيم السر إلى 5 أجزاء، يحتاج 3 منها لإعادة البناء
threshold = 3
total_shares = 5

shares = sss.split_secret(secret, threshold, total_shares)

print(f"تم إنشاء {len(shares)} جزء من السر")
for i, share in enumerate(shares, 1):
    print(f"الجزء {i}: {share.share_data[:20].hex()}...")

# إعادة بناء السر باستخدام 3 أجزاء فقط
reconstructed_secret = sss.reconstruct_secret(shares[:3])

print(f"\nالسر الأصلي: {secret.hex()}")
print(f"السر المعاد بناؤه: {reconstructed_secret.hex()}")
print(f"متطابقان: {secret == reconstructed_secret}")
```

### التوقيع العتبي بـ ECDSA

```python
from advanced_features.threshold_multisig_enhanced import ThresholdECDSA

# إنشاء نظام التوقيع العتبي
threshold_ecdsa = ThresholdECDSA()

# المشاركون
participants = ["علي", "محمد", "فاطمة", "أحمد", "خديجة"]

# إنشاء زوج مفاتيح عتبي (3 من 5)
keypair = threshold_ecdsa.generate_threshold_keypair(
    threshold=3,
    total_participants=5,
    participants=participants
)

print(f"نظام توقيع عتبي: {keypair.threshold} من {keypair.total_participants}")
print(f"معرّف المفتاح: {keypair.key_id}")

# الرسالة للتوقيع
message = b"معاملة مالية: تحويل 10000 ريال"

# كل مشارك ينشئ توقيع جزئي
partial_signatures = []

print("\nإنشاء التوقيعات الجزئية:")
for i, participant in enumerate(participants[:threshold]):
    partial_sig = threshold_ecdsa.create_partial_signature(
        keypair=keypair,
        share_index=i + 1,
        message=message,
        participant_id=participant
    )
    partial_signatures.append(partial_sig)
    print(f"  ✓ {participant}: توقيع جزئي تم إنشاؤه")

# دمج التوقيعات الجزئية
final_signature = threshold_ecdsa.combine_partial_signatures(
    keypair=keypair,
    partial_signatures=partial_signatures,
    message=message
)

print(f"\nحالة التوقيع النهائي: {final_signature.signature_status.value}")

# التحقق من التوقيع
is_valid = threshold_ecdsa.verify_threshold_signature(
    keypair=keypair,
    signature=final_signature,
    message=message
)

print(f"التوقيع صحيح: {is_valid} ✓")
```

### نظام التوقيع المتعدد (Multisig)

```python
from advanced_features.threshold_multisig_enhanced import (
    MultisigManager, ThresholdScheme
)

# إنشاء مدير التوقيعات المتعددة
multisig_manager = MultisigManager()

# إنشاء نظام multisig
participants = ["مدير_مالي", "مدير_تنفيذي", "محاسب", "مراجع", "مدير_عام"]

multisig_keypair = multisig_manager.create_multisig_setup(
    participants=participants,
    threshold=3,  # يحتاج 3 توقيعات
    scheme=ThresholdScheme.THRESHOLD_ECDSA
)

print(f"نظام Multisig تم إنشاؤه: {multisig_keypair.key_id}")

# الحصول على حالة النظام
status = multisig_manager.get_multisig_status(multisig_keypair.key_id)
print(f"العتبة: {status['threshold']}")
print(f"عدد المشاركين: {len(status['participants'])}")
print(f"المشاركون: {', '.join(status['participants'])}")
```

## 2. الحوسبة الآمنة متعددة الأطراف (MPC)

### الأمكنة الآمنة (Secure Enclaves)

```python
from advanced_features.secure_mpc_enclaves import (
    SecureEnclave, EnclaveType
)

# إنشاء مكان آمن برمجي
enclave = SecureEnclave(EnclaveType.SOFTWARE_ENCLAVE)

print(f"معرّف المكان الآمن: {enclave.enclave_id}")
print(f"النوع: {enclave.enclave_type.value}")

# تخزين سر في المكان الآمن
secret_key = b"مفتاح-سري-للغاية"
success = enclave.store_secret("master_key", secret_key)
print(f"تم تخزين السر: {success}")

# استرجاع السر
retrieved_secret = enclave.retrieve_secret("master_key")
print(f"السر متطابق: {retrieved_secret == secret_key}")

# تنفيذ حساب آمن داخل المكان الآمن
def secure_hash(data: bytes) -> bytes:
    import hashlib
    return hashlib.sha256(data).digest()

success = enclave.secure_computation(
    computation_function=secure_hash,
    input_secret_id="master_key",
    output_secret_id="key_hash"
)

# الحصول على شهادة المكان الآمن
attestation = enclave.get_attestation()
print(f"\nشهادة المكان الآمن:")
print(f"  المعرّف: {attestation['enclave_id']}")
print(f"  القياس: {attestation['measurement'][:40]}...")
print(f"  الوقت: {attestation['timestamp']}")

# تنظيف
enclave.clear_secrets()
```

### منسق الحوسبة متعددة الأطراف

```python
from advanced_features.secure_mpc_enclaves import (
    MPCCoordinator, MPCParticipant, MPCProtocol
)
import os

# إنشاء منسق MPC
coordinator = MPCCoordinator()

# تسجيل المشاركين
participants_list = ["طرف_1", "طرف_2", "طرف_3", "طرف_4"]

for participant_id in participants_list:
    participant = MPCParticipant(
        participant_id=participant_id,
        public_key=os.urandom(32),
        capabilities=[MPCProtocol.SECRET_SHARING, MPCProtocol.THRESHOLD_SIGNING]
    )
    coordinator.register_participant(participant)
    print(f"تم تسجيل: {participant_id}")

# إنشاء حساب MPC
function_spec = {
    'function': 'threshold_decryption',
    'threshold': 3,
    'algorithm': 'AES-256-GCM'
}

computation_id = coordinator.create_computation(
    protocol=MPCProtocol.SECRET_SHARING,
    function_specification=function_spec,
    participants=participants_list[:3]
)

print(f"\nمعرّف الحساب: {computation_id}")

# الحصول على حالة الحساب
status = coordinator.get_computation_status(computation_id)
print(f"البروتوكول: {status['protocol']}")
print(f"الحالة: {status['state']}")
print(f"المشاركون: {len(status['participants'])}")
```

### توليد المفاتيح الموزعة

```python
from advanced_features.secure_mpc_enclaves import SecureKeyGeneration

# إنشاء مولد مفاتيح آمن
key_gen = SecureKeyGeneration()

# توليد مفتاح موزع بين الأطراف
participants = ["بنك_أ", "بنك_ب", "بنك_ج", "بنك_د"]

computation_id = key_gen.distributed_key_generation(
    participants=participants,
    threshold=3,  # يحتاج 3 أطراف للاستخدام
    key_type='ecdsa'
)

print(f"معرّف توليد المفتاح: {computation_id}")

# الحصول على معلومات المفتاح
key_info = key_gen.get_key_info(computation_id)
print(f"\nمعلومات المفتاح الموزع:")
print(f"  المشاركون: {', '.join(key_info['participants'])}")
print(f"  العتبة: {key_info['threshold']}")
print(f"  النوع: {key_info['key_type']}")
print(f"  تم الإنشاء: {key_info['created_at']}")
```

## 3. المقاومة للهجمات الجانبية

### العمليات ذات الوقت الثابت

```python
from advanced_features.side_channel_protection import SideChannelGuard

# مقارنة آمنة بوقت ثابت
data1 = b"سر-تشفيري-123456"
data2 = b"سر-تشفيري-123456"
data3 = b"سر-مختلف-789012"

# مقارنة متطابقة
is_equal = SideChannelGuard.constant_time_compare(data1, data2)
print(f"البيانات متطابقة: {is_equal}")

# مقارنة مختلفة
is_different = SideChannelGuard.constant_time_compare(data1, data3)
print(f"البيانات مختلفة: {not is_different}")
```

### توليد أرقام عشوائية آمنة

```python
from advanced_features.side_channel_protection import SideChannelGuard

# توليد بيانات عشوائية آمنة
random_key = SideChannelGuard.secure_random(32)
random_nonce = SideChannelGuard.secure_random(12)

print(f"مفتاح عشوائي: {random_key.hex()}")
print(f"Nonce عشوائي: {random_nonce.hex()}")

# التأكد من أن البيانات مختلفة
another_random = SideChannelGuard.secure_random(32)
print(f"البيانات مختلفة: {random_key != another_random}")
```

### مسح الذاكرة الآمن

```python
from advanced_features.side_channel_protection import SideChannelGuard

# بيانات حساسة في الذاكرة
sensitive_data = bytearray(b"كلمة-مرور-سرية-جداً")
print(f"قبل المسح: {sensitive_data}")

# مسح آمن من الذاكرة
SideChannelGuard.secure_zero_memory(sensitive_data)
print(f"بعد المسح: {sensitive_data}")
print(f"تم المسح بنجاح: {all(byte == 0 for byte in sensitive_data)}")
```

### الحماية من هجمات التوقيت

```python
from advanced_features.side_channel_protection import timing_safe

@timing_safe
def sensitive_operation(password: str) -> bool:
    """عملية حساسة محمية من هجمات التوقيت"""
    correct_password = "كلمة-المرور-الصحيحة"
    
    # هذه المقارنة محمية تلقائياً
    return password == correct_password

# الاستخدام
result1 = sensitive_operation("كلمة-خاطئة")
result2 = sensitive_operation("كلمة-المرور-الصحيحة")

print(f"محاولة خاطئة: {result1}")
print(f"محاولة صحيحة: {result2}")
```

## 4. مرونة الخوارزميات (Algorithm Agility)

### استخدام سجل الخوارزميات

```python
from core_cryptography.algorithm_agility_versioning import (
    get_algorithm_registry, AlgorithmType, SecurityLevel
)

# الحصول على سجل الخوارزميات
registry = get_algorithm_registry()

# الحصول على الخوارزمية الموصى بها
recommended = registry.get_recommended_algorithm(
    algorithm_type=AlgorithmType.SYMMETRIC_ENCRYPTION,
    security_level=SecurityLevel.LEVEL_256
)

print(f"الخوارزمية الموصى بها:")
print(f"  الاسم: {recommended.algorithm_name}")
print(f"  مستوى الأمان: {recommended.security_level}")
print(f"  الحالة: {recommended.status}")

# الحصول على الخوارزميات المهجورة
deprecated = registry.get_deprecated_algorithms()
print(f"\nالخوارزميات المهجورة: {len(deprecated)}")
for algo in deprecated:
    print(f"  - {algo.algorithm_name}: {algo.deprecation_reason}")
```

### التشفير الإصداري

```python
from core_cryptography.algorithm_agility_versioning import create_versioned_encryption

# إنشاء تشفير مع إدارة الإصدارات
versioned_crypto = create_versioned_encryption()

# تشفير البيانات (الإصدار الحالي)
data = b"بيانات مهمة للحفظ طويل الأمد"
encrypted_data = versioned_crypto.encrypt(data)

print(f"إصدار التنسيق: {encrypted_data['format_version']}")
print(f"الخوارزمية: {encrypted_data['context']['algorithm']}")
print(f"وقت التشفير: {encrypted_data['context']['encrypted_at']}")

# فك التشفير (يدعم إصدارات متعددة)
decrypted_data = versioned_crypto.decrypt(encrypted_data)
print(f"البيانات الأصلية: {decrypted_data.decode('utf-8')}")
```

### إدارة الترحيل

```python
from core_cryptography.algorithm_agility_versioning import create_migration_manager

# إنشاء مدير الترحيل
migration_manager = create_migration_manager()

# فحص الحاجة للترحيل
needs_migration, reason = migration_manager.check_migration_needed(encrypted_data)

if needs_migration:
    print(f"يحتاج للترحيل: {reason}")
    
    # تنفيذ الترحيل
    migrated_data = migration_manager.migrate_encryption(encrypted_data)
    print(f"تم الترحيل إلى إصدار: {migrated_data['format_version']}")
else:
    print("لا يحتاج للترحيل")
```

## 5. التشفير من نهاية إلى نهاية للمجموعات

```python
from advanced_features.group_e2e_encryption import GroupE2EManager

# إنشاء مدير تشفير المجموعة
group_manager = GroupE2EManager()

# إنشاء مجموعة
group_id = "مجموعة-العمل-السرية"
members = ["عضو_1", "عضو_2", "عضو_3", "عضو_4"]

group_info = group_manager.create_group(group_id, "admin", members)
print(f"تم إنشاء المجموعة: {group_info['group_id']}")
print(f"عدد الأعضاء: {len(group_info['members'])}")

# تشفير رسالة للمجموعة
message = b"رسالة سرية للمجموعة"
encrypted_message = group_manager.encrypt_for_group(group_id, message)

print(f"\nالرسالة المشفرة:")
print(f"  المجموعة: {encrypted_message['group_id']}")
print(f"  الإصدار: {encrypted_message['version']}")

# فك تشفير الرسالة (أي عضو يمكنه فك التشفير)
decrypted_message = group_manager.decrypt_from_group(
    group_id, 
    "عضو_2", 
    encrypted_message
)
print(f"الرسالة الأصلية: {decrypted_message.decode('utf-8')}")

# إضافة عضو جديد
group_manager.add_member(group_id, "admin", "عضو_5")
print(f"\nتم إضافة عضو جديد")

# إزالة عضو
group_manager.remove_member(group_id, "admin", "عضو_1")
print(f"تم إزالة عضو")
```

## أفضل الممارسات

### 1. استخدام التوقيعات العتبية

```python
# ✅ استخدم عتبات مناسبة
# للمعاملات المالية: 3 من 5 أو 4 من 7
# للعمليات الحرجة: 5 من 7 أو 7 من 10

# ❌ لا تستخدم عتبات ضعيفة
# threshold = 1  # خطير! عضو واحد فقط
```

### 2. حماية الأمكنة الآمنة

```python
# ✅ امسح الأسرار بعد الاستخدام
enclave.clear_secrets()

# ✅ تحقق من شهادة المكان الآمن
attestation = enclave.get_attestation()
verify_attestation(attestation)

# ❌ لا تترك الأسرار في الذاكرة
# secret = enclave.retrieve_secret("key")
# # استخدم السر ثم انساه!
```

### 3. استخدام المقارنات الآمنة

```python
# ✅ استخدم مقارنات وقت ثابت للأسرار
is_valid = SideChannelGuard.constant_time_compare(secret1, secret2)

# ❌ لا تستخدم == للأسرار
# if secret1 == secret2:  # عرضة لهجمات التوقيت!
```

---

**التالي**: [التشفير ما بعد الكم](05-post-quantum.md)
