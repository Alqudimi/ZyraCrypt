# أفضل الممارسات الأمنية

## مقدمة

الأمان لا يتعلق فقط باستخدام التشفير القوي، بل يتطلب اتباع أفضل الممارسات في جميع جوانب النظام. هذا الدليل يوضح كيفية استخدام ZyraCrypt بأمان.

## إدارة المفاتيح

### ✅ افعل هذا

```python
import os
from key_management.key_generator import KeyGenerator

# 1. استخدم مفاتيح عشوائية آمنة
secure_key = os.urandom(32)  # 256 بت من /dev/urandom

# 2. اشتق المفاتيح من كلمات مرور قوية
key_gen = KeyGenerator()
derived = key_gen.derive_key_from_password(
    password="كلمة-مرور-قوية-جداً-123!@#",
    algorithm="argon2"  # الأفضل للأمان
)

# 3. احفظ الملح مع البيانات المشفرة
salt = derived['salt']  # احفظ هذا!

# 4. دوّر المفاتيح بانتظام
def rotate_keys_if_needed(key_age_days):
    if key_age_days > 90:  # كل 3 أشهر
        return generate_new_key()
```

### ❌ لا تفعل هذا

```python
# ❌ مفاتيح ضعيفة
weak_key = b"1234"  # قصير جداً!
weak_key = b"password" * 4  # متوقع!

# ❌ إعادة استخدام الملح
salt = b"same_salt_always"  # خطير!

# ❌ تخزين المفاتيح في الكود
API_KEY = "sk_live_abc123"  # ❌ خطير جداً!

# ❌ عدم تدوير المفاتيح
# استخدام نفس المفتاح لسنوات  # ❌ خطير!
```

## التشفير والبيانات

### قواعد ذهبية

#### 1. لا تعيد استخدام IV/Nonce أبداً

```python
from core_cryptography.encryption_framework import EncryptionFramework

framework = EncryptionFramework()
key = os.urandom(32)

# ✅ صحيح: IV جديد لكل عملية تشفير
for i in range(100):
    data = f"رسالة {i}".encode('utf-8')
    algo, iv, ciphertext, tag = framework.encrypt(data, key, "AES-GCM")
    # كل تشفير له IV فريد تلقائياً

# ❌ خطأ: إعادة استخدام IV
# iv = b"same_iv_for_all"
# for data in messages:
#     ciphertext = encrypt_with_same_iv(data, key, iv)  # ❌ خطير!
```

#### 2. استخدم AEAD للتشفير المصادق

```python
# ✅ استخدم AES-GCM أو ChaCha20-Poly1305
algo, iv, ciphertext, tag = framework.encrypt(
    plaintext, 
    key, 
    "AES-GCM"  # يتضمن مصادقة
)

# ✅ أضف بيانات إضافية محمية
algo, iv, ciphertext, tag = framework.encrypt(
    plaintext,
    key,
    "AES-GCM",
    associated_data=b"user_id:12345"  # محمية لكن غير مشفرة
)
```

#### 3. احم البيانات الحساسة في الذاكرة

```python
from advanced_features.side_channel_protection import SideChannelGuard

# ✅ امسح البيانات الحساسة بعد الاستخدام
password_bytes = bytearray(password.encode('utf-8'))

# ... استخدم كلمة المرور

# امسح من الذاكرة
SideChannelGuard.secure_zero_memory(password_bytes)

# التأكد من المسح
assert all(b == 0 for b in password_bytes)
```

## كلمات المرور

### متطلبات كلمات المرور الآمنة

```python
from key_management.enhanced_kdf_password import PasswordValidator

validator = PasswordValidator()

# ✅ كلمات مرور قوية
strong_passwords = [
    "MyV3ry$tr0ng-P@ssw0rd!2024",
    "كلمة-مرور-عربية-قوية-123!@#",
    "Correct-Horse-Battery-Staple-99!"
]

# الحد الأدنى الموصى به
MIN_LENGTH = 16  # على الأقل 16 حرف
MUST_HAVE = {
    'uppercase': True,
    'lowercase': True,
    'numbers': True,
    'symbols': True
}

def enforce_password_policy(password):
    result = validator.validate_password(password, min_length=MIN_LENGTH)
    
    if not result['valid']:
        raise ValueError(f"كلمة مرور ضعيفة: {', '.join(result['errors'])}")
    
    if result['score'] < 70:
        raise ValueError("كلمة المرور ليست قوية بما يكفي")
    
    return True
```

### تخزين كلمات المرور

```python
from key_management.enhanced_kdf_password import SecurePasswordStore

password_store = SecurePasswordStore()

# ✅ تخزين صحيح
def register_user(username, password):
    # التحقق من القوة
    enforce_password_policy(password)
    
    # تجزئة آمنة
    password_hash = password_store.hash_password(password)
    
    # حفظ الـ hash فقط
    save_to_database(username, password_hash)
    
    # ❌ لا تحفظ كلمة المرور الأصلية!
    # save_to_database(username, password)  # خطير!

# ✅ تسجيل دخول آمن
def login(username, password):
    stored_hash = get_from_database(username)
    
    # استخدم التحقق الآمن
    is_valid = password_store.verify_password(password, stored_hash)
    
    if is_valid:
        return create_session(username)
    else:
        # ❌ لا تكشف سبب الفشل
        return "اسم المستخدم أو كلمة المرور خاطئة"
        # بدلاً من: "كلمة المرور خاطئة" (يكشف أن المستخدم موجود)
```

## المقارنات الآمنة

### استخدم مقارنات وقت ثابت

```python
from advanced_features.side_channel_protection import SideChannelGuard

# ✅ صحيح: مقارنة وقت ثابت للأسرار
def verify_api_token(provided_token, stored_token):
    return SideChannelGuard.constant_time_compare(
        provided_token.encode('utf-8'),
        stored_token.encode('utf-8')
    )

# ❌ خطأ: مقارنة عادية للأسرار
def unsafe_verify(provided, stored):
    return provided == stored  # عرضة لهجمات التوقيت!
```

## التوقيعات الرقمية

### أفضل الممارسات

```python
from core_cryptography.asymmetric_encryption import AsymmetricEncryption

asymmetric = AsymmetricEncryption()

# ✅ استخدم ECDSA بدلاً من RSA للتوقيعات
private_key, public_key = asymmetric.generate_ecdsa_keypair(curve="P-256")

# وقّع البيانات الكاملة
message = b"عقد مهم: ..."
signature = asymmetric.sign_ecdsa(private_key, message)

# ✅ احفظ التوقيع مع البيانات
signed_document = {
    'data': message,
    'signature': signature.hex(),
    'timestamp': '2024-01-01T12:00:00Z',
    'signer': 'المدير المالي'
}

# ❌ لا توقّع فقط جزء من البيانات
# signature = sign(message[:100])  # خطير!
```

## التشفير الهجين والكمي

### استخدم الأمان الهجين دائماً

```python
from advanced_features.hybrid_pqc_enhanced import HybridPQCEngine

# ✅ صحيح: هجين = حماية مضاعفة
def secure_for_future(data):
    engine = HybridPQCEngine(security_level=192)
    public_keys, private_keys = engine.generate_hybrid_keypair()
    
    key_material = engine.hybrid_key_exchange(public_keys)
    return encrypt_with_key(data, key_material.combined_shared_secret)

# ❌ خطأ: كمي فقط (لا توجد حماية كلاسيكية)
# def only_pqc(data):
#     pqc = PostQuantumCryptographyUnit()
#     # فقط PQC بدون كلاسيكي - مخاطرة!
```

### خطط للمستقبل

```python
# ✅ اختر مستوى الأمان حسب عمر البيانات
def choose_security_level(data_lifetime_years):
    if data_lifetime_years > 30:
        return 256  # أرشيف طويل جداً
    elif data_lifetime_years > 10:
        return 192  # بيانات طويلة الأمد
    else:
        return 128  # بيانات قصيرة/متوسطة الأمد

security_level = choose_security_level(50)  # أرشيف 50 سنة
engine = HybridPQCEngine(security_level=security_level)
```

## الأخطاء الشائعة

### 1. تسريب المعلومات في الأخطاء

```python
# ❌ خطأ: رسائل خطأ مفصلة
def bad_login(username, password):
    if username not in users:
        return "اسم المستخدم غير موجود"  # ❌ يكشف معلومات!
    
    if not verify_password(password):
        return "كلمة المرور خاطئة"  # ❌ يكشف معلومات!

# ✅ صحيح: رسالة واحدة
def good_login(username, password):
    if not authenticate(username, password):
        return "اسم المستخدم أو كلمة المرور خاطئة"  # ✅ عام
```

### 2. عدم التحقق من التوقيعات

```python
# ❌ خطأ: قبول البيانات بدون تحقق
def bad_process(data, signature):
    # process_data(data)  # ❌ لم نتحقق من التوقيع!
    pass

# ✅ صحيح: تحقق دائماً
def good_process(data, signature, public_key):
    # تحقق أولاً
    is_valid = verify_signature(public_key, data, signature)
    
    if not is_valid:
        raise ValueError("توقيع غير صحيح!")
    
    # ثم عالج البيانات
    process_data(data)
```

### 3. تخزين البيانات الحساسة بدون تشفير

```python
import json

# ❌ خطأ: حفظ بيانات حساسة بدون تشفير
def bad_save(user_data):
    with open('users.json', 'w') as f:
        json.dump(user_data, f)  # ❌ نص عادي!

# ✅ صحيح: تشفير قبل الحفظ
from core_cryptography.encryption_framework import EncryptionFramework

def good_save(user_data, encryption_key):
    framework = EncryptionFramework()
    
    # تشفير
    data_bytes = json.dumps(user_data).encode('utf-8')
    algo, iv, ciphertext, tag = framework.encrypt(
        data_bytes, 
        encryption_key, 
        "AES-GCM"
    )
    
    # حفظ المشفر
    encrypted = {
        'algo': algo,
        'iv': iv.hex(),
        'ciphertext': ciphertext.hex(),
        'tag': tag.hex()
    }
    
    with open('users.enc', 'w') as f:
        json.dump(encrypted, f)
```

## قائمة مراجعة الأمان

عند نشر تطبيق يستخدم ZyraCrypt، تأكد من:

### المفاتيح والأسرار

- [ ] جميع المفاتيح مولدة بشكل عشوائي آمن
- [ ] كلمات المرور تُشتق باستخدام Argon2
- [ ] المفاتيح مخزنة بشكل آمن (مشفرة)
- [ ] يوجد نظام لتدوير المفاتيح
- [ ] النسخ الاحتياطية للمفاتيح محمية

### التشفير

- [ ] استخدام AES-GCM أو ChaCha20-Poly1305
- [ ] IV/Nonce فريد لكل عملية تشفير
- [ ] البيانات المشفرة تتضمن علامة مصادقة
- [ ] التشفير الهجين للبيانات طويلة الأمد

### المصادقة والتفويض

- [ ] كلمات المرور مجزأة (ليست مشفرة)
- [ ] استخدام مقارنات وقت ثابت
- [ ] رسائل خطأ عامة
- [ ] حماية ضد هجمات التوقيت

### معالجة الأخطاء

- [ ] عدم كشف معلومات حساسة في الأخطاء
- [ ] تسجيل الأخطاء بشكل آمن
- [ ] رسائل خطأ للمستخدم عامة

### الذاكرة والتخزين

- [ ] مسح البيانات الحساسة من الذاكرة
- [ ] تشفير البيانات على القرص
- [ ] حذف آمن للبيانات الحساسة

### الشبكة والاتصالات

- [ ] استخدام HTTPS/TLS دائماً
- [ ] التحقق من الشهادات
- [ ] حماية API tokens
- [ ] معدل محدود للطلبات

### المراقبة والتدقيق

- [ ] تسجيل العمليات الحساسة
- [ ] مراقبة المحاولات الفاشلة
- [ ] تنبيهات للأنشطة المشبوهة
- [ ] مراجعة دورية للسجلات

## موارد إضافية

### المراجع الأمنية

- OWASP Top 10
- NIST Cryptographic Standards
- CWE Top 25

### أدوات مفيدة

```python
# التحقق من قوة المفاتيح
def check_key_strength(key):
    if len(key) < 32:
        print("⚠️ تحذير: المفتاح أقل من 256 بت")
    
    # تحقق من العشوائية
    import collections
    freq = collections.Counter(key)
    if max(freq.values()) > len(key) / 10:
        print("⚠️ تحذير: المفتاح قد لا يكون عشوائياً بما يكفي")

# مراقبة عمر المفاتيح
from datetime import datetime, timedelta

def should_rotate_key(key_created_date):
    age = datetime.now() - key_created_date
    
    if age > timedelta(days=90):
        print("🔑 حان وقت تدوير المفتاح!")
        return True
    
    return False
```

## الخلاصة

الأمان رحلة وليس وجهة. اتبع هذه الممارسات، وراجع نظامك بانتظام، وابق على اطلاع بأحدث التهديدات والحلول.

### القواعد الذهبية الخمس

1. **لا تثق، تحقق دائماً**: تحقق من جميع المدخلات والتوقيعات
2. **افترض الأسوأ**: خطط للاختراق وأضف طبقات حماية
3. **الأقل امتيازاً**: أعط فقط الصلاحيات المطلوبة
4. **الدفاع العميق**: طبقات متعددة من الحماية
5. **التحديث المستمر**: ابق المكتبات محدثة دائماً

---

**تم بواسطة Alqudimi Systems**
**ZyraCrypt v2.0.0**
