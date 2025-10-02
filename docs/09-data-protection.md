# دليل حماية البيانات والمعالجة الآمنة

## مقدمة

يوفر ZyraCrypt مجموعة شاملة من أدوات حماية البيانات التي تشمل الضغط، الإخفاء، المعالجة الآمنة للذاكرة، وإدارة أنواع البيانات المختلفة.

## وحدة الضغط (CompressionUnit)

### الوظائف الأساسية

```python
from data_protection.compression_unit import CompressionUnit

# إنشاء وحدة الضغط
compressor = CompressionUnit()

# البيانات الأصلية
data = b"بيانات كبيرة جداً تحتاج للضغط " * 100

print(f"حجم البيانات الأصلية: {len(data)} بايت")

# ضغط البيانات
compressed_data = compressor.compress(data)
print(f"حجم البيانات المضغوطة: {len(compressed_data)} بايت")
print(f"نسبة الضغط: {(1 - len(compressed_data)/len(data)) * 100:.1f}%")

# فك الضغط
decompressed_data = compressor.decompress(compressed_data)
print(f"البيانات متطابقة: {data == decompressed_data}")
```

### مستويات الضغط

```python
# ضغط سريع (مستوى 1)
fast_compressed = compressor.compress(data, level=1)

# ضغط متوازن (مستوى 6 - افتراضي)
balanced_compressed = compressor.compress(data, level=6)

# ضغط أقصى (مستوى 9)
max_compressed = compressor.compress(data, level=9)

print(f"ضغط سريع: {len(fast_compressed)} بايت")
print(f"ضغط متوازن: {len(balanced_compressed)} بايت")
print(f"ضغط أقصى: {len(max_compressed)} بايت")
```

## وحدة الإخفاء (DataObfuscationUnit)

### الإخفاء باستخدام XOR

```python
from data_protection.data_obfuscation_unit import DataObfuscationUnit

# إنشاء وحدة الإخفاء
obfuscator = DataObfuscationUnit()

# البيانات الأصلية
plaintext = b"معلومات حساسة تحتاج للإخفاء"

# مفتاح الإخفاء (يجب أن يكون عشوائي)
import os
obfuscation_key = os.urandom(32)

# إخفاء البيانات
obfuscated = obfuscator.obfuscate(plaintext, obfuscation_key)
print(f"البيانات المخفية: {obfuscated.hex()[:60]}...")

# إلغاء الإخفاء
revealed = obfuscator.deobfuscate(obfuscated, obfuscation_key)
print(f"البيانات الأصلية: {revealed.decode('utf-8')}")
```

### الجمع بين الإخفاء والتشفير

```python
from core_cryptography.encryption_framework import EncryptionFramework

framework = EncryptionFramework()
obfuscator = DataObfuscationUnit()

# البيانات الحساسة
sensitive_data = b"بيانات سرية للغاية"

# الطبقة الأولى: الإخفاء
obfuscation_key = os.urandom(32)
obfuscated_data = obfuscator.obfuscate(sensitive_data, obfuscation_key)

# الطبقة الثانية: التشفير
encryption_key = os.urandom(32)
algo, iv, ciphertext, tag = framework.encrypt(
    obfuscated_data, 
    encryption_key, 
    "AES-GCM"
)

print("تم تطبيق طبقتين من الحماية:")
print(f"  1. إخفاء XOR")
print(f"  2. تشفير AES-GCM")

# فك الحماية بالترتيب العكسي
decrypted = framework.decrypt(algo, encryption_key, iv, ciphertext, tag)
original = obfuscator.deobfuscate(decrypted, obfuscation_key)

print(f"البيانات الأصلية: {original.decode('utf-8')}")
```

## مدير حماية البيانات (DataProtectionManager)

### المعالجة الشاملة للبيانات

```python
from data_protection.data_protection_manager import DataProtectionManager

# إنشاء مدير حماية البيانات
protection_manager = DataProtectionManager()

# البيانات المعقدة
data = {
    'user_id': '12345',
    'name': 'أحمد محمد',
    'email': 'ahmad@example.com',
    'balance': 10000.50,
    'transactions': [
        {'id': 1, 'amount': 500},
        {'id': 2, 'amount': 1500}
    ]
}

# المفتاح
key = os.urandom(32)

# معالجة كاملة: تسلسل + ضغط + إخفاء + تشفير
protected_data = protection_manager.protect_data(data, key)

print(f"البيانات الأصلية: {len(str(data))} حرف")
print(f"البيانات المحمية: {len(protected_data)} بايت")

# فك الحماية
recovered_data = protection_manager.unprotect_data(protected_data, key)

print(f"البيانات المستردة: {recovered_data}")
print(f"البيانات متطابقة: {data == recovered_data}")
```

### خطوات المعالجة

```python
import json

# 1. التسلسل (Serialization)
serialized = json.dumps(data).encode('utf-8')
print(f"1. التسلسل: {len(serialized)} بايت")

# 2. الضغط
compressed = protection_manager.compression_unit.compress(serialized)
print(f"2. الضغط: {len(compressed)} بايت ({(1-len(compressed)/len(serialized))*100:.1f}% توفير)")

# 3. الإخفاء
obfuscation_key = os.urandom(32)
obfuscated = protection_manager.obfuscation_unit.obfuscate(compressed, obfuscation_key)
print(f"3. الإخفاء: {len(obfuscated)} بايت")

# 4. التشفير
from core_cryptography.encryption_framework import EncryptionFramework
framework = EncryptionFramework()
algo, iv, ciphertext, tag = framework.encrypt(obfuscated, key, "AES-GCM")
print(f"4. التشفير: {len(ciphertext)} بايت")
```

## مدير أنواع البيانات (DataTypeManager)

### اكتشاف وتحويل أنواع البيانات

```python
from data_protection.data_type_manager import DataTypeManager

type_manager = DataTypeManager()

# اكتشاف نوع البيانات
text_data = "نص عادي"
binary_data = b"\x00\x01\x02\x03"
json_data = '{"key": "value"}'
xml_data = '<root><item>data</item></root>'

print(f"نص: {type_manager.detect_data_type(text_data)}")
print(f"ثنائي: {type_manager.detect_data_type(binary_data)}")
print(f"JSON: {type_manager.detect_data_type(json_data)}")
print(f"XML: {type_manager.detect_data_type(xml_data)}")
```

### التسلسل وفك التسلسل

```python
# تسلسل أنواع مختلفة
data_types = {
    'string': 'مرحباً بالعالم',
    'bytes': b'\xDE\xAD\xBE\xEF',
    'dict': {'name': 'أحمد', 'age': 30},
    'list': [1, 2, 3, 4, 5],
    'xml': '<data><value>test</value></data>'
}

for name, data in data_types.items():
    # تسلسل
    serialized = type_manager.serialize(data)
    print(f"\n{name}:")
    print(f"  الأصلي: {data}")
    print(f"  مسلسل: {serialized[:50]}...")
    
    # فك التسلسل
    deserialized = type_manager.deserialize(serialized, type(data).__name__)
    print(f"  مستعاد: {deserialized}")
    print(f"  متطابق: {data == deserialized}")
```

## المعالجة الآمنة للذاكرة (SecureMemoryHandling)

### مسح البيانات الحساسة

```python
from data_protection.secure_memory_handling import SecureMemoryHandling

memory_handler = SecureMemoryHandling()

# بيانات حساسة في الذاكرة
password = bytearray(b"كلمة-مرور-سرية-جداً")
api_key = bytearray(b"sk_live_1234567890abcdef")
encryption_key = bytearray(os.urandom(32))

print("قبل المسح:")
print(f"  كلمة المرور: {password}")
print(f"  مفتاح API: {api_key}")
print(f"  مفتاح التشفير: {encryption_key.hex()[:40]}...")

# استخدام البيانات...
# ...

# مسح آمن من الذاكرة
memory_handler.zeroize_data(password)
memory_handler.zeroize_data(api_key)
memory_handler.zeroize_data(encryption_key)

print("\nبعد المسح:")
print(f"  كلمة المرور: {password}")
print(f"  مفتاح API: {api_key}")
print(f"  مفتاح التشفير: {encryption_key.hex()}")

# التحقق من المسح الكامل
assert all(b == 0 for b in password), "لم يتم مسح كلمة المرور بالكامل!"
assert all(b == 0 for b in api_key), "لم يتم مسح مفتاح API بالكامل!"
assert all(b == 0 for b in encryption_key), "لم يتم مسح مفتاح التشفير بالكامل!"

print("\n✓ تم مسح جميع البيانات الحساسة من الذاكرة")
```

### استخدام مدير السياق

```python
from data_protection.secure_memory_handling import SecureMemoryHandling

class SecureDataContext:
    def __init__(self, data):
        self.data = bytearray(data)
        self.handler = SecureMemoryHandling()
    
    def __enter__(self):
        return self.data
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.handler.zeroize_data(self.data)
        print("✓ تم مسح البيانات تلقائياً")

# الاستخدام
with SecureDataContext(b"معلومات سرية") as secure_data:
    print(f"داخل السياق: {secure_data}")
    # ... استخدم البيانات

print(f"خارج السياق: {secure_data}")  # تم المسح
```

## حالات الاستخدام العملية

### 1. حماية ملفات التكوين

```python
from data_protection.data_protection_manager import DataProtectionManager
import json

# ملف تكوين حساس
config = {
    'database': {
        'host': 'db.example.com',
        'port': 5432,
        'username': 'admin',
        'password': 'super_secret_password',
        'database': 'production_db'
    },
    'api_keys': {
        'stripe': 'sk_live_xxxxxxxxxxxxxxxx',
        'aws': 'AKIA...',
        'sendgrid': 'SG...'
    },
    'encryption': {
        'master_key': 'master_key_value',
        'salt': 'random_salt_value'
    }
}

# حماية التكوين
protection_manager = DataProtectionManager()
master_password = "كلمة-مرور-رئيسية-آمنة!"

from key_management.key_generator import KeyGenerator
key_gen = KeyGenerator()
key_material = key_gen.derive_key_from_password(master_password, "argon2")

# حفظ التكوين المحمي
protected_config = protection_manager.protect_data(config, key_material['key'])

with open('config.protected', 'wb') as f:
    f.write(protected_config)

print("✓ تم حفظ ملف التكوين المحمي")

# قراءة التكوين
with open('config.protected', 'rb') as f:
    protected_data = f.read()

recovered_config = protection_manager.unprotect_data(
    protected_data, 
    key_material['key']
)

print(f"✓ تم استرجاع التكوين: {recovered_config['database']['host']}")
```

### 2. معالجة آمنة لبيانات المستخدمين

```python
from data_protection.data_protection_manager import DataProtectionManager
from data_protection.secure_memory_handling import SecureMemoryHandling

class SecureUserDataProcessor:
    def __init__(self, encryption_key):
        self.protection_manager = DataProtectionManager()
        self.memory_handler = SecureMemoryHandling()
        self.encryption_key = bytearray(encryption_key)
    
    def process_sensitive_data(self, user_data):
        """معالجة بيانات المستخدم بشكل آمن"""
        try:
            # حماية البيانات
            protected = self.protection_manager.protect_data(
                user_data,
                bytes(self.encryption_key)
            )
            
            # حفظ في قاعدة البيانات
            self.save_to_database(protected)
            
            return True
        finally:
            # مسح البيانات الحساسة من الذاكرة
            if isinstance(user_data.get('password'), str):
                pwd_bytes = bytearray(user_data['password'].encode('utf-8'))
                self.memory_handler.zeroize_data(pwd_bytes)
    
    def save_to_database(self, data):
        # حفظ في قاعدة البيانات
        pass
    
    def __del__(self):
        # مسح مفتاح التشفير عند حذف الكائن
        self.memory_handler.zeroize_data(self.encryption_key)

# الاستخدام
key = os.urandom(32)
processor = SecureUserDataProcessor(key)

user_data = {
    'username': 'ahmad',
    'email': 'ahmad@example.com',
    'password': 'user_password_123',
    'credit_card': '1234-5678-9012-3456'
}

processor.process_sensitive_data(user_data)
print("✓ تم معالجة بيانات المستخدم بأمان")
```

### 3. نظام تخزين آمن متعدد الطبقات

```python
from data_protection.data_protection_manager import DataProtectionManager
from data_protection.compression_unit import CompressionUnit
from data_protection.data_obfuscation_unit import DataObfuscationUnit
from core_cryptography.encryption_framework import EncryptionFramework
import os

class MultiLayerSecureStorage:
    def __init__(self):
        self.compressor = CompressionUnit()
        self.obfuscator = DataObfuscationUnit()
        self.framework = EncryptionFramework()
    
    def store(self, data, encryption_key, obfuscation_key):
        """تخزين بيانات مع حماية متعددة الطبقات"""
        # الطبقة 1: ضغط
        compressed = self.compressor.compress(data)
        print(f"✓ الضغط: {len(data)} → {len(compressed)} بايت")
        
        # الطبقة 2: إخفاء
        obfuscated = self.obfuscator.obfuscate(compressed, obfuscation_key)
        print(f"✓ الإخفاء: تطبيق XOR")
        
        # الطبقة 3: تشفير
        algo, iv, ciphertext, tag = self.framework.encrypt(
            obfuscated,
            encryption_key,
            "AES-GCM"
        )
        print(f"✓ التشفير: {algo}")
        
        return {
            'algorithm': algo,
            'iv': iv,
            'ciphertext': ciphertext,
            'tag': tag
        }
    
    def retrieve(self, protected_data, encryption_key, obfuscation_key):
        """استرجاع البيانات المحمية"""
        # فك الطبقة 3: التشفير
        obfuscated = self.framework.decrypt(
            protected_data['algorithm'],
            encryption_key,
            protected_data['iv'],
            protected_data['ciphertext'],
            protected_data['tag']
        )
        print(f"✓ فك التشفير")
        
        # فك الطبقة 2: الإخفاء
        compressed = self.obfuscator.deobfuscate(obfuscated, obfuscation_key)
        print(f"✓ فك الإخفاء")
        
        # فك الطبقة 1: الضغط
        data = self.compressor.decompress(compressed)
        print(f"✓ فك الضغط: {len(data)} بايت")
        
        return data

# الاستخدام
storage = MultiLayerSecureStorage()

# بيانات كبيرة
large_data = b"بيانات مهمة جداً تحتاج لحماية قصوى " * 1000

# مفاتيح
encryption_key = os.urandom(32)
obfuscation_key = os.urandom(32)

print("تخزين البيانات:")
protected = storage.store(large_data, encryption_key, obfuscation_key)

print("\nاسترجاع البيانات:")
retrieved = storage.retrieve(protected, encryption_key, obfuscation_key)

print(f"\nالنتيجة: البيانات متطابقة = {large_data == retrieved}")
```

## أفضل الممارسات

### ✅ افعل هذا

```python
# 1. استخدم الضغط قبل التشفير
data = b"بيانات كبيرة..."
compressed = compressor.compress(data)
encrypted = encrypt(compressed)  # أصغر حجماً

# 2. امسح البيانات الحساسة من الذاكرة
sensitive = bytearray(b"سري")
# ... استخدام
memory_handler.zeroize_data(sensitive)

# 3. استخدم طبقات حماية متعددة للبيانات الحساسة جداً
protected = protection_manager.protect_data(critical_data, key)
```

### ❌ لا تفعل هذا

```python
# ❌ لا تضغط بيانات عشوائية (لن تنضغط)
random_data = os.urandom(1024)
compressed = compressor.compress(random_data)  # نفس الحجم!

# ❌ لا تترك بيانات حساسة في الذاكرة
password = "كلمة-مرور"  # سيبقى في الذاكرة!

# ❌ لا تستخدم نفس مفتاح الإخفاء لكل البيانات
obfuscation_key = b"same_key"  # خطير!
```

## الخلاصة

وحدات حماية البيانات في ZyraCrypt توفر:
- **الضغط**: تقليل حجم البيانات قبل التشفير
- **الإخفاء**: طبقة إضافية من الحماية
- **إدارة الأنواع**: معالجة سلسة لأنواع البيانات المختلفة
- **الأمان في الذاكرة**: مسح آمن للبيانات الحساسة

استخدم هذه الأدوات معاً لبناء نظام حماية بيانات قوي ومتعدد الطبقات.

---

**التالي**: [الأمان المتخصص](10-specialized-security.md)
