# دليل الأمان المتخصص

## مقدمة

يوفر ZyraCrypt مجموعة من الأدوات الأمنية المتخصصة للحالات الخاصة مثل تشفير الملفات، الإخفاء التشفيري، الحذف الآمن، وإدارة الجلسات الآمنة.

## تشفير الملفات (FileEncryptionManager)

### التشفير الأساسي للملفات

```python
from specialized_security.file_encryption_manager import FileEncryptionManager
from core_cryptography.encryption_framework import EncryptionFramework
import os

# إعداد مدير تشفير الملفات
framework = EncryptionFramework()
file_manager = FileEncryptionManager(framework)

# مفتاح التشفير
encryption_key = os.urandom(32)

# إنشاء ملف تجريبي
with open('document.txt', 'w', encoding='utf-8') as f:
    f.write('وثيقة سرية جداً\n')
    f.write('تحتوي على معلومات حساسة\n')
    f.write('يجب تشفيرها بالكامل\n')

# تشفير الملف
file_manager.encrypt_file(
    input_filepath='document.txt',
    output_filepath='document.txt.encrypted',
    key=encryption_key
)

print("✓ تم تشفير الملف")

# فك التشفير
file_manager.decrypt_file(
    input_filepath='document.txt.encrypted',
    output_filepath='document_decrypted.txt',
    key=encryption_key
)

print("✓ تم فك تشفير الملف")
```

### تشفير الملفات مع بيانات إضافية

```python
# بيانات إضافية (ميتاداتا)
metadata = b"user_id:12345|timestamp:2024-01-01|department:finance"

# تشفير مع البيانات الإضافية
file_manager.encrypt_file(
    input_filepath='sensitive_report.pdf',
    output_filepath='sensitive_report.pdf.enc',
    key=encryption_key,
    associated_data=metadata
)

# فك التشفير (يجب تقديم نفس البيانات الإضافية)
file_manager.decrypt_file(
    input_filepath='sensitive_report.pdf.enc',
    output_filepath='sensitive_report_decrypted.pdf',
    key=encryption_key,
    associated_data=metadata
)
```

### نظام تشفير ملفات متقدم

```python
import hashlib
import json
from datetime import datetime

class AdvancedFileEncryption:
    def __init__(self, file_manager, encryption_key):
        self.file_manager = file_manager
        self.encryption_key = encryption_key
    
    def encrypt_with_metadata(self, input_file, output_file):
        """تشفير ملف مع حفظ الميتاداتا"""
        # حساب hash للملف الأصلي
        with open(input_file, 'rb') as f:
            original_hash = hashlib.sha256(f.read()).hexdigest()
        
        # معلومات الملف
        file_info = {
            'original_name': input_file,
            'encrypted_at': datetime.now().isoformat(),
            'original_hash': original_hash,
            'original_size': os.path.getsize(input_file)
        }
        
        # تشفير الملف
        self.file_manager.encrypt_file(
            input_filepath=input_file,
            output_filepath=output_file,
            key=self.encryption_key,
            associated_data=json.dumps(file_info).encode('utf-8')
        )
        
        # حفظ الميتاداتا
        with open(output_file + '.meta', 'w') as f:
            json.dump(file_info, f, indent=2, ensure_ascii=False)
        
        return file_info
    
    def decrypt_with_verification(self, encrypted_file, output_file):
        """فك تشفير مع التحقق من السلامة"""
        # قراءة الميتاداتا
        with open(encrypted_file + '.meta', 'r') as f:
            file_info = json.load(f)
        
        # فك التشفير
        self.file_manager.decrypt_file(
            input_filepath=encrypted_file,
            output_filepath=output_file,
            key=self.encryption_key,
            associated_data=json.dumps(file_info).encode('utf-8')
        )
        
        # التحقق من hash
        with open(output_file, 'rb') as f:
            decrypted_hash = hashlib.sha256(f.read()).hexdigest()
        
        if decrypted_hash != file_info['original_hash']:
            raise ValueError("فشل التحقق من سلامة الملف!")
        
        print(f"✓ تم التحقق من سلامة الملف")
        print(f"  الاسم الأصلي: {file_info['original_name']}")
        print(f"  وقت التشفير: {file_info['encrypted_at']}")
        print(f"  الحجم الأصلي: {file_info['original_size']} بايت")
        
        return file_info

# الاستخدام
framework = EncryptionFramework()
file_manager = FileEncryptionManager(framework)
key = os.urandom(32)

advanced = AdvancedFileEncryption(file_manager, key)

# تشفير
info = advanced.encrypt_with_metadata('important.pdf', 'important.pdf.enc')

# فك التشفير والتحقق
advanced.decrypt_with_verification('important.pdf.enc', 'important_restored.pdf')
```

## الإخفاء التشفيري - Steganography

### إخفاء البيانات في الصور

```python
from specialized_security.steganography_unit import SteganographyUnit

# إنشاء وحدة الإخفاء التشفيري
stego = SteganographyUnit()

# البيانات السرية للإخفاء
secret_message = b"رسالة سرية مخفية في الصورة"

# إخفاء البيانات في صورة
stego.embed_data(
    image_path='cover_image.png',
    data=secret_message,
    output_path='stego_image.png'
)

print("✓ تم إخفاء البيانات في الصورة")

# استخراج البيانات المخفية
extracted_data = stego.extract_data('stego_image.png')

print(f"البيانات المستخرجة: {extracted_data.decode('utf-8')}")
print(f"البيانات متطابقة: {secret_message == extracted_data}")
```

### إخفاء بيانات مشفرة

```python
from core_cryptography.encryption_framework import EncryptionFramework

framework = EncryptionFramework()
stego = SteganographyUnit()

# البيانات الحساسة
sensitive_data = b"معلومات سرية للغاية - تقرير مالي"

# الخطوة 1: تشفير البيانات
encryption_key = os.urandom(32)
algo, iv, ciphertext, tag = framework.encrypt(
    sensitive_data,
    encryption_key,
    "AES-GCM"
)

# دمج البيانات المشفرة
encrypted_package = iv + tag + ciphertext

print(f"حجم البيانات المشفرة: {len(encrypted_package)} بايت")

# الخطوة 2: إخفاء في صورة
stego.embed_data(
    image_path='normal_photo.jpg',
    data=encrypted_package,
    output_path='secret_photo.jpg'
)

print("✓ تم إخفاء البيانات المشفرة في الصورة")

# استخراج وفك التشفير
extracted_package = stego.extract_data('secret_photo.jpg')

# فصل المكونات
iv_size = 12  # حجم IV لـ AES-GCM
tag_size = 16  # حجم Tag

extracted_iv = extracted_package[:iv_size]
extracted_tag = extracted_package[iv_size:iv_size + tag_size]
extracted_ciphertext = extracted_package[iv_size + tag_size:]

# فك التشفير
decrypted = framework.decrypt(
    algo,
    encryption_key,
    extracted_iv,
    extracted_ciphertext,
    extracted_tag
)

print(f"البيانات الأصلية: {decrypted.decode('utf-8')}")
```

### حساب السعة التخزينية

```python
from PIL import Image

def calculate_steganography_capacity(image_path):
    """حساب السعة القصوى للإخفاء في صورة"""
    img = Image.open(image_path)
    width, height = img.size
    
    # كل بكسل له 3 قنوات (RGB)، كل قناة تخزن 1 بت
    bits_capacity = width * height * 3
    bytes_capacity = bits_capacity // 8
    
    # طرح حجم الفاصل
    delimiter_size = len(b"#####END#####")
    usable_capacity = bytes_capacity - delimiter_size
    
    print(f"معلومات الصورة:")
    print(f"  الأبعاد: {width} × {height}")
    print(f"  السعة الكلية: {bytes_capacity:,} بايت")
    print(f"  السعة القابلة للاستخدام: {usable_capacity:,} بايت")
    print(f"  السعة القابلة للاستخدام: {usable_capacity / 1024:.2f} كيلوبايت")
    
    return usable_capacity

# الاستخدام
capacity = calculate_steganography_capacity('large_image.png')

# التحقق من إمكانية الإخفاء
secret_data = b"بيانات كبيرة جداً..."
if len(secret_data) > capacity:
    print(f"⚠️ البيانات أكبر من السعة المتاحة!")
else:
    print(f"✓ يمكن إخفاء البيانات ({len(secret_data)} بايت)")
```

## الحذف الآمن (SecureDeletionUnit)

### الحذف بمعيار DoD 5220.22-M

```python
from specialized_security.secure_deletion_unit import SecureDeletionUnit

# إنشاء وحدة الحذف الآمن
secure_delete = SecureDeletionUnit()

# إنشاء ملف حساس
with open('sensitive_data.txt', 'w') as f:
    f.write('بيانات حساسة جداً يجب حذفها بأمان\n')
    f.write('معلومات سرية لا يجب استرجاعها\n')

print(f"حجم الملف: {os.path.getsize('sensitive_data.txt')} بايت")

# حذف آمن (3 مرات كتابة)
secure_delete.dod_5220_22_m_erase('sensitive_data.txt')

print("✓ تم حذف الملف بأمان (DoD 5220.22-M)")
print("  المرحلة 1: كتابة 0x00")
print("  المرحلة 2: كتابة 0xFF")
print("  المرحلة 3: كتابة عشوائية")
```

### حذف آمن متقدم

```python
import os

class AdvancedSecureDeletion:
    def __init__(self):
        self.deletion_unit = SecureDeletionUnit()
    
    def secure_delete_with_log(self, filepath):
        """حذف آمن مع سجل"""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"الملف غير موجود: {filepath}")
        
        # معلومات الملف قبل الحذف
        file_info = {
            'path': filepath,
            'size': os.path.getsize(filepath),
            'deleted_at': datetime.now().isoformat()
        }
        
        print(f"حذف آمن للملف:")
        print(f"  المسار: {filepath}")
        print(f"  الحجم: {file_info['size']:,} بايت")
        
        # الحذف الآمن
        self.deletion_unit.dod_5220_22_m_erase(filepath)
        
        # حفظ سجل الحذف
        log_file = 'secure_deletion.log'
        with open(log_file, 'a') as f:
            f.write(json.dumps(file_info, ensure_ascii=False) + '\n')
        
        print(f"✓ تم الحذف والتسجيل")
        
        return file_info
    
    def batch_secure_delete(self, filepaths):
        """حذف آمن لعدة ملفات"""
        results = []
        
        for filepath in filepaths:
            try:
                info = self.secure_delete_with_log(filepath)
                results.append({'success': True, 'file': filepath, 'info': info})
            except Exception as e:
                results.append({'success': False, 'file': filepath, 'error': str(e)})
        
        # تقرير
        successful = sum(1 for r in results if r['success'])
        print(f"\nتقرير الحذف الآمن:")
        print(f"  الملفات المحذوفة: {successful}/{len(filepaths)}")
        
        return results

# الاستخدام
deleter = AdvancedSecureDeletion()

# حذف ملف واحد
deleter.secure_delete_with_log('secret_document.pdf')

# حذف عدة ملفات
files_to_delete = [
    'old_password.txt',
    'api_keys.json',
    'private_key.pem'
]

deleter.batch_secure_delete(files_to_delete)
```

## إدارة الجلسات الآمنة (SecureSessionManager)

### إدارة الجلسات الأساسية

```python
from specialized_security.secure_session_manager import SecureSessionManager

# إنشاء مدير الجلسات
session_manager = SecureSessionManager()

# إنشاء جلسة جديدة
session_token = session_manager.create_session()
print(f"رمز الجلسة: {session_token[:20]}...")

# تخزين بيانات في الجلسة
session_manager.set_session_data(session_token, {
    'user_id': '12345',
    'username': 'أحمد',
    'role': 'admin',
    'login_time': datetime.now().isoformat()
})

# استرجاع بيانات الجلسة
session_data = session_manager.get_session_data(session_token)
print(f"بيانات الجلسة: {session_data}")

# حذف الجلسة
session_manager.destroy_session(session_token)
print("✓ تم حذف الجلسة")
```

### نظام جلسات متقدم

```python
import secrets
from datetime import datetime, timedelta

class AdvancedSessionManager:
    def __init__(self):
        self.sessions = {}
        self.session_timeout = 3600  # ساعة واحدة
    
    def create_session(self, user_id, user_data=None):
        """إنشاء جلسة مع بيانات المستخدم"""
        session_id = secrets.token_urlsafe(32)
        
        self.sessions[session_id] = {
            'user_id': user_id,
            'created_at': datetime.now(),
            'last_activity': datetime.now(),
            'data': user_data or {},
            'ip_address': None,  # في التطبيق الحقيقي: من الطلب
            'user_agent': None
        }
        
        return session_id
    
    def validate_session(self, session_id):
        """التحقق من صلاحية الجلسة"""
        if session_id not in self.sessions:
            return False, "الجلسة غير موجودة"
        
        session = self.sessions[session_id]
        now = datetime.now()
        
        # التحقق من انتهاء الصلاحية
        time_diff = (now - session['last_activity']).total_seconds()
        
        if time_diff > self.session_timeout:
            self.destroy_session(session_id)
            return False, "انتهت صلاحية الجلسة"
        
        # تحديث وقت آخر نشاط
        session['last_activity'] = now
        
        return True, "الجلسة صالحة"
    
    def get_session(self, session_id):
        """الحصول على بيانات الجلسة"""
        is_valid, message = self.validate_session(session_id)
        
        if not is_valid:
            raise ValueError(message)
        
        return self.sessions[session_id]
    
    def destroy_session(self, session_id):
        """حذف جلسة"""
        if session_id in self.sessions:
            del self.sessions[session_id]
    
    def cleanup_expired_sessions(self):
        """تنظيف الجلسات المنتهية"""
        now = datetime.now()
        expired = []
        
        for session_id, session in self.sessions.items():
            time_diff = (now - session['last_activity']).total_seconds()
            if time_diff > self.session_timeout:
                expired.append(session_id)
        
        for session_id in expired:
            self.destroy_session(session_id)
        
        print(f"✓ تم حذف {len(expired)} جلسة منتهية")

# الاستخدام
session_mgr = AdvancedSessionManager()

# إنشاء جلسة
session_id = session_mgr.create_session(
    user_id='user_123',
    user_data={'name': 'أحمد', 'role': 'admin'}
)

print(f"جلسة جديدة: {session_id[:20]}...")

# التحقق من الجلسة
is_valid, message = session_mgr.validate_session(session_id)
print(f"حالة الجلسة: {message}")

# الحصول على بيانات الجلسة
session = session_mgr.get_session(session_id)
print(f"المستخدم: {session['data']['name']}")
print(f"وقت الإنشاء: {session['created_at']}")

# تنظيف الجلسات المنتهية
session_mgr.cleanup_expired_sessions()
```

## حالات استخدام متقدمة

### نظام مراسلة سرية مع إخفاء تشفيري

```python
from specialized_security.steganography_unit import SteganographyUnit
from core_cryptography.encryption_framework import EncryptionFramework

class CovertMessaging:
    def __init__(self):
        self.stego = SteganographyUnit()
        self.framework = EncryptionFramework()
    
    def send_covert_message(self, message, cover_image, output_image, encryption_key):
        """إرسال رسالة سرية مخفية ومشفرة"""
        # 1. تشفير الرسالة
        algo, iv, ciphertext, tag = self.framework.encrypt(
            message.encode('utf-8'),
            encryption_key,
            "AES-GCM"
        )
        
        # 2. دمج البيانات المشفرة
        encrypted_data = iv + tag + ciphertext
        
        # 3. إخفاء في الصورة
        self.stego.embed_data(cover_image, encrypted_data, output_image)
        
        print(f"✓ تم إرسال رسالة سرية:")
        print(f"  الطول: {len(message)} حرف")
        print(f"  الصورة: {output_image}")
    
    def receive_covert_message(self, stego_image, encryption_key):
        """استقبال وفك رسالة سرية"""
        # 1. استخراج من الصورة
        encrypted_data = self.stego.extract_data(stego_image)
        
        # 2. فصل المكونات
        iv = encrypted_data[:12]
        tag = encrypted_data[12:28]
        ciphertext = encrypted_data[28:]
        
        # 3. فك التشفير
        decrypted = self.framework.decrypt(
            "AES-GCM",
            encryption_key,
            iv,
            ciphertext,
            tag
        )
        
        return decrypted.decode('utf-8')

# الاستخدام
covert = CovertMessaging()
key = os.urandom(32)

# إرسال
covert.send_covert_message(
    message="اجتماع سري في الساعة 3 مساءً",
    cover_image="vacation_photo.jpg",
    output_image="vacation_photo_with_message.jpg",
    encryption_key=key
)

# استقبال
received = covert.receive_covert_message(
    stego_image="vacation_photo_with_message.jpg",
    encryption_key=key
)

print(f"الرسالة المستلمة: {received}")
```

## أفضل الممارسات

### تشفير الملفات

```python
# ✅ احفظ الميتاداتا بشكل منفصل
# ✅ استخدم مفاتيح فريدة لكل ملف
# ✅ تحقق من hash بعد فك التشفير

# ❌ لا تخزن المفتاح مع الملف المشفر
# ❌ لا تعيد استخدام نفس المفتاح لجميع الملفات
```

### الإخفاء التشفيري

```python
# ✅ اختر صور غلاف ذات جودة عالية
# ✅ شفر البيانات قبل الإخفاء
# ✅ تأكد من السعة الكافية

# ❌ لا تستخدم صور صغيرة جداً
# ❌ لا تخفي بيانات حساسة بدون تشفير
# ❌ لا تعدل الصورة بعد الإخفاء
```

### الحذف الآمن

```python
# ✅ استخدم DoD 5220.22-M للبيانات الحساسة
# ✅ احتفظ بسجل للملفات المحذوفة
# ✅ تحقق من اكتمال الحذف

# ❌ لا تعتمد على حذف نظام التشغيل العادي
# ❌ لا تنسَ حذف النسخ الاحتياطية
```

---

**التالي**: [سلسلة الكتل والتشفير](11-blockchain-crypto.md)
