# أمثلة عملية شاملة

## مقدمة

هذا الدليل يحتوي على أمثلة عملية كاملة لاستخدام ZyraCrypt في سيناريوهات واقعية.

## المثال 1: نظام مصادقة آمن

نظام تسجيل دخول آمن مع تشفير كلمات المرور وإدارة الجلسات.

```python
from key_management.enhanced_kdf_password import (
    EnhancedKDF, PasswordValidator, SecurePasswordStore,
    KDFAlgorithm, SecurityProfile
)
from specialized_security.secure_session_manager import SecureSessionManager
import secrets

class SecureAuthSystem:
    def __init__(self):
        self.password_store = SecurePasswordStore()
        self.password_validator = PasswordValidator()
        self.session_manager = SecureSessionManager()
        self.users_db = {}  # في الواقع: قاعدة بيانات
    
    def register_user(self, username: str, password: str) -> dict:
        """تسجيل مستخدم جديد"""
        
        # التحقق من قوة كلمة المرور
        validation = self.password_validator.validate_password(password)
        
        if not validation['valid']:
            return {
                'success': False,
                'errors': validation['errors']
            }
        
        # تجزئة كلمة المرور
        password_hash = self.password_store.hash_password(password)
        
        # حفظ المستخدم
        self.users_db[username] = {
            'username': username,
            'password_hash': password_hash,
            'created_at': '2024-01-01'
        }
        
        return {
            'success': True,
            'message': f'تم تسجيل المستخدم: {username}'
        }
    
    def login(self, username: str, password: str) -> dict:
        """تسجيل الدخول"""
        
        # التحقق من وجود المستخدم
        if username not in self.users_db:
            return {
                'success': False,
                'message': 'اسم المستخدم أو كلمة المرور خاطئة'
            }
        
        user = self.users_db[username]
        
        # التحقق من كلمة المرور
        is_valid = self.password_store.verify_password(
            password, 
            user['password_hash']
        )
        
        if not is_valid:
            return {
                'success': False,
                'message': 'اسم المستخدم أو كلمة المرور خاطئة'
            }
        
        # إنشاء جلسة
        session_token = self.session_manager.create_session(
            user_data={'username': username}
        )
        
        return {
            'success': True,
            'session_token': session_token,
            'message': f'مرحباً {username}!'
        }
    
    def verify_session(self, session_token: str) -> dict:
        """التحقق من الجلسة"""
        
        session_data = self.session_manager.get_session(session_token)
        
        if session_data:
            return {
                'valid': True,
                'username': session_data['username']
            }
        
        return {'valid': False}

# الاستخدام
auth_system = SecureAuthSystem()

# تسجيل مستخدم
register_result = auth_system.register_user(
    "أحمد",
    "كلمة-مرور-قوية-جداً-123!@#"
)
print(f"التسجيل: {register_result}")

# تسجيل الدخول
login_result = auth_system.login("أحمد", "كلمة-مرور-قوية-جداً-123!@#")
print(f"تسجيل الدخول: {login_result}")

# التحقق من الجلسة
if login_result['success']:
    session_check = auth_system.verify_session(login_result['session_token'])
    print(f"الجلسة: {session_check}")
```

## المثال 2: تشفير الملفات الآمن

نظام كامل لتشفير وفك تشفير الملفات مع إدارة المفاتيح.

```python
from specialized_security.file_encryption_manager import FileEncryptionManager
from key_management.key_manager import KeyManager
from core_cryptography.encryption_framework import EncryptionFramework
import os
import json

class SecureFileSystem:
    def __init__(self, master_password: str):
        self.key_manager = KeyManager()
        self.framework = EncryptionFramework()
        
        # اشتقاق مفتاح رئيسي من كلمة المرور
        key_data = self.key_manager.key_generator.derive_key_from_password(
            password=master_password,
            algorithm="argon2"
        )
        
        self.master_key = key_data['key']
        self.salt = key_data['salt']
    
    def encrypt_file(self, input_path: str, output_path: str) -> dict:
        """تشفير ملف"""
        
        # قراءة الملف
        with open(input_path, 'rb') as f:
            plaintext = f.read()
        
        # تشفير المحتوى
        algo, iv, ciphertext, tag = self.framework.encrypt(
            plaintext,
            self.master_key,
            "AES-GCM"
        )
        
        # حفظ البيانات المشفرة مع الميتاداتا
        encrypted_data = {
            'version': '1.0',
            'algorithm': algo,
            'iv': iv.hex(),
            'tag': tag.hex(),
            'original_filename': os.path.basename(input_path),
            'original_size': len(plaintext)
        }
        
        # كتابة ملف مشفر
        with open(output_path, 'w') as f:
            json.dump(encrypted_data, f)
        
        # كتابة البيانات المشفرة بشكل منفصل
        with open(output_path + '.enc', 'wb') as f:
            f.write(ciphertext)
        
        return {
            'success': True,
            'input': input_path,
            'output': output_path,
            'size': len(ciphertext)
        }
    
    def decrypt_file(self, encrypted_path: str, output_path: str) -> dict:
        """فك تشفير ملف"""
        
        # قراءة الميتاداتا
        with open(encrypted_path, 'r') as f:
            metadata = json.load(f)
        
        # قراءة البيانات المشفرة
        with open(encrypted_path + '.enc', 'rb') as f:
            ciphertext = f.read()
        
        # فك التشفير
        plaintext = self.framework.decrypt(
            metadata['algorithm'],
            self.master_key,
            bytes.fromhex(metadata['iv']),
            ciphertext,
            bytes.fromhex(metadata['tag'])
        )
        
        # كتابة الملف الأصلي
        with open(output_path, 'wb') as f:
            f.write(plaintext)
        
        return {
            'success': True,
            'original_filename': metadata['original_filename'],
            'original_size': metadata['original_size'],
            'output': output_path
        }

# الاستخدام
file_system = SecureFileSystem("كلمة-مرور-رئيسية-قوية!")

# إنشاء ملف تجريبي
with open('document.txt', 'w', encoding='utf-8') as f:
    f.write('محتوى سري للغاية\nيجب حمايته بالتشفير\n')

# تشفير الملف
encrypt_result = file_system.encrypt_file('document.txt', 'document.encrypted')
print(f"التشفير: {encrypt_result}")

# فك التشفير
decrypt_result = file_system.decrypt_file('document.encrypted', 'document_decrypted.txt')
print(f"فك التشفير: {decrypt_result}")
```

## المثال 3: API آمن للبيانات الحساسة

تطبيق Flask API مع تشفير شامل للبيانات.

```python
from flask import Flask, request, jsonify
from flask_cors import CORS
from core_cryptography.encryption_framework import EncryptionFramework
from key_management.envelope_encryption_kms import (
    EnvelopeEncryptionManager, KeyStorageLevel
)
import json
import base64

app = Flask(__name__)
CORS(app)

# إعداد التشفير
encryption_manager = EnvelopeEncryptionManager()
framework = EncryptionFramework()

# قاعدة بيانات وهمية
secure_storage = {}

@app.route('/api/store', methods=['POST'])
def store_sensitive_data():
    """تخزين بيانات حساسة مشفرة"""
    
    try:
        # الحصول على البيانات
        data = request.json
        user_id = data.get('user_id')
        sensitive_data = data.get('data')
        
        if not user_id or not sensitive_data:
            return jsonify({'error': 'البيانات مطلوبة'}), 400
        
        # توليد مفتاح تشفير للمستخدم
        key_id, wrapped_key = encryption_manager.generate_data_encryption_key(
            purpose=f"user_{user_id}_data",
            algorithm="AES-256-GCM",
            security_level=KeyStorageLevel.HIGH_SECURITY
        )
        
        # تشفير البيانات
        data_bytes = sensitive_data.encode('utf-8')
        encrypted = encryption_manager.encrypt_with_wrapped_key(
            wrapped_key, 
            data_bytes
        )
        
        # حفظ البيانات المشفرة
        secure_storage[user_id] = {
            'key_id': key_id,
            'encrypted_data': base64.b64encode(encrypted).decode('utf-8'),
            'wrapped_key': wrapped_key
        }
        
        return jsonify({
            'success': True,
            'message': 'تم تخزين البيانات بأمان',
            'key_id': key_id
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/retrieve/<user_id>', methods=['GET'])
def retrieve_sensitive_data(user_id):
    """استرجاع وفك تشفير البيانات"""
    
    try:
        # التحقق من وجود البيانات
        if user_id not in secure_storage:
            return jsonify({'error': 'المستخدم غير موجود'}), 404
        
        stored = secure_storage[user_id]
        
        # فك تشفير البيانات
        encrypted_data = base64.b64decode(stored['encrypted_data'])
        decrypted = encryption_manager.decrypt_with_wrapped_key(
            stored['wrapped_key'],
            encrypted_data
        )
        
        return jsonify({
            'success': True,
            'user_id': user_id,
            'data': decrypted.decode('utf-8')
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/rotate_key/<user_id>', methods=['POST'])
def rotate_user_key(user_id):
    """تدوير مفتاح التشفير للمستخدم"""
    
    try:
        if user_id not in secure_storage:
            return jsonify({'error': 'المستخدم غير موجود'}), 404
        
        stored = secure_storage[user_id]
        old_wrapped_key = stored['wrapped_key']
        
        # فك تشفير البيانات بالمفتاح القديم
        encrypted_data = base64.b64decode(stored['encrypted_data'])
        plaintext = encryption_manager.decrypt_with_wrapped_key(
            old_wrapped_key,
            encrypted_data
        )
        
        # تدوير المفتاح
        new_key_id, new_wrapped_key = encryption_manager.rotate_key(old_wrapped_key)
        
        # إعادة تشفير بالمفتاح الجديد
        new_encrypted = encryption_manager.encrypt_with_wrapped_key(
            new_wrapped_key,
            plaintext
        )
        
        # تحديث التخزين
        secure_storage[user_id] = {
            'key_id': new_key_id,
            'encrypted_data': base64.b64encode(new_encrypted).decode('utf-8'),
            'wrapped_key': new_wrapped_key
        }
        
        return jsonify({
            'success': True,
            'message': 'تم تدوير المفتاح بنجاح',
            'old_key_id': stored['key_id'],
            'new_key_id': new_key_id
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# تشغيل التطبيق
if __name__ == '__main__':
    app.run(debug=True, port=5000)
```

## المثال 4: نظام توقيع متعدد للمعاملات المالية

نظام يتطلب عدة موافقات للمعاملات الكبيرة.

```python
from advanced_features.threshold_multisig_enhanced import (
    MultisigManager, ThresholdScheme
)
import json
from datetime import datetime

class FinancialTransactionSystem:
    def __init__(self):
        self.multisig_manager = MultisigManager()
        self.transactions = {}
        self.pending_signatures = {}
    
    def setup_multisig(self, transaction_id: str, signers: list, threshold: int):
        """إعداد نظام التوقيع المتعدد للمعاملة"""
        
        keypair = self.multisig_manager.create_multisig_setup(
            participants=signers,
            threshold=threshold,
            scheme=ThresholdScheme.THRESHOLD_ECDSA
        )
        
        self.transactions[transaction_id] = {
            'keypair': keypair,
            'signers': signers,
            'threshold': threshold,
            'signatures_collected': 0,
            'status': 'pending'
        }
        
        return keypair.key_id
    
    def create_transaction(
        self, 
        transaction_id: str,
        from_account: str,
        to_account: str,
        amount: float,
        signers: list
    ) -> dict:
        """إنشاء معاملة مالية جديدة"""
        
        # تحديد العتبة حسب المبلغ
        if amount > 100000:
            threshold = 4  # معاملات كبيرة: 4 توقيعات
        elif amount > 50000:
            threshold = 3  # معاملات متوسطة: 3 توقيعات
        else:
            threshold = 2  # معاملات صغيرة: 2 توقيعات
        
        # إعداد التوقيع المتعدد
        key_id = self.setup_multisig(transaction_id, signers, threshold)
        
        # بيانات المعاملة
        transaction_data = {
            'id': transaction_id,
            'from': from_account,
            'to': to_account,
            'amount': amount,
            'currency': 'SAR',
            'timestamp': datetime.now().isoformat(),
            'status': 'pending_signatures',
            'key_id': key_id
        }
        
        self.pending_signatures[transaction_id] = {
            'data': transaction_data,
            'signatures': [],
            'signed_by': []
        }
        
        return {
            'success': True,
            'transaction_id': transaction_id,
            'required_signatures': threshold,
            'signers': signers
        }
    
    def sign_transaction(self, transaction_id: str, signer: str) -> dict:
        """توقيع معاملة من قبل موقّع"""
        
        if transaction_id not in self.pending_signatures:
            return {'success': False, 'error': 'المعاملة غير موجودة'}
        
        pending = self.pending_signatures[transaction_id]
        transaction = self.transactions[transaction_id]
        
        # التحقق من أن الموقّع مصرح له
        if signer not in transaction['signers']:
            return {'success': False, 'error': 'غير مصرح بالتوقيع'}
        
        # التحقق من عدم التوقيع مسبقاً
        if signer in pending['signed_by']:
            return {'success': False, 'error': 'تم التوقيع مسبقاً'}
        
        # تسجيل التوقيع
        pending['signed_by'].append(signer)
        transaction['signatures_collected'] += 1
        
        # التحقق من اكتمال التوقيعات
        if transaction['signatures_collected'] >= transaction['threshold']:
            transaction['status'] = 'approved'
            pending['data']['status'] = 'approved'
            
            return {
                'success': True,
                'message': 'المعاملة تمت الموافقة عليها',
                'transaction_id': transaction_id,
                'status': 'approved'
            }
        
        return {
            'success': True,
            'message': f'تم التوقيع ({transaction["signatures_collected"]}/{transaction["threshold"]})',
            'transaction_id': transaction_id,
            'status': 'pending_signatures'
        }
    
    def get_transaction_status(self, transaction_id: str) -> dict:
        """الحصول على حالة المعاملة"""
        
        if transaction_id not in self.transactions:
            return {'error': 'المعاملة غير موجودة'}
        
        transaction = self.transactions[transaction_id]
        pending = self.pending_signatures.get(transaction_id, {})
        
        return {
            'transaction_id': transaction_id,
            'status': transaction['status'],
            'signatures': f"{transaction['signatures_collected']}/{transaction['threshold']}",
            'signed_by': pending.get('signed_by', []),
            'pending_signers': [
                s for s in transaction['signers'] 
                if s not in pending.get('signed_by', [])
            ]
        }

# الاستخدام
financial_system = FinancialTransactionSystem()

# إنشاء معاملة كبيرة
signers = ["المدير_المالي", "المدير_التنفيذي", "المحاسب", "المراجع", "المدير_العام"]

transaction = financial_system.create_transaction(
    transaction_id="TXN-2024-001",
    from_account="ACC-12345",
    to_account="ACC-67890",
    amount=150000.00,
    signers=signers
)

print(f"معاملة جديدة: {transaction}")

# التوقيعات
for signer in signers[:4]:  # 4 توقيعات
    result = financial_system.sign_transaction("TXN-2024-001", signer)
    print(f"توقيع {signer}: {result['message']}")

# حالة المعاملة
status = financial_system.get_transaction_status("TXN-2024-001")
print(f"\nحالة المعاملة: {json.dumps(status, ensure_ascii=False, indent=2)}")
```

## المثال 5: نظام رسائل مشفرة من نهاية إلى نهاية

تطبيق مراسلة آمن مع تشفير كامل.

```python
from advanced_features.group_e2e_encryption import GroupE2EManager
from core_cryptography.encryption_framework import EncryptionFramework
from key_management.key_manager import KeyManager
import json

class SecureMessagingApp:
    def __init__(self):
        self.group_manager = GroupE2EManager()
        self.users = {}
        self.messages = []
    
    def register_user(self, username: str):
        """تسجيل مستخدم جديد"""
        self.users[username] = {
            'username': username,
            'groups': []
        }
        return {'success': True, 'username': username}
    
    def create_chat_group(
        self, 
        group_id: str, 
        admin: str, 
        members: list
    ) -> dict:
        """إنشاء مجموعة دردشة مشفرة"""
        
        group_info = self.group_manager.create_group(
            group_id=group_id,
            admin=admin,
            members=members
        )
        
        # تحديث مجموعات الأعضاء
        for member in members:
            if member in self.users:
                self.users[member]['groups'].append(group_id)
        
        return {
            'success': True,
            'group_id': group_id,
            'members': members,
            'admin': admin
        }
    
    def send_message(
        self, 
        group_id: str, 
        sender: str, 
        message: str
    ) -> dict:
        """إرسال رسالة مشفرة للمجموعة"""
        
        # تشفير الرسالة
        message_bytes = message.encode('utf-8')
        encrypted_message = self.group_manager.encrypt_for_group(
            group_id, 
            message_bytes
        )
        
        # حفظ الرسالة
        message_data = {
            'group_id': group_id,
            'sender': sender,
            'encrypted': encrypted_message,
            'timestamp': encrypted_message.get('timestamp', '')
        }
        
        self.messages.append(message_data)
        
        return {
            'success': True,
            'message_id': len(self.messages) - 1,
            'group_id': group_id
        }
    
    def receive_messages(self, group_id: str, recipient: str) -> list:
        """استقبال وفك تشفير الرسائل"""
        
        decrypted_messages = []
        
        for msg in self.messages:
            if msg['group_id'] == group_id:
                try:
                    # فك التشفير
                    plaintext = self.group_manager.decrypt_from_group(
                        group_id,
                        recipient,
                        msg['encrypted']
                    )
                    
                    decrypted_messages.append({
                        'sender': msg['sender'],
                        'message': plaintext.decode('utf-8'),
                        'timestamp': msg['timestamp']
                    })
                except Exception as e:
                    print(f"خطأ في فك التشفير: {e}")
        
        return decrypted_messages

# الاستخدام
messaging_app = SecureMessagingApp()

# تسجيل المستخدمين
users = ["علي", "محمد", "فاطمة", "أحمد"]
for user in users:
    messaging_app.register_user(user)

# إنشاء مجموعة
group_result = messaging_app.create_chat_group(
    group_id="family_chat",
    admin="علي",
    members=users
)
print(f"مجموعة جديدة: {group_result}")

# إرسال رسائل
messaging_app.send_message("family_chat", "علي", "مرحباً بالجميع!")
messaging_app.send_message("family_chat", "محمد", "أهلاً علي، كيف حالك؟")
messaging_app.send_message("family_chat", "فاطمة", "السلام عليكم")

# استقبال الرسائل
messages = messaging_app.receive_messages("family_chat", "أحمد")
print("\nالرسائل المستلمة:")
for msg in messages:
    print(f"  {msg['sender']}: {msg['message']}")
```

## الخلاصة

هذه الأمثلة توضح كيفية استخدام ZyraCrypt في سيناريوهات واقعية:

1. **نظام المصادقة**: تشفير كلمات المرور وإدارة الجلسات
2. **تشفير الملفات**: حماية الملفات الحساسة
3. **API آمن**: تطبيق ويب مع تشفير شامل
4. **التوقيع المتعدد**: معاملات مالية بموافقات متعددة
5. **الرسائل المشفرة**: تطبيق محادثة آمن من نهاية إلى نهاية

---

**التالي**: [مرجع API الكامل](07-api-reference.md)
