"""
Group End-to-End Encryption Module
يوفر تشفير من طرف إلى طرف للمحادثات الجماعية مشابه لما يستخدمه تيليجرام وواتساب
"""

import os
import json
import time
from typing import Dict, List, Tuple, Optional
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from encryption_system.src.core_cryptography.encryption_framework import EncryptionFramework
from encryption_system.src.key_management.key_manager import KeyManager


class GroupE2EEncryption:
    """
    نظام تشفير المجموعات من طرف إلى طرف
    يستخدم مفاتيح مشتركة للمجموعة مع إدارة آمنة للأعضاء
    """
    
    def __init__(self, key_manager: KeyManager, encryption_framework: EncryptionFramework):
        self.key_manager = key_manager
        self.encryption_framework = encryption_framework
        self.groups: Dict[str, Dict] = {}  # معلومات المجموعات
        self.member_keys: Dict[str, Dict] = {}  # مفاتيح الأعضاء
        
    def create_group(self, group_id: str, creator_id: str, creator_public_key) -> Dict:
        """
        إنشاء مجموعة جديدة مع تشفير من طرف إلى طرف
        """
        # إنشاء مفتاح المجموعة الرئيسي
        group_master_key = os.urandom(32)  # 256-bit key
        
        # إنشاء معرف فريد للمجموعة
        group_info = {
            'group_id': group_id,
            'creator_id': creator_id,
            'created_at': time.time(),
            'members': {creator_id: {'joined_at': time.time(), 'public_key': creator_public_key}},
            'group_master_key': group_master_key,
            'key_version': 1,
            'message_counter': 0
        }
        
        self.groups[group_id] = group_info
        
        return {
            'group_id': group_id,
            'status': 'created',
            'member_count': 1,
            'key_version': 1
        }
    
    def add_member_to_group(self, group_id: str, new_member_id: str, new_member_public_key, inviter_id: str) -> Dict:
        """
        إضافة عضو جديد إلى المجموعة
        """
        if group_id not in self.groups:
            raise ValueError(f"المجموعة {group_id} غير موجودة")
        
        group = self.groups[group_id]
        
        # التحقق من أن المدعو موجود في المجموعة
        if inviter_id not in group['members']:
            raise ValueError("المدعو ليس عضواً في المجموعة")
        
        # إضافة العضو الجديد
        group['members'][new_member_id] = {
            'joined_at': time.time(),
            'public_key': new_member_public_key,
            'invited_by': inviter_id
        }
        
        # تحديث إصدار المفتاح (اختياري - للأمان الإضافي)
        # في التطبيقات الحقيقية، قد نرغب في تجديد مفتاح المجموعة عند إضافة أعضاء جدد
        
        return {
            'group_id': group_id,
            'new_member_id': new_member_id,
            'status': 'added',
            'member_count': len(group['members'])
        }
    
    def remove_member_from_group(self, group_id: str, member_id: str, remover_id: str) -> Dict:
        """
        إزالة عضو من المجموعة وتجديد مفتاح المجموعة للأمان
        """
        if group_id not in self.groups:
            raise ValueError(f"المجموعة {group_id} غير موجودة")
        
        group = self.groups[group_id]
        
        # التحقق من الصلاحيات
        if remover_id not in group['members']:
            raise ValueError("المُزيل ليس عضواً في المجموعة")
        
        if member_id not in group['members']:
            raise ValueError("العضو المراد إزالته ليس في المجموعة")
        
        # إزالة العضو
        del group['members'][member_id]
        
        # تجديد مفتاح المجموعة للأمان (Forward Secrecy)
        group['group_master_key'] = os.urandom(32)
        group['key_version'] += 1
        
        return {
            'group_id': group_id,
            'removed_member_id': member_id,
            'status': 'removed',
            'member_count': len(group['members']),
            'new_key_version': group['key_version']
        }
    
    def encrypt_group_message(self, group_id: str, sender_id: str, message: bytes) -> Dict:
        """
        تشفير رسالة للمجموعة
        """
        if group_id not in self.groups:
            raise ValueError(f"المجموعة {group_id} غير موجودة")
        
        group = self.groups[group_id]
        
        if sender_id not in group['members']:
            raise ValueError("المرسل ليس عضواً في المجموعة")
        
        # استخدام مفتاح المجموعة الرئيسي
        group_key = group['group_master_key']
        
        # إنشاء مفتاح فريد للرسالة باستخدام HKDF
        message_counter = group['message_counter']
        group['message_counter'] += 1
        
        # اشتقاق مفتاح الرسالة
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=f"group_{group_id}_msg_{message_counter}".encode(),
            backend=default_backend()
        )
        message_key = hkdf.derive(group_key)
        
        # تشفير الرسالة باستخدام AES-GCM
        iv, ciphertext, tag = self.encryption_framework.symmetric_enc.encrypt_aes_gcm(message_key, message)
        
        encrypted_message = {
            'group_id': group_id,
            'sender_id': sender_id,
            'message_counter': message_counter,
            'key_version': group['key_version'],
            'iv': iv,
            'ciphertext': ciphertext,
            'tag': tag,
            'timestamp': time.time()
        }
        
        return encrypted_message
    
    def decrypt_group_message(self, encrypted_message: Dict, recipient_id: str) -> bytes:
        """
        فك تشفير رسالة المجموعة
        """
        group_id = encrypted_message['group_id']
        
        if group_id not in self.groups:
            raise ValueError(f"المجموعة {group_id} غير موجودة")
        
        group = self.groups[group_id]
        
        if recipient_id not in group['members']:
            raise ValueError("المستقبل ليس عضواً في المجموعة")
        
        # التحقق من إصدار المفتاح
        if encrypted_message['key_version'] != group['key_version']:
            raise ValueError("إصدار مفتاح الرسالة لا يتطابق مع إصدار مفتاح المجموعة الحالي")
        
        # استخدام مفتاح المجموعة الرئيسي
        group_key = group['group_master_key']
        
        # اشتقاق مفتاح الرسالة
        message_counter = encrypted_message['message_counter']
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=f"group_{group_id}_msg_{message_counter}".encode(),
            backend=default_backend()
        )
        message_key = hkdf.derive(group_key)
        
        # فك تشفير الرسالة
        plaintext = self.encryption_framework.symmetric_enc.decrypt_aes_gcm(
            message_key,
            encrypted_message['iv'],
            encrypted_message['ciphertext'],
            encrypted_message['tag']
        )
        
        return plaintext
    
    def get_group_info(self, group_id: str) -> Dict:
        """
        الحصول على معلومات المجموعة
        """
        if group_id not in self.groups:
            raise ValueError(f"المجموعة {group_id} غير موجودة")
        
        group = self.groups[group_id]
        
        return {
            'group_id': group_id,
            'creator_id': group['creator_id'],
            'created_at': group['created_at'],
            'member_count': len(group['members']),
            'members': list(group['members'].keys()),
            'key_version': group['key_version'],
            'message_counter': group['message_counter']
        }
    
    def export_group_key_for_member(self, group_id: str, member_id: str, member_public_key) -> bytes:
        """
        تصدير مفتاح المجموعة مشفراً للعضو الجديد
        """
        if group_id not in self.groups:
            raise ValueError(f"المجموعة {group_id} غير موجودة")
        
        group = self.groups[group_id]
        
        if member_id not in group['members']:
            raise ValueError("العضو ليس في المجموعة")
        
        # تشفير مفتاح المجموعة باستخدام المفتاح العام للعضو
        group_key_data = {
            'group_master_key': group['group_master_key'].hex(),
            'key_version': group['key_version'],
            'group_id': group_id
        }
        
        # في التطبيق الحقيقي، سنستخدم تشفير غير متماثل لتشفير هذه البيانات
        # هنا نستخدم تشفير متماثل مؤقت للتوضيح
        group_key_json = json.dumps(group_key_data).encode()
        
        # إنشاء مفتاح مؤقت للتشفير
        temp_key = os.urandom(32)
        iv, ciphertext, tag = self.encryption_framework.symmetric_enc.encrypt_aes_gcm(temp_key, group_key_json)
        
        return {
            'encrypted_group_key': ciphertext,
            'iv': iv,
            'tag': tag,
            'temp_key': temp_key  # في التطبيق الحقيقي، سيتم تشفير هذا بالمفتاح العام للعضو
        }


class GroupKeyDistribution:
    """
    نظام توزيع المفاتيح للمجموعات
    يدير توزيع مفاتيح المجموعة بشكل آمن للأعضاء الجدد
    """
    
    def __init__(self, group_encryption: GroupE2EEncryption):
        self.group_encryption = group_encryption
    
    def distribute_group_key_to_new_member(self, group_id: str, new_member_id: str, distributor_id: str) -> Dict:
        """
        توزيع مفتاح المجموعة للعضو الجديد
        """
        # الحصول على معلومات المجموعة
        group_info = self.group_encryption.get_group_info(group_id)
        
        # التحقق من أن الموزع عضو في المجموعة
        if distributor_id not in group_info['members']:
            raise ValueError("الموزع ليس عضواً في المجموعة")
        
        # التحقق من أن العضو الجديد في المجموعة
        if new_member_id not in group_info['members']:
            raise ValueError("العضو الجديد ليس في المجموعة")
        
        # تصدير مفتاح المجموعة للعضو الجديد
        member_public_key = self.group_encryption.groups[group_id]['members'][new_member_id]['public_key']
        encrypted_key_data = self.group_encryption.export_group_key_for_member(
            group_id, new_member_id, member_public_key
        )
        
        return {
            'group_id': group_id,
            'new_member_id': new_member_id,
            'encrypted_key_data': encrypted_key_data,
            'status': 'key_distributed'
        }


class GroupMessageHistory:
    """
    إدارة تاريخ رسائل المجموعة مع الحفاظ على التشفير
    """
    
    def __init__(self):
        self.message_history: Dict[str, List[Dict]] = {}
    
    def store_encrypted_message(self, group_id: str, encrypted_message: Dict):
        """
        حفظ الرسالة المشفرة في التاريخ
        """
        if group_id not in self.message_history:
            self.message_history[group_id] = []
        
        self.message_history[group_id].append(encrypted_message)
    
    def get_group_message_history(self, group_id: str, limit: int = 50) -> List[Dict]:
        """
        الحصول على تاريخ رسائل المجموعة
        """
        if group_id not in self.message_history:
            return []
        
        # إرجاع آخر الرسائل
        return self.message_history[group_id][-limit:]
    
    def clear_group_history(self, group_id: str):
        """
        مسح تاريخ رسائل المجموعة
        """
        if group_id in self.message_history:
            del self.message_history[group_id]

