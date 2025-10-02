"""
Group E2E Encryption API
واجهة برمجة التطبيقات لنظام تشفير المجموعات من طرف إلى طرف
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import base64
import json
from typing import Dict, Any

from .group_e2e_encryption import (
    GroupE2EEncryption, 
    GroupKeyDistribution, 
    GroupMessageHistory
)
from ..core_cryptography.encryption_framework import EncryptionFramework
from ..key_management.key_manager import KeyManager


class GroupE2EAPI:
    """
    واجهة برمجة التطبيقات لنظام تشفير المجموعات
    """
    
    def __init__(self):
        self.app = Flask(__name__)
        CORS(self.app)  # تمكين CORS للتطبيقات الخارجية
        
        # تهيئة المكونات
        self.key_manager = KeyManager()
        self.encryption_framework = EncryptionFramework()
        self.group_encryption = GroupE2EEncryption(self.key_manager, self.encryption_framework)
        self.key_distribution = GroupKeyDistribution(self.group_encryption)
        self.message_history = GroupMessageHistory()
        
        # تسجيل المسارات
        self._register_routes()
    
    def _register_routes(self):
        """تسجيل مسارات API"""
        
        @self.app.route('/api/health', methods=['GET'])
        def health_check():
            """فحص حالة الخدمة"""
            return jsonify({
                'status': 'healthy',
                'service': 'Group E2E Encryption API',
                'version': '1.0.0'
            })
        
        @self.app.route('/api/groups', methods=['POST'])
        def create_group():
            """إنشاء مجموعة جديدة"""
            try:
                data = request.get_json()
                
                # التحقق من البيانات المطلوبة
                required_fields = ['group_id', 'creator_id', 'creator_public_key']
                for field in required_fields:
                    if field not in data:
                        return jsonify({'error': f'حقل مطلوب مفقود: {field}'}), 400
                
                # إنشاء المجموعة
                result = self.group_encryption.create_group(
                    data['group_id'],
                    data['creator_id'],
                    data['creator_public_key']
                )
                
                return jsonify({
                    'success': True,
                    'data': result
                })
                
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/groups/<group_id>/members', methods=['POST'])
        def add_member(group_id):
            """إضافة عضو إلى المجموعة"""
            try:
                data = request.get_json()
                
                required_fields = ['new_member_id', 'new_member_public_key', 'inviter_id']
                for field in required_fields:
                    if field not in data:
                        return jsonify({'error': f'حقل مطلوب مفقود: {field}'}), 400
                
                result = self.group_encryption.add_member_to_group(
                    group_id,
                    data['new_member_id'],
                    data['new_member_public_key'],
                    data['inviter_id']
                )
                
                # توزيع مفتاح المجموعة للعضو الجديد
                key_distribution_result = self.key_distribution.distribute_group_key_to_new_member(
                    group_id,
                    data['new_member_id'],
                    data['inviter_id']
                )
                
                return jsonify({
                    'success': True,
                    'data': {
                        'member_addition': result,
                        'key_distribution': key_distribution_result
                    }
                })
                
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/groups/<group_id>/members/<member_id>', methods=['DELETE'])
        def remove_member(group_id, member_id):
            """إزالة عضو من المجموعة"""
            try:
                data = request.get_json()
                
                if 'remover_id' not in data:
                    return jsonify({'error': 'حقل مطلوب مفقود: remover_id'}), 400
                
                result = self.group_encryption.remove_member_from_group(
                    group_id,
                    member_id,
                    data['remover_id']
                )
                
                return jsonify({
                    'success': True,
                    'data': result
                })
                
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/groups/<group_id>/messages', methods=['POST'])
        def send_message(group_id):
            """إرسال رسالة مشفرة للمجموعة"""
            try:
                data = request.get_json()
                
                required_fields = ['sender_id', 'message']
                for field in required_fields:
                    if field not in data:
                        return jsonify({'error': f'حقل مطلوب مفقود: {field}'}), 400
                
                # تحويل الرسالة إلى bytes
                message_bytes = data['message'].encode('utf-8')
                
                # تشفير الرسالة
                encrypted_message = self.group_encryption.encrypt_group_message(
                    group_id,
                    data['sender_id'],
                    message_bytes
                )
                
                # حفظ الرسالة في التاريخ
                self.message_history.store_encrypted_message(group_id, encrypted_message)
                
                # تحويل البيانات الثنائية إلى base64 للإرسال
                response_data = self._encode_binary_data(encrypted_message)
                
                return jsonify({
                    'success': True,
                    'data': response_data
                })
                
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/groups/<group_id>/messages/<int:message_counter>', methods=['GET'])
        def decrypt_message(group_id, message_counter):
            """فك تشفير رسالة من المجموعة"""
            try:
                recipient_id = request.args.get('recipient_id')
                if not recipient_id:
                    return jsonify({'error': 'معرف المستقبل مطلوب'}), 400
                
                # البحث عن الرسالة في التاريخ
                messages = self.message_history.get_group_message_history(group_id)
                target_message = None
                
                for msg in messages:
                    if msg['message_counter'] == message_counter:
                        target_message = msg
                        break
                
                if not target_message:
                    return jsonify({'error': 'الرسالة غير موجودة'}), 404
                
                # فك تشفير الرسالة
                decrypted_message = self.group_encryption.decrypt_group_message(
                    target_message,
                    recipient_id
                )
                
                return jsonify({
                    'success': True,
                    'data': {
                        'message': decrypted_message.decode('utf-8'),
                        'sender_id': target_message['sender_id'],
                        'timestamp': target_message['timestamp']
                    }
                })
                
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/groups/<group_id>', methods=['GET'])
        def get_group_info(group_id):
            """الحصول على معلومات المجموعة"""
            try:
                result = self.group_encryption.get_group_info(group_id)
                
                return jsonify({
                    'success': True,
                    'data': result
                })
                
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/groups/<group_id>/messages', methods=['GET'])
        def get_message_history(group_id):
            """الحصول على تاريخ رسائل المجموعة"""
            try:
                limit = request.args.get('limit', 50, type=int)
                messages = self.message_history.get_group_message_history(group_id, limit)
                
                # تحويل البيانات الثنائية إلى base64
                encoded_messages = [self._encode_binary_data(msg) for msg in messages]
                
                return jsonify({
                    'success': True,
                    'data': {
                        'messages': encoded_messages,
                        'count': len(encoded_messages)
                    }
                })
                
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/groups/<group_id>/key-export/<member_id>', methods=['GET'])
        def export_group_key(group_id, member_id):
            """تصدير مفتاح المجموعة للعضو"""
            try:
                # الحصول على المفتاح العام للعضو من المجموعة
                group_info = self.group_encryption.get_group_info(group_id)
                if member_id not in group_info['members']:
                    return jsonify({'error': 'العضو ليس في المجموعة'}), 404
                
                member_public_key = self.group_encryption.groups[group_id]['members'][member_id]['public_key']
                
                encrypted_key_data = self.group_encryption.export_group_key_for_member(
                    group_id,
                    member_id,
                    member_public_key
                )
                
                # تحويل البيانات الثنائية إلى base64
                response_data = self._encode_binary_data(encrypted_key_data)
                
                return jsonify({
                    'success': True,
                    'data': response_data
                })
                
            except Exception as e:
                return jsonify({'error': str(e)}), 500
    
    def _encode_binary_data(self, data: Dict) -> Dict:
        """تحويل البيانات الثنائية إلى base64 للإرسال عبر JSON"""
        encoded_data = {}
        
        for key, value in data.items():
            if isinstance(value, bytes):
                encoded_data[key] = base64.b64encode(value).decode('utf-8')
            else:
                encoded_data[key] = value
        
        return encoded_data
    
    def _decode_binary_data(self, data: Dict) -> Dict:
        """تحويل البيانات من base64 إلى bytes"""
        decoded_data = {}
        
        for key, value in data.items():
            if isinstance(value, str) and key in ['iv', 'ciphertext', 'tag', 'encrypted_group_key']:
                try:
                    decoded_data[key] = base64.b64decode(value)
                except:
                    decoded_data[key] = value
            else:
                decoded_data[key] = value
        
        return decoded_data
    
    def run(self, host='0.0.0.0', port=5000, debug=False):
        """تشغيل خادم API"""
        self.app.run(host=host, port=port, debug=debug)


# مثال على الاستخدام
if __name__ == '__main__':
    api = GroupE2EAPI()
    print("تشغيل خادم Group E2E Encryption API...")
    print("الوصول إلى API عبر: http://localhost:5000")
    print("فحص الحالة: http://localhost:5000/api/health")
    api.run(debug=True)

