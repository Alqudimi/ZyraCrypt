# دليل التشفير وسلسلة الكتل

## مقدمة

يوفر ZyraCrypt وظائف تشفيرية متخصصة لتطبيقات سلسلة الكتل (Blockchain) بما في ذلك حساب هاش الكتل، إثبات العمل، وتجزئة المعاملات.

## وظائف التشفير لسلسلة الكتل

### حساب هاش الكتلة (Block Hash)

```python
from advanced_features.blockchain_cryptography_functions import BlockchainCryptographyFunctions

# إنشاء كائن وظائف البلوك تشين
blockchain_crypto = BlockchainCryptographyFunctions()

# بيانات كتلة
index = 1
timestamp = 1704067200.0  # 2024-01-01 00:00:00
data = "معاملة: أحمد -> محمد: 100 ريال"
previous_hash = "0000000000000000000000000000000000000000000000000000000000000000"
nonce = 0

# حساب هاش الكتلة
block_hash = blockchain_crypto.calculate_block_hash(
    index=index,
    timestamp=timestamp,
    data=data,
    previous_hash=previous_hash,
    nonce=nonce
)

print(f"هاش الكتلة: {block_hash}")
print(f"الطول: {len(block_hash)} حرف")
```

### إثبات العمل (Proof of Work)

```python
# آخر إثبات عمل
last_proof = 100

# إيجاد إثبات العمل الجديد
print("البحث عن إثبات العمل...")
new_proof = blockchain_crypto.proof_of_work(last_proof)

print(f"✓ تم إيجاد إثبات العمل: {new_proof}")

# التحقق من صحة الإثبات
is_valid = blockchain_crypto.valid_proof(last_proof, new_proof)
print(f"الإثبات صحيح: {is_valid}")

# عرض الهاش الناتج
import hashlib
guess = f"{last_proof}{new_proof}".encode('utf-8')
guess_hash = hashlib.sha256(guess).hexdigest()
print(f"الهاش الناتج: {guess_hash}")
print(f"أول 4 أحرف: {guess_hash[:4]} (يجب أن تكون 0000)")
```

### تجزئة المعاملات

```python
# بيانات المعاملة
sender = "محفظة_أحمد"
recipient = "محفظة_محمد"
amount = 50.5

# إنشاء هاش المعاملة
transaction_hash = blockchain_crypto.create_transaction_hash(
    sender=sender,
    recipient=recipient,
    amount=amount
)

print(f"معاملة:")
print(f"  من: {sender}")
print(f"  إلى: {recipient}")
print(f"  المبلغ: {amount}")
print(f"  الهاش: {transaction_hash}")
```

## بناء سلسلة كتل بسيطة

### كتلة (Block)

```python
from dataclasses import dataclass
from typing import List
import time

@dataclass
class Block:
    index: int
    timestamp: float
    data: str
    previous_hash: str
    nonce: int
    hash: str

class SimpleBlockchain:
    def __init__(self):
        self.chain: List[Block] = []
        self.crypto = BlockchainCryptographyFunctions()
        # إنشاء الكتلة الأولى (Genesis Block)
        self.create_genesis_block()
    
    def create_genesis_block(self):
        """إنشاء الكتلة الأولى"""
        genesis_block = Block(
            index=0,
            timestamp=time.time(),
            data="كتلة التأسيس - Genesis Block",
            previous_hash="0" * 64,
            nonce=0,
            hash=""
        )
        genesis_block.hash = self.crypto.calculate_block_hash(
            genesis_block.index,
            genesis_block.timestamp,
            genesis_block.data,
            genesis_block.previous_hash,
            genesis_block.nonce
        )
        self.chain.append(genesis_block)
    
    def get_last_block(self):
        """الحصول على آخر كتلة"""
        return self.chain[-1]
    
    def mine_block(self, data: str):
        """تعدين كتلة جديدة"""
        previous_block = self.get_last_block()
        
        new_block = Block(
            index=previous_block.index + 1,
            timestamp=time.time(),
            data=data,
            previous_hash=previous_block.hash,
            nonce=0,
            hash=""
        )
        
        # إيجاد nonce الصحيح (Proof of Work)
        print(f"تعدين الكتلة {new_block.index}...")
        while True:
            block_hash = self.crypto.calculate_block_hash(
                new_block.index,
                new_block.timestamp,
                new_block.data,
                new_block.previous_hash,
                new_block.nonce
            )
            
            # التحقق من الصعوبة (4 أصفار في البداية)
            if block_hash[:4] == "0000":
                new_block.hash = block_hash
                break
            
            new_block.nonce += 1
        
        self.chain.append(new_block)
        print(f"✓ تم تعدين الكتلة {new_block.index}")
        print(f"  Nonce: {new_block.nonce}")
        print(f"  Hash: {new_block.hash[:20]}...")
        
        return new_block
    
    def is_chain_valid(self):
        """التحقق من صحة السلسلة"""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            
            # التحقق من الهاش
            calculated_hash = self.crypto.calculate_block_hash(
                current_block.index,
                current_block.timestamp,
                current_block.data,
                current_block.previous_hash,
                current_block.nonce
            )
            
            if current_block.hash != calculated_hash:
                print(f"❌ هاش الكتلة {i} غير صحيح")
                return False
            
            # التحقق من الارتباط
            if current_block.previous_hash != previous_block.hash:
                print(f"❌ الكتلة {i} غير مرتبطة بالكتلة السابقة")
                return False
            
            # التحقق من الصعوبة
            if not current_block.hash.startswith("0000"):
                print(f"❌ الكتلة {i} لا تحقق شرط الصعوبة")
                return False
        
        return True

# الاستخدام
blockchain = SimpleBlockchain()

# تعدين كتل جديدة
blockchain.mine_block("معاملة 1: أحمد -> محمد: 100 ريال")
blockchain.mine_block("معاملة 2: محمد -> فاطمة: 50 ريال")
blockchain.mine_block("معاملة 3: فاطمة -> علي: 25 ريال")

# عرض السلسلة
print("\nسلسلة الكتل:")
for block in blockchain.chain:
    print(f"\nالكتلة {block.index}:")
    print(f"  البيانات: {block.data}")
    print(f"  الوقت: {time.ctime(block.timestamp)}")
    print(f"  Nonce: {block.nonce}")
    print(f"  الهاش السابق: {block.previous_hash[:20]}...")
    print(f"  الهاش: {block.hash[:20]}...")

# التحقق من السلسلة
is_valid = blockchain.is_chain_valid()
print(f"\nالسلسلة صحيحة: {is_valid} ✓")
```

## نظام معاملات متقدم

### معاملة مع توقيع رقمي

```python
from core_cryptography.asymmetric_encryption import AsymmetricEncryption
import json

class SignedTransaction:
    def __init__(self):
        self.asymmetric = AsymmetricEncryption()
        self.blockchain_crypto = BlockchainCryptographyFunctions()
    
    def create_signed_transaction(self, sender_private_key, sender, recipient, amount):
        """إنشاء معاملة موقعة"""
        # بيانات المعاملة
        transaction_data = {
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
            'timestamp': time.time()
        }
        
        # تحويل لـ JSON
        transaction_json = json.dumps(transaction_data, sort_keys=True)
        transaction_bytes = transaction_json.encode('utf-8')
        
        # التوقيع
        signature = self.asymmetric.sign_ecdsa(
            sender_private_key,
            transaction_bytes
        )
        
        # المعاملة الكاملة
        signed_transaction = {
            'transaction': transaction_data,
            'signature': signature.hex()
        }
        
        # حساب الهاش
        tx_hash = self.blockchain_crypto.create_transaction_hash(
            sender,
            recipient,
            amount
        )
        
        signed_transaction['hash'] = tx_hash
        
        return signed_transaction
    
    def verify_transaction(self, signed_transaction, sender_public_key):
        """التحقق من المعاملة"""
        # استخراج البيانات
        transaction_data = signed_transaction['transaction']
        signature = bytes.fromhex(signed_transaction['signature'])
        
        # إعادة بناء البيانات
        transaction_json = json.dumps(transaction_data, sort_keys=True)
        transaction_bytes = transaction_json.encode('utf-8')
        
        # التحقق من التوقيع
        is_valid = self.asymmetric.verify_ecdsa(
            sender_public_key,
            transaction_bytes,
            signature
        )
        
        return is_valid

# الاستخدام
tx_system = SignedTransaction()

# توليد مفاتيح للمرسل
asymmetric = AsymmetricEncryption()
sender_private, sender_public = asymmetric.generate_ecdsa_keypair(curve="P-256")

# إنشاء معاملة موقعة
signed_tx = tx_system.create_signed_transaction(
    sender_private_key=sender_private,
    sender="محفظة_أحمد",
    recipient="محفظة_محمد",
    amount=100.0
)

print("معاملة موقعة:")
print(f"  من: {signed_tx['transaction']['sender']}")
print(f"  إلى: {signed_tx['transaction']['recipient']}")
print(f"  المبلغ: {signed_tx['transaction']['amount']}")
print(f"  الهاش: {signed_tx['hash']}")
print(f"  التوقيع: {signed_tx['signature'][:40]}...")

# التحقق
is_valid = tx_system.verify_transaction(signed_tx, sender_public)
print(f"\nالتوقيع صحيح: {is_valid} ✓")
```

## سلسلة كتل بمعاملات موقعة

```python
class AdvancedBlockchain(SimpleBlockchain):
    def __init__(self):
        super().__init__()
        self.pending_transactions = []
        self.tx_system = SignedTransaction()
    
    def add_transaction(self, signed_transaction, sender_public_key):
        """إضافة معاملة للقائمة المعلقة"""
        # التحقق من التوقيع
        is_valid = self.tx_system.verify_transaction(
            signed_transaction,
            sender_public_key
        )
        
        if not is_valid:
            raise ValueError("توقيع المعاملة غير صحيح!")
        
        self.pending_transactions.append(signed_transaction)
        print(f"✓ تم إضافة معاملة: {signed_transaction['hash'][:16]}...")
    
    def mine_pending_transactions(self, miner_address):
        """تعدين المعاملات المعلقة"""
        if not self.pending_transactions:
            print("لا توجد معاملات للتعدين")
            return None
        
        # تجميع المعاملات
        block_data = {
            'transactions': self.pending_transactions,
            'miner': miner_address
        }
        
        # تحويل لنص
        block_data_str = json.dumps(block_data, ensure_ascii=False)
        
        # تعدين الكتلة
        new_block = self.mine_block(block_data_str)
        
        # مسح المعاملات المعلقة
        self.pending_transactions = []
        
        return new_block

# الاستخدام
adv_blockchain = AdvancedBlockchain()

# إنشاء محافظ
asymmetric = AsymmetricEncryption()

# محفظة أحمد
ahmad_private, ahmad_public = asymmetric.generate_ecdsa_keypair()

# محفظة محمد  
mohamed_private, mohamed_public = asymmetric.generate_ecdsa_keypair()

# إنشاء معاملات
tx1 = tx_system.create_signed_transaction(
    ahmad_private,
    "محفظة_أحمد",
    "محفظة_محمد",
    50.0
)

tx2 = tx_system.create_signed_transaction(
    mohamed_private,
    "محفظة_محمد",
    "محفظة_فاطمة",
    25.0
)

# إضافة المعاملات
adv_blockchain.add_transaction(tx1, ahmad_public)
adv_blockchain.add_transaction(tx2, mohamed_public)

# تعدين
mined_block = adv_blockchain.mine_pending_transactions("محفظة_المُعَدِّن")

# عرض الكتلة المُعَدَّنة
print(f"\nالكتلة المُعَدَّنة {mined_block.index}:")
print(f"  عدد المعاملات: {len(adv_blockchain.chain[-1].data)}")
print(f"  الهاش: {mined_block.hash[:40]}...")

# التحقق من السلسلة
is_valid = adv_blockchain.is_chain_valid()
print(f"\nالسلسلة صحيحة: {is_valid} ✓")
```

## التشفير متعدد التوقيع للمعاملات

### معاملة تتطلب عدة توقيعات

```python
from advanced_features.threshold_multisig_enhanced import MultisigManager, ThresholdScheme

class MultisigTransaction:
    def __init__(self):
        self.multisig_manager = MultisigManager()
        self.blockchain_crypto = BlockchainCryptographyFunctions()
    
    def create_multisig_wallet(self, participants, threshold):
        """إنشاء محفظة متعددة التوقيع"""
        keypair = self.multisig_manager.create_multisig_setup(
            participants=participants,
            threshold=threshold,
            scheme=ThresholdScheme.THRESHOLD_ECDSA
        )
        
        return keypair
    
    def create_multisig_transaction(self, wallet_id, recipient, amount):
        """إنشاء معاملة تحتاج عدة توقيعات"""
        transaction = {
            'wallet_id': wallet_id,
            'recipient': recipient,
            'amount': amount,
            'timestamp': time.time(),
            'status': 'pending_signatures',
            'signatures': []
        }
        
        # حساب الهاش
        tx_data = f"{wallet_id}{recipient}{amount}{transaction['timestamp']}"
        tx_hash = hashlib.sha256(tx_data.encode('utf-8')).hexdigest()
        transaction['hash'] = tx_hash
        
        return transaction

# الاستخدام
multisig_tx = MultisigTransaction()

# إنشاء محفظة متعددة التوقيع (3 من 5)
participants = ["مدير_1", "مدير_2", "مدير_3", "مدير_4", "مدير_5"]
wallet = multisig_tx.create_multisig_wallet(participants, threshold=3)

print(f"محفظة متعددة التوقيع:")
print(f"  المعرّف: {wallet.key_id}")
print(f"  العتبة: {wallet.threshold} من {wallet.total_participants}")
print(f"  المشاركون: {', '.join(participants)}")

# إنشاء معاملة
transaction = multisig_tx.create_multisig_transaction(
    wallet_id=wallet.key_id,
    recipient="محفظة_الشركة",
    amount=1000000.0
)

print(f"\nمعاملة متعددة التوقيع:")
print(f"  المحفظة: {transaction['wallet_id']}")
print(f"  المستلم: {transaction['recipient']}")
print(f"  المبلغ: {transaction['amount']:,.2f} ريال")
print(f"  الهاش: {transaction['hash'][:40]}...")
print(f"  الحالة: {transaction['status']}")
print(f"  التوقيعات المطلوبة: {wallet.threshold}")
```

## أفضل الممارسات

### أمان سلسلة الكتل

```python
# ✅ استخدم توقيعات رقمية لكل معاملة
# ✅ تحقق من صحة السلسلة بانتظام
# ✅ استخدم صعوبة proof-of-work مناسبة
# ✅ احفظ المفاتيح الخاصة بأمان

# ❌ لا تقبل معاملات بدون توقيع
# ❌ لا تقلل من صعوبة التعدين بشكل كبير
# ❌ لا تشارك المفاتيح الخاصة
# ❌ لا تثق بالبيانات بدون تحقق
```

### الأداء

```python
# نصائح لتحسين الأداء:

# 1. تجميع المعاملات في كتل
batch_size = 100  # معاملة لكل كتلة

# 2. ضبط الصعوبة حسب قوة الحوسبة
difficulty = "0000"  # 4 أصفار للبداية

# 3. استخدام قواعد بيانات للتخزين
# بدلاً من الذاكرة فقط

# 4. التوازن بين الأمان والسرعة
# صعوبة أعلى = أمان أكثر + وقت أطول
```

## الخلاصة

وظائف البلوك تشين في ZyraCrypt توفر:
- **حساب الهاش**: SHA-256 للكتل
- **إثبات العمل**: آلية proof-of-work
- **تجزئة المعاملات**: هاش آمن للمعاملات
- **التوقيعات**: دعم التوقيعات الرقمية
- **Multisig**: معاملات متعددة التوقيع

استخدم هذه الأدوات لبناء تطبيقات blockchain آمنة وموثوقة.

---

**التالي**: [استكشاف الأخطاء وحلولها](12-troubleshooting.md)
