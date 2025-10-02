# دليل تحسين الأداء

## مقدمة

هذا الدليل يساعدك على تحسين أداء تطبيقات ZyraCrypt للحصول على أقصى سرعة وكفاءة.

## قياس الأداء

### أدوات القياس

```python
import time
import functools

def measure_time(func):
    """مُزخرِف لقياس وقت التنفيذ"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start = time.perf_counter()
        result = func(*args, **kwargs)
        end = time.perf_counter()
        print(f"{func.__name__}: {(end - start) * 1000:.2f} ms")
        return result
    return wrapper

# الاستخدام
@measure_time
def encrypt_data(framework, data, key):
    return framework.encrypt(data, key, "AES-GCM")
```

### قياس شامل

```python
from core_cryptography.encryption_framework import EncryptionFramework
import os

def benchmark_algorithms():
    """مقارنة أداء الخوارزميات"""
    framework = EncryptionFramework()
    key = os.urandom(32)
    
    # بيانات اختبار بأحجام مختلفة
    data_sizes = [1024, 10*1024, 100*1024, 1024*1024]  # 1KB, 10KB, 100KB, 1MB
    algorithms = ["AES-GCM", "ChaCha20"]
    
    results = {}
    
    for size in data_sizes:
        data = os.urandom(size)
        results[size] = {}
        
        for algo in algorithms:
            start = time.perf_counter()
            
            # تشفير
            _, iv, ciphertext, tag = framework.encrypt(data, key, algo)
            
            # فك تشفير
            framework.decrypt(algo, key, iv, ciphertext, tag)
            
            end = time.perf_counter()
            duration = (end - start) * 1000
            
            results[size][algo] = duration
    
    # عرض النتائج
    print("نتائج القياس (بالميلي ثانية):")
    print("-" * 50)
    for size in data_sizes:
        print(f"\nحجم البيانات: {size / 1024:.1f} KB")
        for algo in algorithms:
            print(f"  {algo}: {results[size][algo]:.2f} ms")

# تشغيل
benchmark_algorithms()
```

## تحسين التشفير

### اختيار الخوارزمية المناسبة

```python
from core_cryptography.encryption_framework import EncryptionFramework

framework = EncryptionFramework()
key = os.urandom(32)

# قرار ذكي بناءً على حجم البيانات
def smart_encrypt(data, key):
    """اختيار خوارزمية بناءً على حجم البيانات"""
    if len(data) < 1024:  # أقل من 1KB
        # ChaCha20 أسرع للبيانات الصغيرة
        return framework.encrypt(data, key, "ChaCha20")
    else:
        # AES-GCM أفضل للبيانات الكبيرة
        return framework.encrypt(data, key, "AES-GCM")

# الاستخدام
small_data = b"رسالة قصيرة"
large_data = b"بيانات كبيرة " * 1000

algo1, *encrypted1 = smart_encrypt(small_data, key)
algo2, *encrypted2 = smart_encrypt(large_data, key)

print(f"البيانات الصغيرة: {algo1}")
print(f"البيانات الكبيرة: {algo2}")
```

### معالجة بالأجزاء للملفات الكبيرة

```python
def encrypt_file_chunked(input_path, output_path, key, chunk_size=1024*1024):
    """تشفير ملف كبير على أجزاء"""
    framework = EncryptionFramework()
    
    with open(input_path, 'rb') as f_in:
        with open(output_path, 'wb') as f_out:
            chunk_num = 0
            total_time = 0
            
            while True:
                chunk = f_in.read(chunk_size)
                if not chunk:
                    break
                
                start = time.perf_counter()
                
                # تشفير الجزء
                algo, iv, ciphertext, tag = framework.encrypt(
                    chunk, key, "AES-GCM"
                )
                
                # حفظ الجزء
                f_out.write(len(iv).to_bytes(4, 'big'))
                f_out.write(iv)
                f_out.write(len(tag).to_bytes(4, 'big'))
                f_out.write(tag)
                f_out.write(len(ciphertext).to_bytes(4, 'big'))
                f_out.write(ciphertext)
                
                chunk_time = (time.perf_counter() - start) * 1000
                total_time += chunk_time
                chunk_num += 1
                
                print(f"الجزء {chunk_num}: {chunk_time:.2f} ms")
            
            print(f"\nالوقت الإجمالي: {total_time:.2f} ms")
            print(f"متوسط الوقت لكل جزء: {total_time / chunk_num:.2f} ms")

# الاستخدام
key = os.urandom(32)
encrypt_file_chunked('large_file.bin', 'large_file.enc', key, chunk_size=512*1024)
```

## تحسين اشتقاق المفاتيح

### ضبط إعدادات KDF

```python
from key_management.enhanced_kdf_password import (
    EnhancedKDF, KDFAlgorithm, SecurityProfile
)

kdf = EnhancedKDF()

# قياس الملفات الأمنية المختلفة
profiles = [
    SecurityProfile.INTERACTIVE,
    SecurityProfile.MODERATE,
    SecurityProfile.SENSITIVE,
    SecurityProfile.PARANOID
]

password = "كلمة-مرور-للاختبار"

print("قياس أداء KDF بملفات أمنية مختلفة:")
print("-" * 60)

for profile in profiles:
    start = time.perf_counter()
    
    key_material = kdf.derive_key(
        password=password,
        algorithm=KDFAlgorithm.ARGON2ID,
        security_profile=profile
    )
    
    duration = (time.perf_counter() - start) * 1000
    
    print(f"{profile.value:12s}: {duration:7.2f} ms")
```

**التوصيات**:
- **INTERACTIVE**: للتطبيقات التفاعلية (< 100ms)
- **MODERATE**: للخوادم (100-500ms)
- **SENSITIVE**: للبيانات الحساسة (500-2000ms)
- **PARANOID**: للأمان الأقصى (> 2000ms)

### التخزين المؤقت للمفاتيح

```python
from functools import lru_cache
import hashlib

class OptimizedKeyManager:
    def __init__(self):
        self.kdf = EnhancedKDF()
        self._cache = {}
    
    def get_key_cached(self, password, algorithm=KDFAlgorithm.ARGON2ID):
        """الحصول على مفتاح مع تخزين مؤقت"""
        # إنشاء مفتاح للتخزين المؤقت
        cache_key = hashlib.sha256(
            f"{password}:{algorithm.value}".encode()
        ).hexdigest()
        
        if cache_key in self._cache:
            print("✓ استخدام مفتاح من الذاكرة المؤقتة")
            return self._cache[cache_key]
        
        print("⚙ اشتقاق مفتاح جديد...")
        key_material = self.kdf.derive_key(
            password=password,
            algorithm=algorithm,
            security_profile=SecurityProfile.INTERACTIVE
        )
        
        self._cache[cache_key] = key_material
        return key_material
    
    def clear_cache(self):
        """مسح الذاكرة المؤقتة"""
        self._cache.clear()

# الاستخدام
key_mgr = OptimizedKeyManager()

# المرة الأولى: بطيء
start = time.perf_counter()
key1 = key_mgr.get_key_cached("password123")
print(f"المرة الأولى: {(time.perf_counter() - start) * 1000:.2f} ms")

# المرة الثانية: سريع
start = time.perf_counter()
key2 = key_mgr.get_key_cached("password123")
print(f"المرة الثانية: {(time.perf_counter() - start) * 1000:.2f} ms")
```

## تحسين الضغط

### اختيار مستوى الضغط

```python
from data_protection.compression_unit import CompressionUnit

compressor = CompressionUnit()

# بيانات اختبار
data = b"بيانات متكررة " * 10000

print("قياس مستويات الضغط:")
print("-" * 60)

for level in range(1, 10):
    start = time.perf_counter()
    compressed = compressor.compress(data, level=level)
    compress_time = (time.perf_counter() - start) * 1000
    
    start = time.perf_counter()
    decompressed = compressor.decompress(compressed)
    decompress_time = (time.perf_counter() - start) * 1000
    
    ratio = len(compressed) / len(data) * 100
    
    print(f"المستوى {level}:")
    print(f"  الحجم: {len(compressed):,} بايت ({ratio:.1f}%)")
    print(f"  الضغط: {compress_time:.2f} ms")
    print(f"  فك الضغط: {decompress_time:.2f} ms")
```

**التوصيات**:
- **مستوى 1-3**: سرعة عالية، ضغط منخفض
- **مستوى 6**: متوازن (افتراضي)
- **مستوى 9**: ضغط أقصى، أبطأ

### ضغط انتقائي

```python
def smart_compress(data, min_size=1024):
    """ضغط فقط إذا كان مفيداً"""
    compressor = CompressionUnit()
    
    # لا تضغط البيانات الصغيرة
    if len(data) < min_size:
        return data, False
    
    # جرب الضغط
    compressed = compressor.compress(data, level=6)
    
    # استخدم الضغط فقط إذا وفر أكثر من 10%
    if len(compressed) < len(data) * 0.9:
        return compressed, True
    else:
        return data, False

# الاستخدام
test_data = [
    b"small",
    b"random " + os.urandom(1024),
    b"repetitive " * 1000
]

for data in test_data:
    result, was_compressed = smart_compress(data)
    savings = (1 - len(result) / len(data)) * 100
    
    print(f"الأصلي: {len(data):,} بايت")
    print(f"النتيجة: {len(result):,} بايت")
    print(f"مضغوط: {was_compressed}")
    print(f"التوفير: {savings:.1f}%\n")
```

## التوازي والمعالجة المتزامنة

### معالجة متوازية

```python
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import multiprocessing

def encrypt_chunk(chunk, key):
    """تشفير جزء"""
    framework = EncryptionFramework()
    return framework.encrypt(chunk, key, "AES-GCM")

def parallel_encrypt(data_chunks, key, workers=None):
    """تشفير عدة أجزاء بالتوازي"""
    if workers is None:
        workers = multiprocessing.cpu_count()
    
    start = time.perf_counter()
    
    with ThreadPoolExecutor(max_workers=workers) as executor:
        results = list(executor.map(
            lambda chunk: encrypt_chunk(chunk, key),
            data_chunks
        ))
    
    duration = (time.perf_counter() - start) * 1000
    
    print(f"معالجة {len(data_chunks)} جزء بـ {workers} عامل:")
    print(f"  الوقت: {duration:.2f} ms")
    print(f"  متوسط لكل جزء: {duration / len(data_chunks):.2f} ms")
    
    return results

# الاستخدام
key = os.urandom(32)
chunks = [os.urandom(10*1024) for _ in range(10)]  # 10 أجزاء × 10KB

# متسلسل
start = time.perf_counter()
for chunk in chunks:
    encrypt_chunk(chunk, key)
serial_time = (time.perf_counter() - start) * 1000
print(f"متسلسل: {serial_time:.2f} ms")

# متوازي
parallel_encrypt(chunks, key, workers=4)
```

### معالجة غير متزامنة (Async)

```python
import asyncio

async def encrypt_async(data, key):
    """تشفير غير متزامن"""
    framework = EncryptionFramework()
    # في تطبيق حقيقي، استخدم await للعمليات الطويلة
    await asyncio.sleep(0)  # نقطة تحويل
    return framework.encrypt(data, key, "AES-GCM")

async def process_multiple_async(data_list, key):
    """معالجة عدة بيانات بشكل غير متزامن"""
    start = time.perf_counter()
    
    tasks = [encrypt_async(data, key) for data in data_list]
    results = await asyncio.gather(*tasks)
    
    duration = (time.perf_counter() - start) * 1000
    print(f"معالجة غير متزامنة: {duration:.2f} ms")
    
    return results

# الاستخدام
async def main():
    key = os.urandom(32)
    data_list = [f"بيانات {i}".encode() for i in range(10)]
    
    results = await process_multiple_async(data_list, key)
    print(f"تم معالجة {len(results)} عنصر")

# تشغيل
# asyncio.run(main())
```

## تحسين الذاكرة

### المراقبة

```python
import tracemalloc

def monitor_memory(func):
    """مراقبة استخدام الذاكرة"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        tracemalloc.start()
        
        result = func(*args, **kwargs)
        
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        
        print(f"{func.__name__} - استخدام الذاكرة:")
        print(f"  الحالي: {current / 1024 / 1024:.2f} MB")
        print(f"  الذروة: {peak / 1024 / 1024:.2f} MB")
        
        return result
    return wrapper

@monitor_memory
def process_large_data():
    framework = EncryptionFramework()
    key = os.urandom(32)
    
    # بيانات كبيرة
    large_data = os.urandom(10 * 1024 * 1024)  # 10 MB
    
    # تشفير
    algo, iv, ciphertext, tag = framework.encrypt(large_data, key, "AES-GCM")
    
    # فك تشفير
    decrypted = framework.decrypt(algo, key, iv, ciphertext, tag)

# تشغيل
process_large_data()
```

### تقليل استخدام الذاكرة

```python
def memory_efficient_encrypt(input_path, output_path, key):
    """تشفير بكفاءة في الذاكرة"""
    framework = EncryptionFramework()
    chunk_size = 64 * 1024  # 64 KB فقط في الذاكرة
    
    with open(input_path, 'rb') as f_in:
        with open(output_path, 'wb') as f_out:
            while True:
                # قراءة جزء صغير فقط
                chunk = f_in.read(chunk_size)
                if not chunk:
                    break
                
                # تشفير
                algo, iv, ct, tag = framework.encrypt(chunk, key, "AES-GCM")
                
                # كتابة مباشرة (لا تخزين)
                f_out.write(iv)
                f_out.write(tag)
                f_out.write(ct)
                
                # الذاكرة تُحرر تلقائياً

# الاستخدام
key = os.urandom(32)
memory_efficient_encrypt('large.bin', 'large.enc', key)
```

## نصائح عامة للأداء

### 1. تجنب إنشاء كائنات متكررة

```python
# ❌ بطيء
for _ in range(1000):
    framework = EncryptionFramework()  # إنشاء جديد في كل مرة
    framework.encrypt(data, key, "AES-GCM")

# ✅ سريع
framework = EncryptionFramework()  # إنشاء مرة واحدة
for _ in range(1000):
    framework.encrypt(data, key, "AES-GCM")
```

### 2. استخدم المخزن المؤقت للعمليات المتكررة

```python
from functools import lru_cache

@lru_cache(maxsize=128)
def get_derived_key(password: str):
    """تخزين مؤقت للمفاتيح المشتقة"""
    key_gen = KeyGenerator()
    return key_gen.derive_key_from_password(password, "argon2")
```

### 3. اختر الخوارزمية المناسبة

```python
# للسرعة القصوى
fast_algo = "ChaCha20"

# للأمان الأقصى
secure_algo = "AES-GCM"

# للمستقبل
future_safe = HybridPQCEngine(security_level=128)  # أقل مستوى للسرعة
```

### 4. راقب وحلل

```python
import cProfile

def profile_function(func):
    """تحليل الأداء المفصل"""
    profiler = cProfile.Profile()
    profiler.enable()
    
    result = func()
    
    profiler.disable()
    profiler.print_stats(sort='cumulative')
    
    return result

# الاستخدام
def my_encryption_workflow():
    # ... عمليات التشفير
    pass

profile_function(my_encryption_workflow)
```

## ملخص التوصيات

### للسرعة القصوى
1. استخدم ChaCha20 للبيانات الصغيرة
2. استخدم SecurityProfile.INTERACTIVE
3. تجنب Argon2 PARANOID
4. استخدم المعالجة المتوازية
5. قلل إنشاء الكائنات

### للكفاءة في الذاكرة
1. معالجة بالأجزاء للملفات الكبيرة
2. حرر الذاكرة بعد الاستخدام
3. استخدم generators بدل lists
4. تجنب النسخ غير الضرورية
5. راقب استخدام الذاكرة

### للتوازن
1. AES-GCM للبيانات العامة
2. SecurityProfile.MODERATE
3. ضغط انتقائي
4. تخزين مؤقت ذكي
5. قياس دوري للأداء

---

**التالي**: [الفهرس الرئيسي](00-index.md)
