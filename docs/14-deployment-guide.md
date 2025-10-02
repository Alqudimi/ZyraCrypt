# دليل النشر والإنتاج

## مقدمة

هذا الدليل يوضح كيفية نشر تطبيقات ZyraCrypt في بيئة الإنتاج بشكل آمن وموثوق.

## الإعداد للإنتاج

### متطلبات بيئة الإنتاج

```bash
# 1. تثبيت Python 3.10+
python3 --version

# 2. إنشاء بيئة افتراضية
python3 -m venv production_env
source production_env/bin/activate

# 3. تثبيت ZyraCrypt
pip install -e .

# 4. تثبيت خادم WSGI للإنتاج
pip install gunicorn  # لـ Linux/Unix
# أو
pip install waitress  # لـ Windows
```

### ملف المتطلبات

إنشاء `requirements.txt`:

```txt
cryptography>=46.0.2
pynacl>=1.6.0
argon2-cffi>=25.1.0
liboqs-python>=0.14.1
pillow>=11.3.0
flask>=3.1.2
flask-cors>=6.0.1
flask-sqlalchemy>=3.1.1
psycopg2-binary>=2.9.10
gunicorn>=23.0.0
```

## إدارة المفاتيح في الإنتاج

### استخدام متغيرات البيئة

```python
import os
from key_management.key_generator import KeyGenerator

# ❌ لا تفعل: مفاتيح في الكود
# MASTER_KEY = b"hardcoded_key_123"

# ✅ افعل: استخدم متغيرات البيئة
def get_master_key():
    key_b64 = os.environ.get('MASTER_ENCRYPTION_KEY')
    
    if not key_b64:
        raise ValueError("MASTER_ENCRYPTION_KEY not set!")
    
    import base64
    return base64.b64decode(key_b64)

# في بيئة الإنتاج
master_key = get_master_key()
```

### إعداد متغيرات البيئة

**Linux/Mac** (`.env` file):
```bash
export MASTER_ENCRYPTION_KEY="base64_encoded_key_here"
export DATABASE_ENCRYPTION_KEY="base64_encoded_key_here"
export SESSION_SECRET="random_secret_here"
```

**Systemd Service**:
```ini
[Service]
Environment="MASTER_ENCRYPTION_KEY=..."
Environment="DATABASE_ENCRYPTION_KEY=..."
EnvironmentFile=/etc/myapp/secrets.env
```

**Docker**:
```dockerfile
# في Dockerfile
ENV MASTER_ENCRYPTION_KEY=""

# عند التشغيل
docker run -e MASTER_ENCRYPTION_KEY="..." myapp
```

### استخدام Vault للمفاتيح

```python
import hvac  # HashiCorp Vault client

class VaultKeyManager:
    def __init__(self, vault_url, token):
        self.client = hvac.Client(url=vault_url, token=token)
    
    def get_key(self, key_path):
        """الحصول على مفتاح من Vault"""
        secret = self.client.secrets.kv.v2.read_secret_version(
            path=key_path
        )
        return secret['data']['data']['key'].encode('utf-8')
    
    def rotate_key(self, key_path, new_key):
        """تدوير مفتاح في Vault"""
        self.client.secrets.kv.v2.create_or_update_secret(
            path=key_path,
            secret={'key': new_key.decode('utf-8')}
        )

# الاستخدام
vault = VaultKeyManager('https://vault.example.com', token='...')
master_key = vault.get_key('secret/encryption/master')
```

## تطبيق Flask للإنتاج

### تطبيق آمن مع ZyraCrypt

```python
# app.py
import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from core_cryptography.encryption_framework import EncryptionFramework
from key_management.key_manager import KeyManager
import logging

# إعداد السجلات
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/myapp/app.log'),
        logging.StreamHandler()
    ]
)

app = Flask(__name__)

# إعدادات الإنتاج
app.config['SECRET_KEY'] = os.environ.get('SESSION_SECRET')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 ميجابايت

# CORS محدود
CORS(app, resources={
    r"/api/*": {
        "origins": ["https://yourdomain.com"],
        "methods": ["GET", "POST"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})

# التشفير
framework = EncryptionFramework()
key_manager = KeyManager()

# الحصول على المفتاح الرئيسي
MASTER_KEY = os.environ.get('MASTER_ENCRYPTION_KEY').encode('utf-8')

@app.route('/api/encrypt', methods=['POST'])
def encrypt_data():
    try:
        data = request.json.get('data')
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # التشفير
        algo, iv, ciphertext, tag = framework.encrypt(
            data.encode('utf-8'),
            MASTER_KEY,
            "AES-GCM"
        )
        
        # السجل
        app.logger.info(f"Data encrypted successfully")
        
        return jsonify({
            'algorithm': algo,
            'iv': iv.hex(),
            'ciphertext': ciphertext.hex(),
            'tag': tag.hex()
        })
    
    except Exception as e:
        app.logger.error(f"Encryption error: {str(e)}")
        return jsonify({'error': 'Encryption failed'}), 500

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy'}), 200

if __name__ == '__main__':
    # للتطوير فقط
    app.run(debug=False, host='0.0.0.0', port=5000)
```

### تشغيل مع Gunicorn

```bash
# تشغيل أساسي
gunicorn -w 4 -b 0.0.0.0:5000 app:app

# مع إعدادات متقدمة
gunicorn \
    --workers 4 \
    --worker-class gevent \
    --bind 0.0.0.0:5000 \
    --timeout 120 \
    --access-logfile /var/log/myapp/access.log \
    --error-logfile /var/log/myapp/error.log \
    --log-level info \
    app:app
```

### ملف Gunicorn Config

`gunicorn_config.py`:
```python
import os
import multiprocessing

# عدد العمال
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = 'gevent'

# الربط
bind = '0.0.0.0:5000'

# المهلات
timeout = 120
keepalive = 5

# السجلات
accesslog = '/var/log/myapp/access.log'
errorlog = '/var/log/myapp/error.log'
loglevel = 'info'

# الأمان
limit_request_line = 4096
limit_request_fields = 100
limit_request_field_size = 8190
```

تشغيل:
```bash
gunicorn -c gunicorn_config.py app:app
```

## النشر على السحابة

### AWS EC2

**1. إعداد EC2**:
```bash
# تحديث النظام
sudo apt update && sudo apt upgrade -y

# تثبيت Python 3.10
sudo apt install python3.10 python3.10-venv python3-pip

# تثبيت التطبيق
git clone https://github.com/yourusername/myapp.git
cd myapp
python3.10 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**2. إعداد Systemd Service**:

`/etc/systemd/system/myapp.service`:
```ini
[Unit]
Description=MyApp Encryption Service
After=network.target

[Service]
Type=notify
User=ubuntu
Group=ubuntu
WorkingDirectory=/home/ubuntu/myapp
Environment="PATH=/home/ubuntu/myapp/venv/bin"
EnvironmentFile=/etc/myapp/secrets.env
ExecStart=/home/ubuntu/myapp/venv/bin/gunicorn -c gunicorn_config.py app:app
ExecReload=/bin/kill -s HUP $MAINPID
KillMode=mixed
KillSignal=SIGQUIT
TimeoutStopSec=5
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

**3. تفعيل وتشغيل**:
```bash
sudo systemctl daemon-reload
sudo systemctl enable myapp
sudo systemctl start myapp
sudo systemctl status myapp
```

### Docker

**Dockerfile**:
```dockerfile
FROM python:3.10-slim

WORKDIR /app

# تثبيت التبعيات
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# نسخ التطبيق
COPY . .

# المستخدم غير الجذر
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# المنفذ
EXPOSE 5000

# التشغيل
CMD ["gunicorn", "-c", "gunicorn_config.py", "app:app"]
```

**docker-compose.yml**:
```yaml
version: '3.8'

services:
  app:
    build: .
    ports:
      - "5000:5000"
    environment:
      - MASTER_ENCRYPTION_KEY=${MASTER_ENCRYPTION_KEY}
      - DATABASE_ENCRYPTION_KEY=${DATABASE_ENCRYPTION_KEY}
      - SESSION_SECRET=${SESSION_SECRET}
    volumes:
      - ./logs:/var/log/myapp
    restart: unless-stopped
    
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - app
    restart: unless-stopped
```

**بناء وتشغيل**:
```bash
# بناء
docker-compose build

# تشغيل
docker-compose up -d

# عرض السجلات
docker-compose logs -f

# إيقاف
docker-compose down
```

### Kubernetes

**deployment.yaml**:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp-encryption
spec:
  replicas: 3
  selector:
    matchLabels:
      app: myapp
  template:
    metadata:
      labels:
        app: myapp
    spec:
      containers:
      - name: myapp
        image: myapp:latest
        ports:
        - containerPort: 5000
        env:
        - name: MASTER_ENCRYPTION_KEY
          valueFrom:
            secretKeyRef:
              name: encryption-secrets
              key: master-key
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 5000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 5000
          initialDelaySeconds: 5
          periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: myapp-service
spec:
  selector:
    app: myapp
  ports:
  - port: 80
    targetPort: 5000
  type: LoadBalancer
```

## Nginx كوكيل عكسي

### إعداد Nginx

`/etc/nginx/sites-available/myapp`:
```nginx
upstream myapp {
    server 127.0.0.1:5000;
}

server {
    listen 80;
    server_name example.com;
    
    # إعادة توجيه لـ HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name example.com;
    
    # SSL
    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    
    # الأمان
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=31536000" always;
    
    # حجم الطلب
    client_max_body_size 20M;
    
    location / {
        proxy_pass http://myapp;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # المهلات
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
    
    # السجلات
    access_log /var/log/nginx/myapp_access.log;
    error_log /var/log/nginx/myapp_error.log;
}
```

**تفعيل**:
```bash
sudo ln -s /etc/nginx/sites-available/myapp /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

## المراقبة والسجلات

### إعداد السجلات

```python
import logging
from logging.handlers import RotatingFileHandler

# سجل متناوب
handler = RotatingFileHandler(
    '/var/log/myapp/app.log',
    maxBytes=10*1024*1024,  # 10 ميجابايت
    backupCount=10
)

handler.setFormatter(logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
))

app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)

# سجل أمني منفصل
security_logger = logging.getLogger('security')
security_handler = RotatingFileHandler(
    '/var/log/myapp/security.log',
    maxBytes=10*1024*1024,
    backupCount=20
)
security_handler.setFormatter(logging.Formatter(
    '%(asctime)s - SECURITY - %(levelname)s - %(message)s'
))
security_logger.addHandler(security_handler)

# تسجيل الأحداث الأمنية
@app.route('/api/encrypt', methods=['POST'])
def encrypt_data():
    # ...
    security_logger.info(f"Encryption request from {request.remote_addr}")
    # ...
```

### Prometheus للمراقبة

```python
from prometheus_flask_exporter import PrometheusMetrics

metrics = PrometheusMetrics(app)

# مقاييس مخصصة
encryption_counter = metrics.counter(
    'encryption_requests_total',
    'Total encryption requests'
)

@app.route('/api/encrypt', methods=['POST'])
def encrypt_data():
    encryption_counter.inc()
    # ...
```

## النسخ الاحتياطي والاستعادة

### نسخ احتياطي للمفاتيح

```python
import json
from datetime import datetime

def backup_keys(vault_manager, backup_path):
    """نسخ احتياطي للمفاتيح"""
    keys = {
        'master_key': vault_manager.get_key('secret/master').hex(),
        'database_key': vault_manager.get_key('secret/database').hex(),
        'backup_date': datetime.now().isoformat()
    }
    
    # تشفير النسخة الاحتياطية
    from core_cryptography.encryption_framework import EncryptionFramework
    framework = EncryptionFramework()
    
    backup_password = input("أدخل كلمة مرور النسخة الاحتياطية: ")
    key_material = key_gen.derive_key_from_password(backup_password, "argon2")
    
    data = json.dumps(keys).encode('utf-8')
    algo, iv, ct, tag = framework.encrypt(data, key_material['key'], "AES-GCM")
    
    backup = {
        'algorithm': algo,
        'salt': key_material['salt'].hex(),
        'iv': iv.hex(),
        'ciphertext': ct.hex(),
        'tag': tag.hex()
    }
    
    with open(backup_path, 'w') as f:
        json.dump(backup, f)
    
    print(f"✓ تم حفظ النسخة الاحتياطية في: {backup_path}")
```

## قائمة مراجعة الإنتاج

### قبل النشر

- [ ] جميع المفاتيح محفوظة بأمان (Vault/متغيرات بيئة)
- [ ] تم تفعيل HTTPS/TLS
- [ ] تم ضبط حدود الطلبات
- [ ] السجلات معدة ومراقبة
- [ ] النسخ الاحتياطي مجدول
- [ ] تم اختبار استعادة النسخة الاحتياطية
- [ ] المفاتيح لها خطة تدوير
- [ ] تم تكوين جدار الحماية
- [ ] تم تعطيل وضع التطوير
- [ ] تحديث جميع التبعيات

### بعد النشر

- [ ] مراقبة السجلات للأخطاء
- [ ] اختبار جميع endpoints
- [ ] التحقق من SSL/TLS
- [ ] مراقبة استخدام الموارد
- [ ] إعداد التنبيهات
- [ ] توثيق الإعدادات
- [ ] تدريب فريق العمليات

---

**التالي**: [دليل الترحيل](15-migration-guide.md)
