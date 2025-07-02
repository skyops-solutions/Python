#!/usr/bin/env python3
"""
Швидкий запуск AWS IAM Policy Scanner
"""

import sys
import os

# Додати поточну директорію до шляху Python
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Імпортувати основний CLI
from main import cli

if __name__ == '__main__':
    try:
        cli()
    except KeyboardInterrupt:
        print("\n🛑 Сканування перервано користувачем")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Критична помилка: {e}")
        sys.exit(1)

# ===============================
# test_policy.json - Тестова політика
# ===============================
"""
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
"""

# ===============================
# good_policy.json - Приклад гарної політики
# ===============================
"""
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": [
        "arn:aws:s3:::my-app-bucket/*"
      ],
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "true"
        }
      }
    }
  ]
}
"""

# ===============================
# README_QUICK.md
# ===============================
"""
# 🚀 Швидкий старт AWS IAM Policy Scanner

## Встановлення
```bash
pip install boto3 click rich pyyaml
```

## Налаштування AWS
```bash
aws configure
# або
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
```

## 🔍 Основні команди

### 1. Демо режим (без AWS підключення)
```bash
python run.py demo
```

### 2. Перевірка файлу політики
```bash
echo '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' > test.json
python run.py check-policy test.json
```

### 3. Показати best practices
```bash
python run.py best-practices
```

### 4. Справжнє сканування AWS (потрібні credentials)
```bash
python run.py scan
python run.py scan --severity HIGH
python run.py scan --profile production
```

### 5. Оптимізація політик
```bash
python run.py optimize --days 30
```

## 📊 Приклад виводу

```
📊 Результати сканування
AWS Account: 123456789012
Всього політик: 15
Знайдено порушень: 8

🔴 Високий ризик: 3
🟡 Середній ризик: 4
🔵 Низький ризик: 1
```

## 🎯 Що перевіряє

- ✅ Admin access (*:* дозволи)
- ✅ Wildcard ресурси
- ✅ Небезпечні дії
- ✅ Відсутність MFA умов
- ✅ Надлишкові дозволи

## 🔧 Швидкі тести

1. **Тест поганої політики:**
```bash
python run.py check-policy test_policy.json
```

2. **Тест гарної політики:**
```bash
python run.py check-policy good_policy.json
```

3. **Демо всіх функцій:**
```bash
python run.py demo
```
"""