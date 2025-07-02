# 🔐 IAM Policy Scanner & Optimizer

> Інструмент для аналізу, перевірки та оптимізації AWS IAM політик з підтримкою демо-режиму, офлайн-перевірки та інтеграції з реальним AWS-акаунтом.

---

## 🚀 Як запустити

### 1. Встановити залежності

```bash
pip install boto3 click rich pyyaml tabulate colorama python-dateutil requests
```

---

### 2. Швидкий тест без AWS

```bash
# Демо режим — демонстрація можливостей
python run.py demo

# Навчальні best practices
python run.py best-practices
```

---

### 3. Перевірити файл політики

```bash
# Створити тестову IAM політику
echo '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' > bad_policy.json

# Перевірити її
python run.py check-policy bad_policy.json
```

---

### 4. Справжнє AWS сканування

```bash
# Налаштувати AWS CLI
aws configure

# Сканувати всі IAM політики
python run.py scan

# Сканувати з фільтром за рівнем ризику
python run.py scan --severity HIGH --output report.json

# Оптимізувати політики за останні 30 днів активності
python run.py optimize --days 30
```

---

## 🎯 Основні команди

| Команда           | Опис                                                                 |
|-------------------|----------------------------------------------------------------------|
| `demo`            | Демонстрація з тестовими даними                                      |
| `scan`            | Сканування AWS IAM політик                                           |
| `optimize`        | Оптимізація політик за принципом least privilege                     |
| `analyze`         | Аналіз окремого користувача або ролі                                 |
| `check-policy`    | Перевірка політики з JSON-файлу                                      |
| `best-practices`  | Перелік рекомендацій з безпеки                                       |

---

## 💡 Що робить інструмент

🔴 **HIGH SEVERITY**
- Повний admin доступ (`"Action": "*"` + `"Resource": "*"`).
- Wildcard-ресурси без обмежень.
- Критичні дії (наприклад `iam:*`, `sts:*`) без MFA.

🟡 **MEDIUM SEVERITY**
- Широкі дозволи (наприклад `s3:*`).
- Дії без умов доступу.
- Відсутність security-умов (`Condition`, `MFA`).

🔵 **LOW SEVERITY**
- Оптимізації: усунення зайвих дій, зменшення обсягів.
- Покращення відповідно до best practices.

---

## ✨ Особливості

- ✅ **Працює без підключення до AWS** — офлайн перевірка JSON-політик.
- 🧪 **Демо режим** — для демонстрацій і тренувань.
- 📘 **Best practices** — навчальні приклади та поради.
- 🎨 **Rich Console UI** — кольоровий, форматований вивід.
- 📤 **JSON-експорт** — для звітів та інтеграції з іншими системами.

---

## 🛠️ Залежності

- Python ≥ 3.8
- `boto3`, `click`, `rich`, `pyyaml`, `tabulate`, `colorama`, `python-dateutil`, `requests`

---

## 📄 Ліцензія

MIT License — вільно використовуйте та модифікуйте.
