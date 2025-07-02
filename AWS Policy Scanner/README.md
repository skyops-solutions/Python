🚀 Як запустити:
1. Встановити залежності:
bashpip install boto3 click rich pyyaml tabulate colorama python-dateutil requests
2. Швидкий тест без AWS:
bash# Демо режим
python run.py demo

# Best practices
python run.py best-practices
3. Перевірити файл політики:
bash# Створити тестову політику
echo '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' > bad_policy.json

# Перевірити
python run.py check-policy bad_policy.json
4. Справжнє AWS сканування:
bash# Налаштувати AWS
aws configure

# Сканувати
python run.py scan
python run.py scan --severity HIGH --output report.json
python run.py optimize --days 30
🎯 Основні команди:
КомандаОписdemoДемонстрація з тестовими данимиscanСканування AWS IAM політикoptimizeОптимізація за least privilegeanalyzeАналіз користувача/роліcheck-policyПеревірка файлу політикиbest-practicesПоказати рекомендації
💡 Що робить інструмент:
🔴 HIGH SEVERITY

Повний admin доступ (*:*)
Wildcard ресурси без обмежень
Критичні IAM дії без MFA

🟡 MEDIUM SEVERITY

Широкі service дозволи (s3:*)
Небезпечні дії без умов
Відсутність security conditions

🔵 LOW SEVERITY

Оптимізації на базі використання
Рекомендації з покращення

✨ Особливості:

Без AWS підключення - можна тестувати на файлах
Демо режим - показує всі можливості
Best practices - навчальний матеріал
Красивий вивід - Rich console formatting
JSON експорт - для інтеграції з іншими системами