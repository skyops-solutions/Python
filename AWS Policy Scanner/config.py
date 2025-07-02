"""
Конфігураційний файл для AWS IAM Policy Scanner
"""

# Небезпечні дії, які потребують особливої уваги
DANGEROUS_ACTIONS = {
    # IAM дії
    'iam:*': 'Повний доступ до IAM',
    'iam:CreateRole': 'Створення нових ролей',
    'iam:DeleteRole': 'Видалення ролей',
    'iam:AttachRolePolicy': 'Прикріплення політик до ролей',
    'iam:DetachRolePolicy': 'Відкріплення політик від ролей',
    'iam:PutRolePolicy': 'Додавання inline політик до ролей',
    'iam:DeleteRolePolicy': 'Видалення inline політик з ролей',
    'iam:CreateUser': 'Створення користувачів',
    'iam:DeleteUser': 'Видалення користувачів',
    'iam:CreateAccessKey': 'Створення ключів доступу',
    'iam:UpdateLoginProfile': 'Зміна паролів користувачів',
    
    # STS дії
    'sts:AssumeRole': 'Припущення ролей',
    'sts:AssumeRoleWithSAML': 'Припущення ролей через SAML',
    'sts:AssumeRoleWithWebIdentity': 'Припущення ролей через Web Identity',
    
    # EC2 дії
    'ec2:TerminateInstances': 'Видалення EC2 інстансів',
    'ec2:StopInstances': 'Зупинка EC2 інстансів',
    'ec2:ModifyInstanceAttribute': 'Зміна атрибутів інстансів',
    'ec2:CreateImage': 'Створення AMI образів',
    'ec2:ModifySecurityGroupRules': 'Зміна правил security груп',
    
    # S3 дії
    's3:DeleteBucket': 'Видалення S3 бакетів',
    's3:DeleteObject': 'Видалення об\'єктів S3',
    's3:PutBucketPolicy': 'Зміна політик бакетів',
    's3:PutBucketAcl': 'Зміна ACL бакетів',
    's3:PutObjectAcl': 'Зміна ACL об\'єктів',
    
    # RDS дії
    'rds:DeleteDBInstance': 'Видалення RDS інстансів',
    'rds:DeleteDBCluster': 'Видалення RDS кластерів',
    'rds:ModifyDBInstance': 'Зміна RDS інстансів',
    'rds:RebootDBInstance': 'Перезавантаження RDS інстансів',
    
    # Lambda дії
    'lambda:DeleteFunction': 'Видалення Lambda функцій',
    'lambda:UpdateFunctionCode': 'Оновлення коду Lambda функцій',
    'lambda:AddPermission': 'Додавання дозволів до Lambda',
    
    # CloudFormation дії
    'cloudformation:DeleteStack': 'Видалення CloudFormation стеків',
    'cloudformation:UpdateStack': 'Оновлення CloudFormation стеків',
    
    # Wildcards
    '*': 'Повний доступ до всіх сервісів'
}

# Чутливі дії, які потребують MFA
SENSITIVE_ACTIONS = [
    'iam:CreateUser', 'iam:DeleteUser', 'iam:CreateRole', 'iam:DeleteRole',
    'ec2:TerminateInstances', 'ec2:StopInstances',
    's3:DeleteBucket', 's3:DeleteObject',
    'rds:DeleteDBInstance', 'rds:DeleteDBCluster',
    'lambda:DeleteFunction',
    'cloudformation:DeleteStack'
]

# Рекомендовані умови безпеки
SECURITY_CONDITIONS = {
    'mfa_required': {
        'Bool': {
            'aws:MultiFactorAuthPresent': 'true'
        }
    },
    'mfa_age_limit': {
        'NumericLessThan': {
            'aws:MultiFactorAuthAge': '3600'  # 1 година
        }
    },
    'ip_restriction': {
        'IpAddress': {
            'aws:SourceIp': ['203.0.113.0/24', '198.51.100.0/24']  # Приклад IP діапазонів
        }
    },
    'time_restriction': {
        'DateGreaterThan': {
            'aws:CurrentTime': '2024-01-01T00:00:00Z'
        },
        'DateLessThan': {
            'aws:CurrentTime': '2024-12-31T23:59:59Z'
        }
    },
    'secure_transport': {
        'Bool': {
            'aws:SecureTransport': 'true'
        }
    }
}

# Загальні дії для різних сервісів (для генерації рекомендацій)
COMMON_ACTIONS_BY_SERVICE = {
    'ec2': [
        'ec2:DescribeInstances', 'ec2:DescribeImages', 'ec2:DescribeSecurityGroups',
        'ec2:StartInstances', 'ec2:StopInstances', 'ec2:RebootInstances',
        'ec2:CreateTags', 'ec2:DescribeTags'
    ],
    's3': [
        's3:GetObject', 's3:PutObject', 's3:DeleteObject',
        's3:ListBucket', 's3:GetBucketLocation', 's3:GetBucketVersioning',
        's3:PutObjectAcl', 's3:GetObjectAcl'
    ],
    'iam': [
        'iam:GetUser', 'iam:ListUsers', 'iam:GetRole', 'iam:ListRoles',
        'iam:GetPolicy', 'iam:ListPolicies', 'iam:GetPolicyVersion',
        'iam:ListAttachedUserPolicies', 'iam:ListAttachedRolePolicies'
    ],
    'rds': [
        'rds:DescribeDBInstances', 'rds:DescribeDBClusters',
        'rds:CreateDBSnapshot', 'rds:DescribeDBSnapshots',
        'rds:ListTagsForResource'
    ],
    'lambda': [
        'lambda:InvokeFunction', 'lambda:GetFunction', 'lambda:ListFunctions',
        'lambda:GetFunctionConfiguration', 'lambda:ListTags'
    ],
    'logs': [
        'logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents',
        'logs:DescribeLogGroups', 'logs:DescribeLogStreams'
    ]
}
