import boto3
import json
import re
from datetime import datetime, timedelta
from typing import Dict, List, Set, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, TaskID
from rich.panel import Panel
from rich.tree import Tree
import click
import yaml

console = Console()

@dataclass
class PolicyViolation:
    """Клас для зберігання порушень політики"""
    severity: str  # HIGH, MEDIUM, LOW
    type: str
    resource: str
    issue: str
    recommendation: str
    current_policy: Dict
    suggested_policy: Optional[Dict] = None

@dataclass
class ScanResult:
    """Результат сканування"""
    account_id: str
    scan_time: datetime
    total_policies: int
    violations: List[PolicyViolation]
    
    def to_dict(self):
        return {
            'account_id': self.account_id,
            'scan_time': self.scan_time.isoformat(),
            'total_policies': self.total_policies,
            'violations': [asdict(v) for v in self.violations]
        }

class IAMPolicyScanner:
    """Головний клас для сканування IAM політик"""
    
    def __init__(self, aws_profile: str = None, region: str = 'us-east-1'):
        """Ініціалізація сканера"""
        try:
            if aws_profile:
                session = boto3.Session(profile_name=aws_profile)
            else:
                session = boto3.Session()
                
            self.iam = session.client('iam', region_name=region)
            self.sts = session.client('sts', region_name=region)
            self.cloudtrail = session.client('cloudtrail', region_name=region)
            
            # Отримати account ID
            self.account_id = self.sts.get_caller_identity()['Account']
            
            console.print(f"[green]✅ Підключено до AWS Account: {self.account_id}[/green]")
            
        except Exception as e:
            console.print(f"[red]❌ Помилка підключення до AWS: {e}[/red]")
            raise
    
    def get_all_policies(self) -> List[Dict]:
        """Отримати всі IAM політики"""
        policies = []
        
        try:
            # Отримати всі користувацькі політики
            paginator = self.iam.get_paginator('list_policies')
            for page in paginator.paginate(Scope='Local'):
                for policy in page['Policies']:
                    try:
                        # Отримати версію політики
                        policy_version = self.iam.get_policy_version(
                            PolicyArn=policy['Arn'],
                            VersionId=policy['DefaultVersionId']
                        )
                        
                        policy['Document'] = policy_version['PolicyVersion']['Document']
                        policies.append(policy)
                        
                    except Exception as e:
                        console.print(f"[yellow]⚠️ Не вдалося отримати політику {policy['PolicyName']}: {e}[/yellow]")
                        
        except Exception as e:
            console.print(f"[red]❌ Помилка отримання політик: {e}[/red]")
            
        return policies
    
    def get_inline_policies(self) -> List[Dict]:
        """Отримати всі inline політики користувачів та ролей"""
        inline_policies = []
        
        try:
            # Inline політики користувачів
            paginator = self.iam.get_paginator('list_users')
            for page in paginator.paginate():
                for user in page['Users']:
                    user_policies = self.iam.list_user_policies(UserName=user['UserName'])
                    for policy_name in user_policies['PolicyNames']:
                        try:
                            policy_doc = self.iam.get_user_policy(
                                UserName=user['UserName'],
                                PolicyName=policy_name
                            )
                            
                            inline_policies.append({
                                'Type': 'UserInlinePolicy',
                                'Name': f"{user['UserName']}/{policy_name}",
                                'UserName': user['UserName'],
                                'PolicyName': policy_name,
                                'Document': policy_doc['PolicyDocument']
                            })
                        except Exception as e:
                            console.print(f"[yellow]⚠️ Не вдалося отримати inline політику {policy_name}: {e}[/yellow]")
            
            # Inline політики ролей
            paginator = self.iam.get_paginator('list_roles')
            for page in paginator.paginate():
                for role in page['Roles']:
                    role_policies = self.iam.list_role_policies(RoleName=role['RoleName'])
                    for policy_name in role_policies['PolicyNames']:
                        try:
                            policy_doc = self.iam.get_role_policy(
                                RoleName=role['RoleName'],
                                PolicyName=policy_name
                            )
                            
                            inline_policies.append({
                                'Type': 'RoleInlinePolicy',
                                'Name': f"{role['RoleName']}/{policy_name}",
                                'RoleName': role['RoleName'],
                                'PolicyName': policy_name,
                                'Document': policy_doc['PolicyDocument']
                            })
                        except Exception as e:
                            console.print(f"[yellow]⚠️ Не вдалося отримати inline політику {policy_name}: {e}[/yellow]")
                            
        except Exception as e:
            console.print(f"[red]❌ Помилка отримання inline політик: {e}[/red]")
            
        return inline_policies
    
    def analyze_policy_document(self, policy_doc: Dict, policy_name: str) -> List[PolicyViolation]:
        """Аналіз документа політики на порушення"""
        violations = []
        
        if 'Statement' not in policy_doc:
            return violations
        
        statements = policy_doc['Statement']
        if not isinstance(statements, list):
            statements = [statements]
        
        for i, statement in enumerate(statements):
            violations.extend(self._check_overly_broad_permissions(statement, policy_name, i))
            violations.extend(self._check_wildcard_resources(statement, policy_name, i))
            violations.extend(self._check_dangerous_actions(statement, policy_name, i))
            violations.extend(self._check_missing_conditions(statement, policy_name, i))
            violations.extend(self._check_admin_access(statement, policy_name, i))
        
        return violations
    
    def _check_overly_broad_permissions(self, statement: Dict, policy_name: str, stmt_index: int) -> List[PolicyViolation]:
        """Перевірка на надто широкі дозволи"""
        violations = []
        
        if statement.get('Effect') != 'Allow':
            return violations
        
        actions = statement.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]
        
        # Перевірка на wildcard дії
        wildcard_actions = [action for action in actions if '*' in action and action != '*']
        
        for action in wildcard_actions:
            service = action.split(':')[0] if ':' in action else 'unknown'
            
            violations.append(PolicyViolation(
                severity='MEDIUM',
                type='OVERLY_BROAD_PERMISSIONS',
                resource=policy_name,
                issue=f"Широкі дозволи для сервісу: {action}",
                recommendation=f"Замініть '{action}' на конкретні дії, які дійсно потрібні",
                current_policy=statement,
                suggested_policy=self._suggest_specific_actions(action, statement)
            ))
        
        return violations
    
    def _check_wildcard_resources(self, statement: Dict, policy_name: str, stmt_index: int) -> List[PolicyViolation]:
        """Перевірка на wildcard ресурси"""
        violations = []
        
        if statement.get('Effect') != 'Allow':
            return violations
        
        resources = statement.get('Resource', [])
        if isinstance(resources, str):
            resources = [resources]
        
        # Перевірка на * в ресурсах
        if '*' in resources:
            violations.append(PolicyViolation(
                severity='HIGH',
                type='WILDCARD_RESOURCES',
                resource=policy_name,
                issue="Використання '*' для ресурсів дає доступ до всіх ресурсів",
                recommendation="Вкажіть конкретні ARN ресурсів замість '*'",
                current_policy=statement,
                suggested_policy=self._suggest_specific_resources(statement)
            ))
        
        return violations
    
    def _check_dangerous_actions(self, statement: Dict, policy_name: str, stmt_index: int) -> List[PolicyViolation]:
        """Перевірка на небезпечні дії"""
        violations = []
        
        if statement.get('Effect') != 'Allow':
            return violations
        
        dangerous_actions = {
            'iam:*': 'Повний доступ до IAM',
            'iam:CreateRole': 'Створення нових ролей',
            'iam:AttachRolePolicy': 'Прикріплення політик до ролей',
            'iam:PutRolePolicy': 'Додавання inline політик',
            'sts:AssumeRole': 'Припущення ролей',
            'ec2:TerminateInstances': 'Видалення EC2 інстансів', 
            's3:DeleteBucket': 'Видалення S3 бакетів',
            'rds:DeleteDBInstance': 'Видалення RDS інстансів'
        }
        
        actions = statement.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]
        
        for action in actions:
            if action in dangerous_actions or action == '*':
                severity = 'HIGH' if action in ['*', 'iam:*'] else 'MEDIUM'
                
                violations.append(PolicyViolation(
                    severity=severity,
                    type='DANGEROUS_ACTIONS',
                    resource=policy_name,
                    issue=f"Небезпечна дія: {action} - {dangerous_actions.get(action, 'Повний доступ')}",
                    recommendation=f"Обмежте використання '{action}' або додайте умови",
                    current_policy=statement
                ))
        
        return violations
    
    def _check_missing_conditions(self, statement: Dict, policy_name: str, stmt_index: int) -> List[PolicyViolation]:
        """Перевірка на відсутність умов безпеки"""
        violations = []
        
        if statement.get('Effect') != 'Allow':
            return violations
        
        # Перевірка відсутності MFA для чутливих дій
        actions = statement.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]
        
        sensitive_actions = [
            'iam:CreateUser', 'iam:DeleteUser', 'iam:CreateRole', 'iam:DeleteRole',
            'ec2:TerminateInstances', 's3:DeleteBucket', 'rds:DeleteDBInstance'
        ]
        
        has_sensitive_actions = any(
            any(sensitive in action for sensitive in sensitive_actions) 
            for action in actions
        )
        
        if has_sensitive_actions and 'Condition' not in statement:
            violations.append(PolicyViolation(
                severity='MEDIUM',
                type='MISSING_CONDITIONS',
                resource=policy_name,
                issue="Чутливі дії без обмежувальних умов",
                recommendation="Додайте умови, такі як MFA, IP-обмеження або часові обмеження",
                current_policy=statement,
                suggested_policy=self._suggest_conditions(statement)
            ))
        
        return violations
    
    def _check_admin_access(self, statement: Dict, policy_name: str, stmt_index: int) -> List[PolicyViolation]:
        """Перевірка на адміністративний доступ"""
        violations = []
        
        if statement.get('Effect') != 'Allow':
            return violations
        
        actions = statement.get('Action', [])
        resources = statement.get('Resource', [])
        
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        
        # Перевірка на повний доступ
        if '*' in actions and '*' in resources:
            violations.append(PolicyViolation(
                severity='HIGH',
                type='ADMIN_ACCESS',
                resource=policy_name,
                issue="Повний адміністративний доступ (*:* на все)",
                recommendation="Розділіть на окремі політики з конкретними дозволами",
                current_policy=statement
            ))
        
        return violations
    
    def _suggest_specific_actions(self, broad_action: str, statement: Dict) -> Dict:
        """Запропонувати конкретні дії замість широких"""
        service = broad_action.split(':')[0]
        
        # Приклади конкретних дій для популярних сервісів
        common_actions = {
            'ec2': ['ec2:DescribeInstances', 'ec2:StartInstances', 'ec2:StopInstances'],
            's3': ['s3:GetObject', 's3:PutObject', 's3:ListBucket'],
            'iam': ['iam:GetUser', 'iam:ListUsers', 'iam:GetRole'],
            'rds': ['rds:DescribeDBInstances', 'rds:CreateDBSnapshot']
        }
        
        suggested_statement = statement.copy()
        if service in common_actions:
            suggested_statement['Action'] = common_actions[service]
        
        return suggested_statement
    
    def _suggest_specific_resources(self, statement: Dict) -> Dict:
        """Запропонувати конкретні ресурси"""
        suggested_statement = statement.copy()
        
        # Приклади конкретних ресурсів
        actions = statement.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]
        
        # Визначити тип ресурсу на основі дій
        if any('s3:' in action for action in actions):
            suggested_statement['Resource'] = [
                'arn:aws:s3:::my-specific-bucket',
                'arn:aws:s3:::my-specific-bucket/*'
            ]
        elif any('ec2:' in action for action in actions):
            suggested_statement['Resource'] = [
                f'arn:aws:ec2:*:{self.account_id}:instance/*'
            ]
        
        return suggested_statement
    
    def _suggest_conditions(self, statement: Dict) -> Dict:
        """Запропонувати умови безпеки"""
        suggested_statement = statement.copy()
        
        # Додати MFA умову для чутливих дій
        suggested_statement['Condition'] = {
            'Bool': {
                'aws:MultiFactorAuthPresent': 'true'
            },
            'DateGreaterThan': {
                'aws:MultiFactorAuthAge': '3600'  # MFA не старше 1 години
            }
        }
        
        return suggested_statement
    
    def get_unused_permissions(self, days: int = 90) -> Dict[str, List[str]]:
        """Знайти невикористані дозволи за період"""
        unused_permissions = {}
        
        try:
            # Отримати CloudTrail логи за період
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(days=days)
            
            console.print(f"[blue]🔍 Аналіз використання дозволів за {days} днів...[/blue]")
            
            # Отримати всі API виклики
            paginator = self.cloudtrail.get_paginator('lookup_events')
            used_actions = set()
            
            for page in paginator.paginate(
                StartTime=start_time,
                EndTime=end_time
            ):
                for event in page['Events']:
                    event_name = event['EventName']
                    # Конвертувати event name в IAM action формат
                    if 'EventSource' in event:
                        service = event['EventSource'].replace('.amazonaws.com', '')
                        action = f"{service}:{event_name}"
                        used_actions.add(action)
            
            return {'used_actions': list(used_actions)}
            
        except Exception as e:
            console.print(f"[yellow]⚠️ Не вдалося отримати CloudTrail логи: {e}[/yellow]")
            return {}
    
    def scan_all_policies(self) -> ScanResult:
        """Повне сканування всіх політик"""
        console.print("[blue]🚀 Початок сканування IAM політик...[/blue]")
        
        all_violations = []
        
        with Progress() as progress:
            # Сканування користувацьких політик
            task1 = progress.add_task("Сканування користувацьких політик...", total=None)
            managed_policies = self.get_all_policies()
            progress.update(task1, total=len(managed_policies))
            
            for i, policy in enumerate(managed_policies):
                violations = self.analyze_policy_document(
                    policy['Document'], 
                    policy['PolicyName']
                )
                all_violations.extend(violations)
                progress.update(task1, advance=1)
            
            # Сканування inline політик
            task2 = progress.add_task("Сканування inline політик...", total=None)
            inline_policies = self.get_inline_policies()
            progress.update(task2, total=len(inline_policies))
            
            for i, policy in enumerate(inline_policies):
                violations = self.analyze_policy_document(
                    policy['Document'],
                    policy['Name']
                )
                all_violations.extend(violations)
                progress.update(task2, advance=1)
        
        # Створити результат сканування
        result = ScanResult(
            account_id=self.account_id,
            scan_time=datetime.utcnow(),
            total_policies=len(managed_policies) + len(inline_policies),
            violations=all_violations
        )
        
        return result
    
    def generate_least_privilege_policy(self, current_policy: Dict, used_actions: List[str]) -> Dict:
        """Згенерувати least privilege політику на основі використання"""
        new_statements = []
        
        if 'Statement' not in current_policy:
            return current_policy
        
        statements = current_policy['Statement']
        if not isinstance(statements, list):
            statements = [statements]
        
        for statement in statements:
            if statement.get('Effect') != 'Allow':
                new_statements.append(statement)
                continue
            
            actions = statement.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]
            
            # Фільтрувати тільки використані дії
            filtered_actions = []
            for action in actions:
                if action in used_actions or any(used.startswith(action.replace('*', '')) for used in used_actions):
                    filtered_actions.append(action)
            
            if filtered_actions:
                new_statement = statement.copy()
                new_statement['Action'] = filtered_actions
                new_statements.append(new_statement)
        
        return {
            'Version': current_policy.get('Version', '2012-10-17'),
            'Statement': new_statements
        }

class IAMReporter:
    """Клас для генерації звітів"""
    
    def __init__(self):
        self.console = Console()
    
    def print_summary(self, result: ScanResult):
        """Вивести загальну інформацію"""
        # Статистика по severity
        high = len([v for v in result.violations if v.severity == 'HIGH'])
        medium = len([v for v in result.violations if v.severity == 'MEDIUM'])
        low = len([v for v in result.violations if v.severity == 'LOW'])
        
        # Панель з результатами
        summary = f"""
[bold]AWS Account:[/bold] {result.account_id}
[bold]Час сканування:[/bold] {result.scan_time.strftime('%Y-%m-%d %H:%M:%S')}
[bold]Всього політик:[/bold] {result.total_policies}
[bold]Знайдено порушень:[/bold] {len(result.violations)}

[bold red]🔴 Високий ризик:[/bold red] {high}
[bold yellow]🟡 Середній ризик:[/bold yellow] {medium}  
[bold blue]🔵 Низький ризик:[/bold blue] {low}
        """
        
        self.console.print(Panel(summary, title="📊 Результати сканування", border_style="blue"))
    
    def print_violations_table(self, result: ScanResult):
        """Вивести таблицю порушень"""
        if not result.violations:
            self.console.print("[green]✅ Порушень не знайдено![/green]")
            return
        
        table = Table(title="🛡️ Знайдені порушення безпеки")
        table.add_column("Пріоритет", style="bold")
        table.add_column("Тип", style="cyan")
        table.add_column("Ресурс", style="magenta") 
        table.add_column("Проблема", style="red")
        table.add_column("Рекомендація", style="green")
        
        # Сортувати за пріоритетом
        severity_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
        sorted_violations = sorted(result.violations, key=lambda x: severity_order.get(x.severity, 3))
        
        for violation in sorted_violations:
            severity_icon = {
                'HIGH': '🔴',
                'MEDIUM': '🟡', 
                'LOW': '🔵'
            }.get(violation.severity, '⚪')
            
            table.add_row(
                f"{severity_icon} {violation.severity}",
                violation.type,
                violation.resource,
                violation.issue[:50] + "..." if len(violation.issue) > 50 else violation.issue,
                violation.recommendation[:50] + "..." if len(violation.recommendation) > 50 else violation.recommendation
            )
        
        self.console.print(table)
    
    def print_policy_tree(self, result: ScanResult):
        """Вивести дерево політик з порушеннями"""
        tree = Tree("🏛️ IAM Політики")
        
        # Групувати порушення по ресурсах
        violations_by_resource = {}
        for violation in result.violations:
            if violation.resource not in violations_by_resource:
                violations_by_resource[violation.resource] = []
            violations_by_resource[violation.resource].append(violation)
        
        for resource, violations in violations_by_resource.items():
            resource_node = tree.add(f"📄 {resource}")
            
            for violation in violations:
                severity_icon = {
                    'HIGH': '🔴',
                    'MEDIUM': '🟡',
                    'LOW': '🔵'
                }.get(violation.severity, '⚪')
                
                resource_node.add(f"{severity_icon} {violation.type}: {violation.issue}")
        
        self.console.print(tree)
    
    def save_report(self, result: ScanResult, filename: str = None):
        """Зберегти звіт у файл"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"iam_scan_report_{timestamp}.json"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(result.to_dict(), f, indent=2, ensure_ascii=False, default=str)
            
            self.console.print(f"[green]✅ Звіт збережено: {filename}[/green]")
            
        except Exception as e:
            self.console.print(f"[red]❌ Помилка збереження звіту: {e}[/red]")
    
    def generate_remediation_script(self, result: ScanResult, filename: str = None):
        """Згенерувати скрипт для виправлення"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"iam_remediation_{timestamp}.py"
        
        script_content = f'''#!/usr/bin/env python3
"""
Автоматично згенерований скрипт для виправлення IAM порушень
Згенеровано: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
AWS Account: {result.account_id}
"""

import boto3
import json
from datetime import datetime

def main():
    """Основна функція виправлення"""
    iam = boto3.client('iam')
    
    print("🚀 Початок виправлення IAM порушень...")
    
    # TODO: Реалізувати автоматичне виправлення
    # УВАГА: Тестуйте на dev середовищі перед production!
    
'''
        
        # Додати конкретні виправлення для кожного порушення
        for i, violation in enumerate(result.violations):
            if violation.suggested_policy:
                script_content += f'''
    # Виправлення {i+1}: {violation.issue}
    # Рекомендація: {violation.recommendation}
    suggested_policy_{i} = {json.dumps(violation.suggested_policy, indent=4)}
    
    # УВАГА: Перевірте політику перед застосуванням!
    # iam.put_user_policy(...) або iam.create_policy(...)
    
'''
        
        script_content += '''
    print("✅ Виправлення завершено!")

if __name__ == "__main__":
    main()
'''
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(script_content)
            
            self.console.print(f"[green]✅ Скрипт виправлення збережено: {filename}[/green]")
            
        except Exception as e:
            self.console.print(f"[red]❌ Помилка збереження скрипту: {e}[/red]")
