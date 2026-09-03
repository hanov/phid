"""Bundle only supported AWS service models, plus credential/SSO dependencies."""
from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files

# Keep aligned with phi_security.aws.ALLOW. Credential providers use these too.
services = {
    'sts', 'ec2', 's3', 's3control', 'rds', 'docdb', 'dynamodb', 'redshift',
    'opensearch', 'logs', 'cloudtrail', 'iam', 'kms', 'macie2', 'guardduty',
    'securityhub', 'accessanalyzer', 'config', 'lambda', 'ecs', 'eks',
    'apigateway', 'elbv2', 'cloudfront', 'backup', 'glue', 'cloudwatch',
    'organizations', 'sso', 'sso-oidc', 'signin',
}
hiddenimports = ['html.parser']
datas = []
for source, destination in collect_data_files('botocore'):
    parts = Path(destination).parts
    # Root botocore data contains endpoint, partition, retry and SDK configuration.
    if len(parts) > 2 and parts[:2] == ('botocore', 'data') and parts[2] not in services:
        continue
    datas.append((source, destination))
