"""The sole AWS execution boundary. No prefix-based permissions or arbitrary SDK calls."""
import time
import boto3
from botocore.config import Config

ALLOW = {
 'sts': {'get_caller_identity'},
 'ec2': {'describe_regions','describe_instances','describe_security_groups','describe_flow_logs','describe_snapshots','describe_snapshot_attribute','describe_images','describe_volumes','describe_route_tables','describe_vpc_endpoints'},
 's3': {'list_buckets','get_bucket_location','get_bucket_tagging','get_bucket_encryption','get_bucket_policy','get_bucket_policy_status','get_public_access_block','get_bucket_acl','get_bucket_logging','get_bucket_versioning','get_bucket_replication','list_objects_v2','head_object','get_object'},
 's3control': {'get_public_access_block'},
 'rds': {'describe_db_instances','describe_db_clusters','describe_db_snapshots','describe_db_snapshot_attributes','list_tags_for_resource'},
 'docdb': {'describe_db_clusters','list_tags_for_resource'},
 'dynamodb': {'scan','list_tables','describe_table','list_tags_of_resource','describe_continuous_backups'},
 'redshift': {'describe_clusters','describe_cluster_snapshots'},
 'opensearch': {'list_domain_names','describe_domain'},
 'logs': {'describe_log_groups','filter_log_events'},
 'cloudtrail': {'lookup_events','describe_trails','get_event_selectors','get_trail_status'},
 'iam': {'get_account_authorization_details','list_mfa_devices','get_instance_profile'},
 'kms': {'list_keys','describe_key','get_key_policy','list_grants','list_aliases'},
 'macie2': {'list_findings','get_findings'},
 'guardduty': {'list_detectors','list_findings','get_findings'},
 'securityhub': {'get_findings'},
 'accessanalyzer': {'list_analyzers','list_findings'},
 'config': {'describe_configuration_recorders','select_resource_config','get_resource_config_history'},
 'lambda': {'list_functions'},
 'ecs': {'list_clusters','list_services','describe_services','describe_task_definition'},
 'eks': {'list_clusters','describe_cluster'},
 'apigateway': {'get_rest_apis','get_stages','get_resources','get_integration'},
 'elbv2': {'describe_load_balancers','describe_listeners','describe_target_groups','describe_target_health'},
 'cloudfront': {'list_distributions'},
 'backup': {'list_backup_vaults','list_recovery_points_by_backup_vault'},
 'glue': {'get_databases','get_tables'},
 'cloudwatch': {'get_metric_statistics'},
 'organizations': {'list_accounts'},
}

class AWS:
    def __init__(self, config, session=None):
        self.config = config
        self.session = session or boto3.Session(profile_name=config.get('profile'))
        self.clients = {}
        self.coverage = []
        self.deadline = time.monotonic() + config['max_scan_seconds']

    def client(self, service, region):
        key = (service, region)
        if key not in self.clients:
            self.clients[key] = self.session.client(service, region_name=region, config=Config(connect_timeout=5, read_timeout=15, retries={'max_attempts': 2, 'mode':'standard'}, ignore_configured_endpoint_urls=True))
        return self.clients[key]

    def call(self, service, operation, region, **kwargs):
        if operation not in ALLOW.get(service, set()): raise PermissionError('AWS operation not allowed')
        if operation == 'get_object':
            targets = self.config.get('sample_keys', [])
            log_targets = [{'bucket': t['bucket'], 'key': t['key']} for t in self.config.get('log_objects', [])]
            is_log = {'bucket':kwargs.get('Bucket'), 'key':kwargs.get('Key')} in log_targets
            if not is_log and (not self.config.get('sample_objects') or {'bucket':kwargs.get('Bucket'), 'key':kwargs.get('Key')} not in targets):
                raise PermissionError('Object sampling requires an explicit configured bucket/key')
            if kwargs.get('Range') != 'bytes=0-' + str(self.config['sample_bytes'] - 1): raise PermissionError('Unbounded object sampling prohibited')
        if service == 'dynamodb' and operation == 'scan':
            targets = self.config.get('db_samples', [])
            if not any(t.get('service') == 'dynamodb' and t.get('region') == region and t.get('table') == kwargs.get('TableName') and t.get('limit', 5) == kwargs.get('Limit') for t in targets) or not 1 <= kwargs.get('Limit', 0) <= 10:
                raise PermissionError('Database sampling requires an explicit table and limit of 1..10')
        if time.monotonic() > self.deadline:
            self.coverage.append({'service': service, 'operation': operation, 'region': region, 'status':'TIME_BUDGET_EXCEEDED'})
            return None
        try:
            result = getattr(self.client(service, region), operation)(**kwargs)
            self.coverage.append({'service':service, 'operation':operation, 'region':region, 'status':'COLLECTED'})
            return result
        except Exception as exc:
            code = getattr(exc, 'response', {}).get('Error', {}).get('Code', type(exc).__name__)
            self.coverage.append({'service':service,'operation':operation,'region':region,'status':str(code)})
            return None

    def pages(self, service, operation, region, result_key, item_limit=None, **kwargs):
        item_limit=item_limit or self.config['max_resources']
        items, seen = [], set()
        for _ in range(self.config['max_pages']):
            data = self.call(service, operation, region, **kwargs)
            if data is None: break
            values = data.get(result_key, [])
            if isinstance(values, list): items.extend(values)
            # AWS pagination parameter names vary by service/operation.
            token = data.get('NextToken') or data.get('nextToken') or data.get('next_token') or data.get('NextMarker') or (data.get('Marker') if data.get('IsTruncated') or service in ['rds','docdb','redshift'] else None) or data.get('LastEvaluatedTableName') or data.get('NextContinuationToken') or data.get('ContinuationToken') or data.get('position')
            if len(items) > item_limit or (len(items) == item_limit and token) or (token and token in seen):
                self.coverage.append({'service':service,'operation':operation,'region':region,'status':'TRUNCATED'})
                return items[:item_limit]
            if not token: return items
            seen.add(token)
            key = 'NextToken'
            if 'nextToken' in data: key = 'nextToken'
            elif 'next_token' in data: key = 'next_token'
            elif 'NextMarker' in data or service in ['iam','rds','docdb','redshift']: key = 'Marker'
            elif 'LastEvaluatedTableName' in data: key = 'ExclusiveStartTableName'
            elif 'position' in data: key = 'position'
            elif service == 's3': key = 'ContinuationToken'
            kwargs[key] = token
        if seen: self.coverage.append({'service':service,'operation':operation,'region':region,'status':'TRUNCATED'})
        return items[:item_limit]
