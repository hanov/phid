"""Opt-in bounded content discovery and expanded configuration telemetry."""
import json
import re
from datetime import datetime, timezone
from .privacy import detect, fingerprint, merge_classification, safe
from .detection import schema_type


def objects(collector, bucket):
    config, aws = collector.config, collector.aws
    if not config.get('object_metadata'):
        return
    for prefix in config.get('object_prefixes', {}).get(bucket['name'], ['']):
        for item in aws.pages('s3', 'list_objects_v2', bucket['region'], 'Contents', Bucket=bucket['name'], Prefix=prefix, MaxKeys=min(config['max_resources'], 1000)):
            key = item['Key']
            evidence = collector.evidence_item('s3-metadata', 'ObjectObserved', bucket['arn'] + '/' + key,
                reference=bucket['arn'] + '/' + key + ':' + str(item.get('LastModified')), bucket=bucket['name'],
                objectPrefix=key.rsplit('/', 1)[0] if '/' in key else '', size=item.get('Size'),
                lastModified=str(item.get('LastModified')), storageClass=item.get('StorageClass'))
            collector.edge(bucket['arn'], bucket['arn'] + '/' + key, 'contains_object', [evidence])


def database_samples(collector, region):
    """DynamoDB samples use an explicit allowlist of table targets and small limits."""
    for target in collector.config.get('db_samples', []):
        if target.get('region') != region:
            continue
        if target.get('service') in ['postgresql', 'redshift']:
            continue
        if target.get('service') != 'dynamodb':
            collector.aws.coverage.append({'service': target.get('service'), 'status': 'UNSUPPORTED_SAMPLE', 'region': region})
            continue
        response = collector.aws.call('dynamodb', 'scan', region, TableName=target['table'], Limit=target.get('limit', 5), ConsistentRead=False)
        if response is None:
            continue
        for row in response.get('Items', []):
            result = detect(json.dumps(row), collector.config['custom_patterns'], collector.config.get('pattern_classifications'))
            for r in collector.resources:
                if r['type'] == 'DynamoDB' and r['name'] == target['table']:
                    merge_classification(r, result['classification'], result['detectedTypes'], 'database_sample', collector.config)
                    r['evidence'].append(collector.evidence_item('database-sample', 'SensitiveSample', r['arn'], reference=fingerprint(row), detectedTypes=result['detectedTypes'], contentHash=fingerprint(row), classification=result['classification']))

    from .database import postgres_samples
    postgres_samples(collector, region)


METRICS = {
    'EC2': [('AWS/EC2', 'NetworkOut', 'InstanceId'), ('AWS/EC2', 'NetworkPacketsOut', 'InstanceId')],
    'RDS': [('AWS/RDS', 'DatabaseConnections', 'DBInstanceIdentifier')],
    'Lambda': [('AWS/Lambda', 'Invocations', 'FunctionName')],
    'DynamoDB': [('AWS/DynamoDB', 'ConsumedReadCapacityUnits', 'TableName')],
    'S3': [('AWS/S3', 'GetRequests', 'BucketName')],
    'OpenSearch': [('AWS/ES', 'SearchRate', 'DomainName')],
    'LoadBalancer': [('AWS/ApplicationELB', 'RequestCount', 'LoadBalancer')],
    'APIGateway': [('AWS/ApiGateway', 'Count', 'ApiName')],
}


def metrics(collector, region):
    for r in collector.resources:
        if r['region'] != region:
            continue
        for namespace, metric, dimension in METRICS.get(r['type'], []):
            value = r['arn'].split(':loadbalancer/')[-1] if dimension == 'LoadBalancer' else r['name']
            dimensions = [{'Name': dimension, 'Value': value}]
            if r['type'] == 'S3':
                dimensions.append({'Name': 'FilterId', 'Value': 'EntireBucket'})
            if r['type'] == 'OpenSearch':
                dimensions.append({'Name': 'ClientId', 'Value': collector.account})
            response = collector.aws.call('cloudwatch', 'get_metric_statistics', region, Namespace=namespace, MetricName=metric, Dimensions=dimensions, StartTime=collector.start, EndTime=collector.end, Period=3600, Statistics=['Sum'])
            if response:
                collector.evidence_item('cloudwatch-metrics', metric, r['arn'], namespace=namespace, dimensions=dimensions, datapoints=response.get('Datapoints', []))
                if not response.get('Datapoints'):
                    collector.aws.coverage.append({'service': 'cloudwatch', 'region': region, 'status': 'NO_DATAPOINTS', 'metric': metric, 'resource': r['arn']})


def config_history(collector, region, item):
    if not collector.config.get('config_history') or not item.get('resourceId') or not item.get('resourceType'):
        return
    history = collector.aws.pages('config', 'get_resource_config_history', region, 'configurationItems', resourceType=item['resourceType'], resourceId=item['resourceId'], earlierTime=collector.start, laterTime=collector.end, chronologicalOrder='Forward', limit=min(collector.config['max_resources'], 100))
    previous = None
    for record in history:
        try:
            value = json.loads(record.get('configuration') or '{}')
        except (ValueError, TypeError):
            continue
        changed = sorted(k for k in set(value) | set(previous or {}) if previous is not None and value.get(k) != previous.get(k))
        collector.evidence_item('config-history', 'ConfigurationChange', record.get('arn', item.get('arn')),
            timestamp=str(record.get('configurationItemCaptureTime')), reference=str(record.get('configurationStateId')) + item['resourceId'],
            changedFields=changed, configurationHash=fingerprint(value))
        previous = value


def ingest_log_objects(collector, region):
    """Read only explicitly named, bounded log objects; no bucket log sweep."""
    import shlex
    for target in collector.config.get('log_objects', []):
        if target['region'] != region:
            continue
        response = collector.aws.call('s3', 'get_object', region, Bucket=target['bucket'], Key=target['key'], Range='bytes=0-' + str(collector.config['sample_bytes'] - 1))
        if response is None:
            continue
        try:
            content = response['Body'].read(collector.config['sample_bytes']).decode('utf-8', errors='replace')
        finally:
            response['Body'].close()
        for line in content.splitlines():
            try:
                fields = shlex.split(line)
            except ValueError:
                continue
            ref = fingerprint([target['bucket'], target['key'], line])
            if target.get('format') == 'alb' and len(fields) >= 15:
                collector.evidence_item('alb-access', 'HTTPRequest', target.get('resource'), timestamp=fields[1], reference=ref, sourceIp=fields[3].rsplit(':', 1)[0], status=fields[8], bytesReceived=fields[10], bytesSent=fields[11], requestHash=fingerprint(fields[12]))
            elif target.get('format') == 's3-access' and len(fields) >= 10:
                collector.evidence_item('s3-access', fields[7], 'arn:aws:s3:::' + fields[1], reference=ref, sourceIp=fields[4], identity=fields[5], objectPrefix=fields[8].rsplit('/', 1)[0] if '/' in fields[8] else '', requestHash=fingerprint(fields[9]))
            else:
                result = detect(line, collector.config['custom_patterns'])
                if result['detectedTypes']:
                    collector.evidence_item('application-log', 'SensitiveLogEntry', target.get('resource'), reference=ref, classification=result['classification'], detectedTypes=result['detectedTypes'], contentHash=fingerprint(line))
