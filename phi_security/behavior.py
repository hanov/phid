"""Evidence-based behavioral detections. Novelty requires observed history."""
from collections import defaultdict
from datetime import datetime, timedelta, timezone
import fnmatch
import ipaddress
import statistics

from .events import touches, unique_events
from .privacy import fingerprint, sensitive
from .storage import now

READS = {'GetObject', 'GetItem', 'BatchGetItem', 'Query', 'Scan', 'ExecuteStatement', 'Select', 'GetRecords'}


def timestamp(value):
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00'))
    except (ValueError, TypeError, AttributeError):
        return None


def approved(event, resource, config):
    for rule in config.get('approved_activity', []):
        start, end, when = timestamp(rule.get('from')), timestamp(rule.get('to')), timestamp(event.get('timestamp'))
        if not start or not end or not when or not start <= when <= end:
            continue
        if not fnmatch.fnmatchcase(event.get('identity') or '', rule.get('identity', '')):
            continue
        if fnmatch.fnmatchcase(resource.get('arn', ''), rule.get('resource', '')):
            return rule
    return None


def detect(resources, events, principals, config, at=None):
    at = at or datetime.now(timezone.utc)
    events = unique_events(events)
    boundary = at - timedelta(hours=24)
    oldest = at - timedelta(days=config['baseline_days'])
    valid = [(e, timestamp(e.get('timestamp'))) for e in events]
    historical = [e for e, t in valid if t and oldest <= t < boundary]
    recent = [e for e, t in valid if t and boundary <= t <= at]
    result = []

    def add(resource, kind, rows, description, severity='MEDIUM', assessment='security_anomaly', **extra):
        if not rows or not config.get('detectors', {}).get(kind, True):
            return
        result.append({'id': 'finding-' + fingerprint([resource['id'], kind, extra.get('identity')])[:20],
                       'resourceId': resource['id'], 'resource': resource['arn'], 'classification': resource['classification'],
                       'type': kind, 'title': description, 'description': description,
                       'severity': severity, 'assessment': assessment, 'status': 'OPEN',
                       'createdAt': now(), 'updatedAt': now(), 'evidence': sorted({e['id'] for e in rows}),
                       'recommendations': ['Validate business authorization and source evidence with the resource owner.'], **extra})

    for resource in resources:
        if not sensitive(resource):
            continue
        old = [e for e in historical if touches(e, resource['arn'])]
        current = [e for e in recent if touches(e, resource['arn'])]
        read = [e for e in current if e.get('eventType') in READS and e.get('successful') and not approved(e, resource, config)]
        past_reads = [e for e in old if e.get('eventType') in READS and e.get('successful')]
        enough = len({e['timestamp'][:10] for e in past_reads}) >= config['min_baseline_days']
        identities = {e.get('identity') for e in past_reads}
        if enough:
            by_identity = defaultdict(list)
            for e in read:
                by_identity[e.get('identity')].append(e)
            for identity, rows in by_identity.items():
                if not identity:
                    continue
                previous = [e for e in historical if e.get('identity') == identity and e.get('eventType') in READS and e.get('successful')]
                novelty = []
                if identity not in identities:
                    novelty.append('identity')
                for field in ['sourceIp', 'region', 'objectPrefix']:
                    seen = {e.get(field) for e in previous if e.get(field)}
                    changed = [e for e in rows if e.get(field) and e[field] not in seen]
                    if changed and seen:
                        if field == 'sourceIp':
                            changed = [e for e in changed if not approved_ip(e[field], config)]
                        if changed:
                            novelty.append(field)
                hours = config.get('expected_hours', {}).get(identity)
                if hours and any(timestamp(e['timestamp']).hour not in hours for e in rows):
                    novelty.append('outside_expected_hours_utc')
                new_actions = {e['eventType'] for e in rows} - {e['eventType'] for e in previous}
                if new_actions & {'Scan', 'GetObject'} and previous:
                    novelty.append('bulk_capable_action')
                # A new IP or identity alone is not an incident: require two independent signals.
                if len(novelty) >= 2:
                    add(resource, 'UNEXPECTED_SENSITIVE_ACCESS', rows, 'Sensitive access differs from observed identity behavior', 'HIGH', identity=identity, signals=novelty)
        presigned = [e for e in read if str(e.get('authenticationMethod', '')).lower() in ['querystring', 'query-string']]
        if presigned:
            add(resource, 'PRESIGNED_SENSITIVE_ACCESS', presigned, 'Sensitive object access used query-string authentication; verify sharing intent', 'MEDIUM', 'confirmed_access')
        for e in read:
            destination = e.get('destinationAccount')
            if destination and destination != resource.get('account') and destination not in config.get('trusted_accounts', []):
                add(resource, 'OBSERVED_CROSS_ACCOUNT_ACCESS', [e], 'Sensitive access references an unapproved destination account', 'HIGH', 'suspected_exposure', destinationAccount=destination, identity=e.get('identity'))
        prior_decrypt = [e for e in historical if e.get('eventType') == 'Decrypt' and e.get('successful')]
        decrypt = [e for e in current if e.get('eventType') == 'Decrypt' and e.get('successful')]
        if len(decrypt) >= config['bulk_threshold'] and len({e['timestamp'][:10] for e in prior_decrypt}) >= config['min_baseline_days']:
            mean = len(prior_decrypt) / len({e['timestamp'][:10] for e in prior_decrypt})
            if len(decrypt) >= 5 * mean:
                add(resource, 'DECRYPT_VOLUME_ANOMALY', decrypt, 'Decrypt activity exceeds observed daily history', 'HIGH', historicalMean=mean)
        for e in current:
            if e.get('source') == 'guardduty':
                add(resource, 'GUARDDUTY_SENSITIVE_CONTEXT', [e, *read], 'GuardDuty evidence affects an identity or resource with sensitive-data context', 'HIGH', 'suspected_exposure' if read else 'security_anomaly', observedReads=len(read))
            if e.get('source') == 'config-history' and e.get('changedFields'):
                add(resource, 'SENSITIVE_CONFIGURATION_CHANGE', [e], 'Sensitive resource configuration changed', 'MEDIUM', 'configuration_risk', changedFields=e['changedFields'])
            if e.get('source') == 'cloudwatch-metrics':
                points = sorted(e.get('datapoints', []), key=lambda p: str(p.get('Timestamp')))
                values = [p.get('Sum', p.get('Average', 0)) for p in points]
                if len(values) >= 8 and statistics.mean(values[:-1]) > 0 and values[-1] > statistics.mean(values[:-1]) * 5:
                    add(resource, 'METRIC_VOLUME_ANOMALY', [e], 'Resource metric exceeds preceding collected intervals', 'MEDIUM', metric=e.get('eventType'), deviation=values[-1] / statistics.mean(values[:-1]))
        leaks = [e for e in current if e.get('payloadLeak')]
        if leaks:
            add(resource, 'SENSITIVE_HTTP_PAYLOAD_LOGGING', leaks, 'Sensitive data detected in logged HTTP payloads', 'HIGH', 'privacy_finding', rootCauseCandidates=sorted({e.get('rootCauseCandidate', 'Payload logging') for e in leaks}))
        if resource.get('retentionDays') is None and resource.get('type') == 'CloudWatchLogs' or resource.get('retentionDays', 0) and resource.get('retentionDays', 0) > config.get('max_retention_days', 90):
            refs = [e for e in events if e['id'] in resource.get('evidence', [])]
            add(resource, 'SENSITIVE_RETENTION', refs, 'Sensitive log retention exceeds configured policy', 'MEDIUM', 'configuration_risk')
        created = timestamp(resource.get('createdAt'))
        if 'Snapshot' in resource.get('type', '') and created and (at - created).days > config.get('max_backup_age_days', 90):
            add(resource, 'OLD_SENSITIVE_BACKUP', [e for e in events if e['id'] in resource.get('evidence', [])], 'Sensitive backup exceeds configured age threshold', 'MEDIUM', 'configuration_risk')
    # Network novelty is attributed only through workload interfaces/IPs; not called exfiltration.
    for resource in resources:
        if not sensitive(resource):
            continue
        def belongs(e):
            return e.get('source') == 'vpc-flow' and e.get('action') == 'ACCEPT' and e.get('logStatus') == 'OK' and (e.get('resource') in resource.get('networkInterfaces', []) or bool(resource.get('privateIp')) and e.get('sourceIp') == resource.get('privateIp'))
        past = [e for e in historical if belongs(e)]
        current = [e for e in recent if belongs(e)]
        if len({e['timestamp'][:10] for e in past}) < config['min_baseline_days']:
            continue
        destinations = {e.get('destinationIp') for e in past}
        ports = {e.get('port') for e in past}
        for e in current:
            signals = []
            if e.get('destinationIp') not in destinations and not approved_ip(e.get('destinationIp'), config):
                signals.append('new_destination')
            if e.get('port') not in ports and e.get('port') not in config.get('approved_ports', [443, 80]):
                signals.append('unusual_port')
            baseline_bytes = statistics.mean([x.get('bytes', 0) for x in past])
            if e.get('bytes', 0) > max(1024 * 1024, baseline_bytes * 5):
                signals.append('unusual_bytes')
            enrich = config.get('network_enrichment', {})
            dest = enrich.get(e.get('destinationIp'), {})
            for key in ['asn', 'country', 'vpc']:
                known = {enrich.get(ip, {}).get(key) for ip in destinations} - {None}
                if dest.get(key) and known and dest[key] not in known:
                    signals.append('new_' + key)
            if len(signals) >= 2:
                add(resource, 'NETWORK_BEHAVIOR_ANOMALY', [e], 'Multiple network behavior changes on a sensitive workload', signals=signals)
    return result


def approved_ip(value, config):
    try:
        ip = ipaddress.ip_address(value)
        return any(ip in ipaddress.ip_network(cidr) for cidr in config.get('approved_cidrs', []))
    except ValueError:
        return False
