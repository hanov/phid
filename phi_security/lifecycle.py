"""Conservative scoped reconciliation: absence is meaningful only with coverage."""
from .storage import now

CONFIGURATION_TYPES = {'PUBLIC_SENSITIVE_DATA', 'UNENCRYPTED_SENSITIVE_DATA',
                       'SENSITIVE_NON_PRODUCTION', 'RESOURCE_POLICY_EXTERNAL_ACCESS',
                       'SHARED_SENSITIVE_BACKUP', 'OPEN_SECURITY_GROUP'}


def reconcile(store, findings, collected, coverage):
    current = {f['id'] for f in findings}
    observed = {r['id'] for r in collected}
    # A limit, denial or missing telemetry must never cause resolution.
    complete = bool(coverage) and all(c.get('status') == 'COLLECTED' for c in coverage)
    if not complete:
        return []
    resolved = []
    for old in store.all('findings'):
        if old['id'] in current or old.get('resourceId') not in observed or old.get('status') == 'RESOLVED':
            continue
        if old.get('type') not in CONFIGURATION_TYPES:
            continue  # historical behavioral events do not become false on a later scan
        old.update(status='RESOLVED', resolvedAt=now(), updatedAt=now(), resolution='Condition absent in a complete scoped rescan')
        store.put('findings', old)
        resolved.append(old['id'])
    return resolved
