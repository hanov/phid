"""Observed permission deltas and key-sharing context across scans."""
from .privacy import fingerprint, sensitive
from .storage import now


def detect(resources, principals, previous_principals, previous_resources, config):
    findings = []
    old = {p['id']: p for p in previous_principals}
    prior_resources = {r['id']: r for r in previous_resources}
    for p in principals:
        previous = old.get(p['id'])
        if not previous or 'candidateResources' not in previous:
            continue
        gained = set(p.get('candidateResources', [])) - set(previous['candidateResources'])
        for resource in resources:
            if resource['id'] not in gained or not sensitive(resource):
                continue
            findings.append({'id': 'finding-' + fingerprint([p['id'], resource['id'], 'new_access'])[:20], 'resourceId': resource['id'], 'resource': resource['arn'], 'classification': resource['classification'], 'type': 'NEW_SENSITIVE_PERMISSION', 'title': 'Principal gained candidate sensitive-data access since prior observation', 'severity': 'MEDIUM', 'assessment': 'configuration_risk', 'status': 'OPEN', 'createdAt': now(), 'updatedAt': now(), 'evidence': p.get('evidence', []) + previous.get('evidence', []), 'identity': p['arn'], 'recommendations': ['Review the permission change and operational need. Effective authorization requires full policy evaluation.']})
    for key in [r for r in resources if r['type'] == 'KMS']:
        protected = [r for r in resources if r.get('encryption', {}).get('keyId') in [key['arn'], key['name']] and sensitive(r)]
        previous = prior_resources.get(key['id'])
        new_grants = []
        if previous:
            previous_grants = {fingerprint(g) for g in previous.get('grants', [])}
            new_grants = [g for g in key.get('grants', []) if fingerprint(g) not in previous_grants and 'Decrypt' in g.get('Operations', [])]
        if new_grants or len(protected) > config.get('max_resources_per_key', 20):
            for resource in protected:
                findings.append({'id': 'finding-' + fingerprint([resource['id'], key['id'], 'kms_scope'])[:20], 'resourceId': resource['id'], 'resource': resource['arn'], 'classification': resource['classification'], 'type': 'KMS_ACCESS_SCOPE_REVIEW', 'title': 'KMS decrypt grants or key reuse need review', 'severity': 'MEDIUM', 'assessment': 'configuration_risk', 'status': 'OPEN', 'createdAt': now(), 'updatedAt': now(), 'evidence': key.get('evidence', []) + resource.get('evidence', []), 'newDecryptGrants': new_grants, 'protectedResources': len(protected), 'recommendations': ['Validate decrypt-grant recipients and intended key-sharing boundaries.']})
    return findings
