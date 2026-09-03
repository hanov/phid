"""Bounded autonomous triage; sampling opt-in is not repeated by default."""
from .privacy import fingerprint


def triage(engine, report):
    limit = engine.config.get('max_agent_investigations', 5)
    existing = {inv.get('triageFingerprint') for inv in engine.all('investigations')}
    investigations = []
    for finding in sorted(report.get('findings', []), key=lambda f: {'CRITICAL': 0, 'HIGH': 1}.get(f['severity'], 2)):
        if len(investigations) >= limit:
            break
        if finding['severity'] not in ['CRITICAL', 'HIGH'] or finding.get('assessment') == 'configuration_risk':
            continue
        signature = fingerprint([finding['id'], sorted(finding.get('evidence', []))])
        if signature in existing:
            continue
        result = engine.investigate({'trigger': finding['id'], 'refresh': False})
        item = engine.find('investigations', result['investigationId'])
        item['triageFingerprint'] = signature
        engine.store.put('investigations', item)
        engine.store.commit()
        existing.add(signature)
        investigations.append(item['id'])
    return investigations
