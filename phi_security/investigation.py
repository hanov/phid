"""Bounded evidence expansion and explicit counter-evidence review."""
from .behavior import approved, approved_ip, timestamp
from .events import canonical_resource, event_resources, touches, unique_events
from .analysis import READ_EVENTS
from .privacy import sensitive


def review(engine, params, initial):
    all_events = unique_events(engine.filtered(engine.all('evidence'), params.get('timeRange', {})))
    selected = {e['id']: e for e in unique_events(initial)}
    resources = engine.all('resources')
    steps = []
    queries = ['identity_sessions', 'resource_access', 'related_network', 'counter_evidence']
    plan = None
    if engine.config.get('llm', {}).get('provider', 'none') != 'none':
        from .llm import Router
        plan = Router(engine.config, engine.store).query('Plan a bounded review of supporting and disconfirming evidence.', list(selected.values()), role='fast')
        queries = list(dict.fromkeys(plan.get('queries', []) + queries))
    # The model can order these templates only; it cannot supply operations or commands.
    limit = engine.config.get('max_investigation_steps', 4)
    queries = [q for q in queries if q != 'counter_evidence'][:max(0, limit - 1)] + ['counter_evidence']
    queries = list(dict.fromkeys(queries))
    for query in queries:
        before = len(selected)
        identities = {e.get('identity') for e in selected.values()} - {None}
        sessions = {e.get('session') for e in selected.values()} - {None}
        arns = {r for e in selected.values() for r in event_resources(e)}
        ips = {e.get('sourceIp') for e in selected.values()} - {None}
        stamps = [timestamp(e.get('timestamp')) for e in selected.values()]
        stamps = [t for t in stamps if t]
        def nearby(e):
            t = timestamp(e.get('timestamp'))
            return bool(t and stamps and min(stamps).timestamp() - 900 <= t.timestamp() <= max(stamps).timestamp() + 900)
        for e in all_events:
            match = False
            if query == 'identity_sessions':
                match = bool(e.get('session') in sessions or e.get('identity') in identities) and nearby(e)
            elif query == 'resource_access':
                match = bool(set(event_resources(e)) & arns) and nearby(e)
            elif query == 'related_network':
                match = e.get('source') == 'vpc-flow' and e.get('sourceIp') in ips and nearby(e)
            elif query == 'counter_evidence':
                match = e.get('identity') in identities and e.get('successful') is False and nearby(e)
            if match:
                selected[e['id']] = e
        steps.append({'query': query, 'source': 'stored_evidence', 'newEvidence': len(selected) - before, 'totalEvidence': len(selected)})
    events = list(selected.values())
    reads = [e for e in events if e.get('source') == 'cloudtrail' and e.get('eventType') in READ_EVENTS and e.get('successful')]
    sensitive_reads = [e for e in reads if any(sensitive(r) and touches(e, r['arn']) for r in resources)]
    approved_reads = [e for e in sensitive_reads if any(touches(e, r['arn']) and approved(e, r, engine.config) for r in resources)]
    denied = [e['id'] for e in events if e.get('successful') is False]
    vpn = [e['id'] for e in reads if approved_ip(e.get('sourceIp'), engine.config)]
    correlated = [f for f in engine.all('findings') if set(f.get('evidence', [])) & set(selected) and f.get('status') != 'RESOLVED']
    exposure = [f for f in correlated if f.get('assessment') == 'possible_exfiltration']
    anomalous = [f for f in correlated if f.get('assessment') in ['security_anomaly', 'suspected_exposure']]
    if sensitive_reads and len(approved_reads) == len(sensitive_reads) and not exposure and not anomalous:
        disposition = 'confirmed_expected_behavior'
    elif exposure:
        disposition = 'possible_exfiltration'
    elif anomalous:
        disposition = 'human_investigation_required'
    elif not reads:
        disposition = 'suspicious_but_insufficient_evidence'
    else:
        disposition = 'human_investigation_required'
    sources = sorted({e['source'] for e in events})
    last = engine.store.meta('lastScan') or {}
    gaps = [c for c in last.get('coverage', []) if c.get('status') != 'COLLECTED']
    return {
        'events': events, 'steps': steps, 'disposition': disposition, 'plannerRunId': plan['id'] if plan else None,
        'supportingEvidence': [e['id'] for e in sensitive_reads],
        'contradictingEvidence': sorted(set(denied + vpn + [e['id'] for e in approved_reads])),
        'counterEvidenceNotes': ['Denied requests do not disprove other successful requests.', 'Approved networks do not by themselves establish business authorization.'],
        'expectedBehavior': [rule.get('reason', 'Configured approved activity') for rule in engine.config.get('approved_activity', []) if any(any(touches(e, r['arn']) and approved(e, r, engine.config) == rule for r in resources) for e in reads)],
        'observedBehavior': {'successfulReadEvents': len(reads), 'sensitiveReadEvents': len(sensitive_reads), 'identities': sorted({e['identity'] for e in reads if e.get('identity')})},
        'evidenceQuality': {'sources': sources, 'sourceCount': len(sources), 'coverageGaps': len(gaps), 'level': 'INSUFFICIENT' if not sensitive_reads else 'LIMITED' if gaps else 'CORROBORATED' if len(sources) >= 2 else 'SINGLE_SOURCE', 'notBreachProbability': True},
        'missingEvidence': ['Validate business authorization and destination ownership.', 'Event counts are not patient or affected-record counts.'] + (['Resolve telemetry coverage gaps.'] if gaps else []),
        'relatedFindings': [f['id'] for f in correlated],
    }
