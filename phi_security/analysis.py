import fnmatch
import ipaddress
import statistics
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from .privacy import sensitive, fingerprint
from .storage import now
from .events import unique_events, touches

READ_ACTIONS = ['s3:GetObject','dynamodb:GetItem','dynamodb:Query','dynamodb:Scan','rds-data:ExecuteStatement','kms:Decrypt','logs:GetLogEvents','logs:FilterLogEvents','secretsmanager:GetSecretValue']
READ_EVENTS = {'GetObject','GetItem','BatchGetItem','Query','Scan','ExecuteStatement','Select','GetRecords'}
RANK = {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3,'INFO':4,'UNKNOWN':5}

def array(value): return value if isinstance(value,list) else [value] if value is not None else []

def compute_risk_score(resource, events, principals, baselines_map):
    """Multi-factor privacy risk score 0–100 for a resource.

    Returns {'score': int, 'level': str, 'factors': list}.
    This is a heuristic model; the score does not establish confirmed exposure.
    """
    score = 0; factors = []
    # Data sensitivity contribution.
    sens = {'PHI_HIGH': 40, 'PHI': 30, 'CREDENTIAL': 30, 'FINANCIAL': 25, 'PII': 20, 'CONFIDENTIAL': 20}
    s = resource.get('sensitivityScore', sens.get(resource.get('classification', ''), 20 if sensitive(resource) else 0))
    if s:
        score += s; factors.append({'factor': 'data_sensitivity', 'value': resource.get('classification'), 'contribution': s})
    # Public exposure.
    if resource.get('publicAccess') is True:
        score += 25; factors.append({'factor': 'public_exposure', 'value': True, 'contribution': 25})
    # Missing encryption.
    if resource.get('encryption', {}).get('type') == 'none':
        score += 10; factors.append({'factor': 'unencrypted', 'value': True, 'contribution': 10})
    # Behavioral anomaly: any principal with candidate access to this resource.
    arn = resource.get('arn', '')
    for p in principals:
        if resource.get('id') not in p.get('candidateResources', []):
            continue
        b = baselines_map.get(p.get('id', ''))
        if not b or b.get('status') != 'ANOMALY':
            continue
        deviation = ((b.get('behaviors') or [{}])[0].get('deviation') or 1.0)
        contrib = min(20, max(0, int((deviation - 5) * 2)))
        if contrib > 0:
            score += contrib
            factors.append({'factor': 'behavior_deviation', 'value': f'{deviation:.1f}x historical mean', 'contribution': contrib, 'principal': p.get('arn')})
    score = min(100, score)
    level = 'CRITICAL' if score >= 80 else 'HIGH' if score >= 60 else 'MEDIUM' if score >= 40 else 'LOW' if score >= 20 else 'INFO'
    return {'score': score, 'level': level, 'factors': factors}
def statements(policy): return array((policy or {}).get('Statement'))
def matches(pattern, value): return fnmatch.fnmatchcase(value.lower(),str(pattern).lower())

def permissions(principal, resources, config):
    entries=[]; allowed=[]
    for policy in principal.get('policies',[]):
        for stmt in statements(policy):
            for action in array(stmt.get('Action')):
                for resource in array(stmt.get('Resource')):
                    entries.append({'action':action,'resource':resource,'effect':stmt.get('Effect'),'condition':stmt.get('Condition'),'note':'Broad permission; review operational need' if '*' in action or resource=='*' else None})
    # Candidate access only: SCPs, session policies, boundaries and resource denies may restrict it.
    for r in resources:
        service = r['arn'].split(':')[2]
        possible = [a for a in READ_ACTIONS if a.split(':')[0] == service or service == 'rds' and a.startswith('rds-data:')]
        for action in possible:
            def resource_match(pattern):
                return fnmatch.fnmatchcase(r['arn'], str(pattern)) or fnmatch.fnmatchcase(r['arn'] + '/example-object', str(pattern))
            allows = any(stmt['effect'] == 'Allow' and matches(stmt['action'], action) and resource_match(stmt['resource']) for stmt in entries)
            denies = any(stmt['effect'] == 'Deny' and not stmt['condition'] and matches(stmt['action'], action) and resource_match(stmt['resource']) for stmt in entries)
            if allows and not denies:
                allowed.append(r['id'])
    principal['permissions']=entries
    principal['candidateResources']=sorted(set(allowed))
    principal['accessByCapability'] = {}
    capabilities = {'write': ['s3:PutObject', 'dynamodb:PutItem', 'dynamodb:UpdateItem'],
                    'export': ['rds:StartExportTask', 'dynamodb:ExportTableToPointInTime', 's3:GetObject'],
                    'decrypt': ['kms:Decrypt'], 'query': ['dynamodb:Query', 'dynamodb:Scan', 'rds-data:ExecuteStatement']}
    for capability, actions in capabilities.items():
        principal['accessByCapability'][capability] = sorted({r['id'] for r in resources for stmt in entries if stmt['effect'] == 'Allow' and any(matches(stmt['action'], a) and (a.split(':')[0] == r['arn'].split(':')[2] or a.startswith('rds-data:') and r['arn'].split(':')[2] == 'rds') for a in actions) and (matches(stmt['resource'], r['arn']) or matches(stmt['resource'], r['arn'] + '/example-object'))})
    principal['canAccessPhi']=any(r['id'] in allowed and r['classification'].startswith('PHI') for r in resources)
    expected=config.get('expected_access',{}).get(principal['arn'])
    principal['hasExcessiveAccess']=bool(expected is not None and any(r['id'] in allowed and not any(matches(x,r['arn']) for x in expected) for r in resources))
    principal['accessAssessment']='candidate_identity_policy_access_not_effective_authorization'
    principal['crossAccountTrust']=[]
    for stmt in statements(principal.get('trustPolicy')):
        if stmt.get('Effect')!='Allow':continue
        principals=stmt.get('Principal',{})
        accounts=array(principals.get('AWS')) if isinstance(principals,dict) else array(principals)
        for target in accounts:
            own=principal['arn'].split(':')[4]
            if target=='*' or (target.startswith('arn:') and target.split(':')[4]!=own) or (target.isdigit() and target!=own):
                principal['crossAccountTrust'].append({'principal':target,'conditions':stmt.get('Condition',{}),'assessment':'potential_trust_subject_to_conditions'})
    principal['riskLevel']='HIGH' if principal['hasExcessiveAccess'] else 'MEDIUM' if principal['canAccessPhi'] and any(e['note'] for e in entries) else 'LOW'
    return principal


def baseline(events, principals, config, at=None):
    events = unique_events(events)
    at=at or datetime.now(timezone.utc)
    boundary=at-timedelta(hours=24); oldest=at-timedelta(days=config['baseline_days'])
    results=[]
    for p in principals:
        selected=[e for e in events if e.get('identity')==p['arn'] and e.get('source')=='cloudtrail' and e.get('successful') and e.get('eventType') in READ_EVENTS]
        daily=defaultdict(int); current=[]; historical=[]
        for e in selected:
            try:t=datetime.fromisoformat(e['timestamp'].replace('Z','+00:00'))
            except (ValueError,TypeError):continue
            if t>at or t<oldest:continue
            if t>=boundary:current.append(e)
            else:daily[t.date().isoformat()]+=1;historical.append(e)
        enough=len(daily)>=config['min_baseline_days']
        mean=statistics.mean(daily.values()) if daily else None
        deviation=(len(current)/mean) if mean else None
        anomalous=bool(enough and len(current)>=config['bulk_threshold'] and deviation>=5)
        score=min(100,round((deviation or 0)*10)) if anomalous else 0
        b={'id':p['id'],'principalId':p['id'],'principalArn':p['arn'],'principalName':p['name'],'status':'ANOMALY' if anomalous else 'NORMAL' if enough else 'INSUFFICIENT_HISTORY','calculatedFrom':oldest.isoformat(),'calculatedTo':at.isoformat(),'observedDays':len(daily),'dailyMean':mean,'currentCount':len(current),'currentAnomalyScore':score,'anomalyThreshold':50,'behaviors':[{'action':'sensitive_data_reads','normal':mean,'current':len(current),'deviation':deviation,'anomaly':anomalous}],'evidence':[e['id'] for e in current],'coverageNote':'Based on collected events only; missing days are not assumed to have zero activity.'}
        b['observedDimensions'] = {field: sorted({str(e[field]) for e in historical if e.get(field)}) for field in ['eventType', 'resource', 'region', 'sourceIp', 'objectPrefix']}
        b['currentDimensions'] = {field: sorted({str(e[field]) for e in current if e.get(field)}) for field in ['eventType', 'resource', 'region', 'sourceIp', 'objectPrefix']}
        b['newDimensions'] = {field: sorted(set(b['currentDimensions'][field]) - set(b['observedDimensions'][field])) if enough else [] for field in b['observedDimensions']}
        results.append(b)
    return results


def analyze(resources, principals, evidence, config, previous_findings=(), prior_incidents=()):
    evidence = unique_events(evidence)
    findings=[]; incidents=[]; evmap={e['id']:e for e in evidence}
    old={f['id']:f for f in previous_findings}; old_inc={i['id']:i for i in prior_incidents}
    def finding(r, kind, severity, title, refs, assessment='configuration_risk', detail=None):
        identifier='finding-'+fingerprint([r['id'],kind])[:20]
        row={'id':identifier,'resourceId':r['id'],'resource':r['arn'],'classification':r['classification'],'type':kind,'severity':severity,'title':title,'description':detail or title,'assessment':assessment,'status':'OPEN','evidence':list(dict.fromkeys(refs)),'createdAt':old.get(identifier,{}).get('createdAt',now()),'updatedAt':now(),'recommendations':['Review source evidence and intended access with the resource owner. No remediation was performed.']}
        findings.append(row)
        row['evidenceObservedAt']=max((evmap[x].get('timestamp','') for x in refs if x in evmap),default=None)
        row['classificationBasis']=r.get('classificationBasis','unknown')
        if RANK[severity]<RANK.get(r['riskLevel'],5):r['riskLevel']=severity
        return row
    def incident(f, title):
        identifier='INC-'+fingerprint(f['id'])[:16]
        prior=old_inc.get(identifier,{})
        timeline=[{'time':evmap[x].get('timestamp'),'event':evmap[x].get('eventType'),'evidenceId':x} for x in f['evidence'] if x in evmap]
        item={'id':identifier,'title':title,'status':prior.get('status','OPEN'),'severity':f['severity'],'classification':f['classification'],'assessment':f['assessment'],'confidence':None,'createdAt':prior.get('createdAt',now()),'updatedAt':now(),'resources':[f['resourceId']],'evidence':f['evidence'],'timeline':sorted(timeline,key=lambda t:t['time'] or ''),'notes':prior.get('notes',[]),'estimatedRecordsAffected':None,'affectedDataTypes':[],'recommendations':f['recommendations'],'conclusion':'Human investigation required. Pattern detections and anomalies do not establish unauthorized access or a legal breach.'}
        source_count = len({evmap[x].get('source') for x in f['evidence'] if x in evmap})
        confidence = min(1.0, source_count / 3)
        item['confidence'] = {'score': confidence, 'basis': 'source_diversity', 'meaning': 'Evidence corroboration heuristic, not probability of breach or unauthorized access'}
        if confidence >= config.get('minimum_incident_confidence', 0):
            incidents.append(item);f['incidentId']=identifier
    for r in resources:
        if not sensitive(r):continue
        confirmed=r.get('classificationBasis') not in ['name_heuristic_unconfirmed','unknown']
        if r.get('publicAccess') is True:
            finding(r,'PUBLIC_SENSITIVE_DATA','CRITICAL' if confirmed else 'HIGH','Public access configuration on a sensitive-data candidate',r['evidence'],detail='Public configuration observed; data classification basis: '+r.get('classificationBasis','unknown')+'. Actual external access is not established.')
        if r.get('encryption',{}).get('type')=='none':finding(r,'UNENCRYPTED_SENSITIVE_DATA','HIGH','Sensitive-data store lacks encryption',r['evidence'])
        environment=str(r.get('tags',{}).get('Environment',r.get('tags',{}).get('environment',r['name']))).lower()
        if any(word in environment.split('-') for word in ['dev','test','staging','qa','sandbox']):
            finding(r,'SENSITIVE_NON_PRODUCTION','MEDIUM','Sensitive-data candidate in a non-production environment',r['evidence'],detail='Validate whether this contains real or synthetic data; production provenance is not established.')
        leaks=[e for e in evidence if e.get('resourceId')==r['id'] and e.get('eventType')=='SensitiveLogEntry' and set(e.get('detectedTypes',[])) - {'IP_ADDRESS'}]
        if leaks:
            f=finding(r,'SENSITIVE_DATA_IN_LOGS','HIGH','Sensitive patterns detected in application logs',[e['id'] for e in leaks],'privacy_finding')
            f.update(logGroup=r['name'],matchCount=len(leaks),detectedTypes=sorted({t for e in leaks for t in e['detectedTypes']}),firstDetected=min(e['timestamp'] for e in leaks),lastDetected=max(e['timestamp'] for e in leaks))
            incident(f,'Review sensitive data logged by '+r['name'])
        for stmt in statements(r.get('policy')):
            if stmt.get('Effect')!='Allow':continue
            principal=stmt.get('Principal',{})
            targets=array(principal.get('AWS')) if isinstance(principal,dict) else array(principal)
            external=[p for p in targets if p=='*' or (isinstance(p,str) and p.startswith('arn:') and p.split(':')[4]!=r.get('account'))]
            if external:finding(r,'RESOURCE_POLICY_EXTERNAL_ACCESS','HIGH','Potential external access path in resource policy',r['evidence'],detail='Policy principals: '+str(external)+'. Conditions, explicit denies and organization controls require evaluation.')
        if r.get('sharedAccounts'):finding(r,'SHARED_SENSITIVE_BACKUP','HIGH','Sensitive backup shared with other accounts',r['evidence'])
        # Security group rules indicate potential reachability, not successful access.
        for sg in resources:
            if sg['type']=='SecurityGroup' and sg['name'] in r.get('securityGroups',[]):
                internet=any(any(x.get('CidrIp')=='0.0.0.0/0' for x in rule.get('IpRanges',[])) or any(x.get('CidrIpv6')=='::/0' for x in rule.get('Ipv6Ranges',[])) for rule in sg.get('ingress',[]))
                if internet:finding(r,'OPEN_SECURITY_GROUP','HIGH','Sensitive resource attached to an Internet-wide ingress rule',r['evidence']+sg['evidence'])
    for p in principals:
        permissions(p,resources,config)
        p['resourcesAccessed']=sorted({r['id'] for r in resources for e in evidence if e.get('identity')==p['arn'] and e.get('resource') and touches(e,r['arn']) and e.get('successful')})
        for r in resources:
            if sensitive(r) and r['id'] in p['candidateResources']:
                if p.get('mfaEnabled') is False and p.get('type') == 'User':finding(r,'MFA_ACCESS_GAP_'+p['id'],'MEDIUM','IAM user with candidate sensitive access has no registered MFA device',p['evidence']+r['evidence'])
                if p['hasExcessiveAccess']:finding(r,'EXCESSIVE_ACCESS_'+p['id'],'HIGH','Candidate permissions exceed configured access expectations',p['evidence']+r['evidence'])
                if p['crossAccountTrust']:finding(r,'CROSS_ACCOUNT_'+p['id'],'HIGH','External trust may permit sensitive-data access',p['evidence']+r['evidence'])
    baselines=baseline(evidence,principals,config)
    for b in baselines:
        if b['status']!='ANOMALY':continue
        for r in resources:
            refs=[x for x in b['evidence'] if evmap[x].get('resource') and touches(evmap[x],r['arn'])]
            from .behavior import approved
            refs = [ref for ref in refs if not approved(evmap[ref], r, config)]
            if sensitive(r) and refs:
                f=finding(r,'BULK_ACCESS_'+b['principalId'],'HIGH','Sensitive-data reads exceed observed historical baseline',refs,'security_anomaly')
                incident(f,'Unusual sensitive-data access by '+b['principalName'])
    for e in evidence:
        for r in resources:
            if e.get('resource')!=r['arn'] or not sensitive(r):continue
            if e['source']=='accessanalyzer' and e.get('status')=='ACTIVE':finding(r,'ACCESS_ANALYZER_EXTERNAL','HIGH','Access Analyzer reports external access',r['evidence']+[e['id']])
            if e['source']=='securityhub' and e.get('recordState')=='ACTIVE':finding(r,'SECURITY_HUB_CONTROL','MEDIUM','Security Hub finding affects sensitive-data candidate',r['evidence']+[e['id']])
    from .correlation import correlate
    correlated=correlate(resources,evidence,config)
    for f in correlated:
        f['createdAt']=old.get(f['id'],{}).get('createdAt',f['createdAt'])
        findings.append(f)
        incident(f,f['title'])
    from .behavior import detect as detect_behavior
    for f in detect_behavior(resources, evidence, principals, config):
        f['createdAt'] = old.get(f['id'], {}).get('createdAt', f['createdAt'])
        findings.append(f)
        if f['assessment'] != 'configuration_risk' and f['severity'] in ['CRITICAL', 'HIGH']:
            incident(f, f['title'])
    switches = config.get('detectors', {})
    def enabled(finding):
        kind = finding['type']
        flag = 'data_exfiltration_detection' if kind == 'POSSIBLE_EXFILTRATION' else 'bulk_access_detection' if kind.startswith('BULK_') else 'unusual_identity_detection' if kind == 'UNEXPECTED_SENSITIVE_ACCESS' else 'log_phi_detection' if kind in ['SENSITIVE_DATA_IN_LOGS', 'SENSITIVE_HTTP_PAYLOAD_LOGGING'] else kind
        return switches.get(flag, True) and switches.get(kind, True)
    findings = [f for f in findings if enabled(f)]
    active_incident_ids = {f.get('incidentId') for f in findings}
    incidents = [i for i in incidents if i['id'] in active_incident_ids]
    # Attach a multi-factor risk score to every resource for richer API responses.
    baselines_map={b['principalId']:b for b in baselines}
    for r in resources:
        r['riskScore']=compute_risk_score(r,evidence,principals,baselines_map)
        relevant = [f for f in findings if f['resourceId'] == r['id']]
        for f in relevant:
            if f['assessment'] in ['possible_exfiltration', 'suspected_exposure', 'security_anomaly']:
                r['riskScore']['factors'].append({'factor': f['type'].lower(), 'contribution': 10, 'evidence': f['evidence']})
                r['riskScore']['score'] = min(100, r['riskScore']['score'] + 10)
        score = r['riskScore']['score']
        r['riskScore']['level'] = 'CRITICAL' if score >= 80 else 'HIGH' if score >= 60 else 'MEDIUM' if score >= 40 else 'LOW' if score >= 20 else 'INFO'
        r['riskLevel'] = min([f['severity'] for f in relevant], key=lambda level: RANK[level]) if relevant else r['riskScore']['level']
    # Stable IDs deduplicate repeated scans and policy statements.
    return list({f['id']:f for f in findings}.values()),list({i['id']:i for i in incidents}.values()),baselines
