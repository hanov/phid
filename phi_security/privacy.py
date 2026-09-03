import hashlib
import ipaddress
import json
import re

PATTERNS = [
 ('AUTHORIZATION', r'(?i)\b(?:authorization|cookie|set-cookie)\s*[:=]\s*[^\r\n]+'),
 # Expanded keyword list covers common OAuth/API secret naming conventions.
 ('SECRET', r'(?i)\b(?:api[_-]?key|api[_-]?secret|client[_-]?secret|password|passwd|private[_-]?key|auth[_-]?token|refresh[_-]?token|access_token|session_token|x-api-key)\s*[\"\x27]?\s*[:=]\s*[\"\x27]?[^\s,\"\x27}]+'),
 ('AWS_ACCESS_KEY', r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'),
 ('JWT', r'\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b'),
 ('SSN', r'\b\d{3}-\d{2}-\d{4}\b'),
 ('EMAIL', r'[\w.%+-]+@[\w.-]+\.[a-zA-Z]{2,}'),
 ('DOB', r'(?i)\b(?:dob|date[ _]of[ _]birth|birth_date|birthdate)\s*[\"\x27]?\s*[:=]?\s*[\"\x27]?\d[\d/.-]+'),
 ('MRN', r'(?i)\b(?:mrn|medical[ _]record(?:[ _]number)?)\s*[\"\x27]?\s*[:=\-]?\s*[\"\x27]?[A-Z0-9]*\d[A-Z0-9-]*'),
 ('PATIENT_NAME', r'\b(?:[Pp]atient(?:[ _][Nn]ame)?|[Nn]ame)\s*[\"\x27]?\s*[:=]?\s*[\"\x27]?[A-Z][a-z]+\s+[A-Z][a-z]+\b'),
 # Health plan identifiers must be checked before the broad PHONE_NUMBER pattern
 # because policy numbers and member IDs may be all-digit strings.
 ('HEALTH_PLAN_ID', r'(?i)\b(?:member[_-]?id|policy[_-]?(?:no|number)|group[_-]?(?:no|number)|plan[_-]?id|subscriber[_-]?id)\s*[\"\x27]?\s*[:=]\s*[\"\x27]?[A-Z0-9]{4,20}\b'),
 # National Provider Identifier must also precede PHONE_NUMBER: a 10-digit NPI
 # would otherwise be consumed by the phone number pattern first.
 ('NPI', r'(?i)\b(?:npi|national[_-]?provider[_-]?(?:identifier|number|id|no))\s*[\"\x27]?\s*[:=\-]?\s*[\"\x27]?\d{10}\b'),
 ('CREDIT_CARD', r'\b(?:\d[ -]?){12,18}\d\b'),
 ('PHONE_NUMBER', r'(?:\+\d{1,3}[ .-]?)?(?:\(\d{3}\)|\b\d{3})[ .-]?\d{3}[ .-]?\d{4}\b'),
 ('IP_ADDRESS', r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
 ('IPV6', r'(?i)(?<![\w:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![\w:])'),
 ('PASSPORT', r'(?i)\bpassport(?:[ _]number)?\s*[\"\x27]?\s*[:=]\s*[\"\x27]?[A-Z0-9-]+'),
 ('DIAGNOSIS', r'(?i)\b(?:diagnosis|dx|medication|prescription|insurance_member_id|lab_result|address)\s*[\"\x27]?\s*[:=]\s*[\"\x27]?[^\r\n,\"}]+'),
]

def detect(text, custom=(), pattern_classifications=None):
    from .detection import structured_types, entropy_redact
    original = text
    types, count = structured_types(text), 0
    for name, pattern in PATTERNS + [(p['name'], p['regex']) for p in custom]:
        text, n = re.subn(pattern, '[' + name + '_REDACTED]', text)
        if n:
            types.append(name)
            count += n
    text, entropy_types = entropy_redact(text)
    types = sorted(set(types + entropy_types))
    count = max(count + len(entropy_types), len(types))
    # Structured fields may contain values not matched by regular expressions.
    # Redact the entire payload whenever schema detection adds sensitive types.
    if structured_types(original):
        text = '[STRUCTURED_SENSITIVE_PAYLOAD_REDACTED]'
    category = classify(types)
    mapping = {p['name']: p['classification'] for p in custom if p.get('classification')}
    mapping.update(pattern_classifications or {})
    candidates = [category] + [mapping[t] for t in types if t in mapping]
    category = max(candidates, key=lambda label: SENSITIVITY.get(label, 40))
    return {'redacted': text, 'detectedTypes': types, 'count': count, 'classification': category}

def classify(types):
    if set(types) & {'AUTHORIZATION', 'SECRET', 'AWS_ACCESS_KEY', 'JWT', 'HIGH_ENTROPY_SECRET'}: return 'CREDENTIAL'
    if set(types) & {'MRN', 'DIAGNOSIS', 'HEALTH_PLAN_ID', 'TREATMENT', 'MEDICATION', 'LAB_RESULT', 'IMAGING', 'APPOINTMENT'}: return 'PHI_HIGH'
    if set(types) & {'PATIENT_NAME', 'NPI'}: return 'PHI'
    if 'CREDIT_CARD' in types: return 'FINANCIAL'
    if types: return 'PII'
    return 'UNCLASSIFIED'

def safe(value):
    if isinstance(value, str): return detect(value)['redacted']
    if isinstance(value, list): return [safe(x) for x in value]
    if isinstance(value, dict):
        return {str(k): ('[REDACTED]' if re.fullmatch(r'(?i)(password|secret|token|authorization|cookie|patient_name|ssn|dob|email|phone|address)', str(k)) else safe(v)) for k, v in value.items()}
    return value

def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()

def sensitive(resource):
    return resource.get('isSensitive',False) or resource.get('classification') in {'PHI', 'PHI_HIGH', 'PII', 'FINANCIAL', 'CREDENTIAL', 'SECRET', 'CONFIDENTIAL'}

def metadata_classification(name, tags, config):
    override = config.get('classification_overrides', {}).get(name)
    if override: return override, [], 'configured'
    for key, value in tags.items():
        if key.lower() in ['classification', 'data-classification', 'sensitivity'] and value.upper() in {'PHI','PHI_HIGH','PII','FINANCIAL','CREDENTIAL','SECRET','PUBLIC','INTERNAL','CONFIDENTIAL'} | set(config.get('classification_taxonomy',{})):
            return value.upper(), [], 'tag'
    words = str(name).lower()
    if re.search(r'patient|medical|health|diagnos|\bmrn\b|\behr\b|\bphi\b|\bhipaa\b|clinical', words): return 'PHI', [], 'name_heuristic_unconfirmed'
    if re.search(r'customer|employee|payroll|billing|personal-data|\bpii\b', words): return 'PII', [], 'name_heuristic_unconfirmed'
    return 'UNCLASSIFIED', [], 'unknown'


SENSITIVITY = {'UNCLASSIFIED': 0, 'PUBLIC': 0, 'INTERNAL': 5, 'CONFIDENTIAL': 20,
               'PII': 20, 'FINANCIAL': 25, 'PHI': 30, 'SECRET': 35, 'CREDENTIAL': 35, 'PHI_HIGH': 40}


def merge_classification(resource, category, types, basis, config):
    """Never lose a stronger classification when a later sample has weaker data."""
    taxonomy = config.get('classification_taxonomy', {})
    def score(label):
        return taxonomy.get(label, {}).get('sensitivity', SENSITIVITY.get(label, 20))
    current = resource.get('classification', 'UNCLASSIFIED')
    if score(category) >= score(current):
        resource.update(classification=category, classificationBasis=basis)
    resource['classifications'] = sorted(set(resource.get('classifications', [current]) + [category]))
    resource['detectedTypes'] = sorted(set(resource.get('detectedTypes', []) + list(types)))
    resource['isSensitive'] = sensitive(resource) or taxonomy.get(category, {}).get('sensitive', False)
    resource['sensitivityScore'] = score(resource['classification'])


def storage_safe(value):
    """Drop raw payload/secret fields while preserving identifiers needed for joins."""
    blocked = {'rawmessage', 'raw_message', 'rawpayload', 'raw_payload', 'requestbody',
               'request_body', 'responsebody', 'response_body', 'password', 'secret',
               'secretaccesskey', 'sessiontoken', 'authorization', 'cookie', 'patient_name',
               'ssn', 'dob', 'email', 'phone', 'credentials', 'access_token', 'refresh_token'}
    if isinstance(value, dict):
        return {k: '[REDACTED]' if str(k).lower() in blocked else storage_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [storage_safe(item) for item in value]
    return value
