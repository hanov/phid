import copy
import re
import json
import os
from pathlib import Path

DEFAULT = {
    'regions': ['us-east-1'], 'max_pages': 5, 'max_resources': 100,
    'lookback_hours': 24, 'max_log_events': 1000, 'scan_logs': True,
    'sample_objects': False, 'sample_bytes': 8192, 'sample_keys': [],
    'log_groups': [], 'cloudtrail_log_groups': [], 'flow_log_groups': [],
    'trusted_accounts': [], 'approved_cidrs': [], 'expected_access': {},
    'custom_patterns': [], 'classification_overrides': {},
    'bulk_threshold': 1000, 'baseline_days': 30, 'min_baseline_days': 7,
    'retention_days': 90, 'max_scan_seconds': 600,
    'classification_taxonomy': {},
    'llm': {'provider': 'none', 'models': {}, 'allow_remote': False, 'timeout': 120,
            'base_url': 'http://127.0.0.1:11434', 'max_context_records': 100},
    'detectors': {}, 'approved_activity': [], 'expected_hours': {},
    'network_enrichment': {}, 'approved_ports': [443, 80],
    'third_parties': {}, 'max_resources_per_key': 20, 'max_retention_days': 90, 'max_backup_age_days': 90,
    'minimum_incident_confidence': 0.0, 'max_investigation_steps': 4, 'max_agent_investigations': 5,
    'log_objects': [], 'object_metadata': False, 'object_prefixes': {}, 'db_samples': [],
    'config_history': False, 'organizations': False,
    'metrics': [], 'agent_interval': 300, 'sample_every_cycle': False,
    'pattern_classifications': {}, 'nlp_model': None,

}

def load(config_path=None, db_path=None):
    config = copy.deepcopy(DEFAULT)
    config_path = config_path or os.environ.get('PHI_CONFIG')
    if config_path:
        raw = Path(config_path).read_text()
        if str(config_path).endswith(('.yaml', '.yml')):
            import yaml
            values = yaml.safe_load(raw)
        else:
            values = json.loads(raw)
        if not isinstance(values, dict):
            raise ValueError('Configuration must be an object')
        config.update(normalize(values))
        config['llm'] = {**DEFAULT['llm'], **config.get('llm', {})}
    if os.environ.get('AWS_REGIONS'):
        config['regions'] = os.environ['AWS_REGIONS'].split(',')
    elif os.environ.get('AWS_REGION') or os.environ.get('AWS_DEFAULT_REGION'):
        config['regions'] = [os.environ.get('AWS_REGION') or os.environ['AWS_DEFAULT_REGION']]
    if config.get('detectors', {}).get('log_phi_detection') is False:
        config['scan_logs'] = False
    config['db'] = db_path or os.environ.get('PHI_DB') or config.get('db', 'data/phi-security.db')
    for key in ['max_pages', 'max_resources', 'lookback_hours', 'max_log_events', 'sample_bytes', 'max_scan_seconds', 'retention_days']:
        if not isinstance(config[key], int) or not 1 <= config[key] <= 100000:
            raise ValueError('Invalid configuration: ' + key)
    if config['sample_bytes'] > 65536:
        raise ValueError('sample_bytes must not exceed 65536')
    if not isinstance(config['regions'], list) or not config['regions']:
        raise ValueError('regions must be a non-empty list')
    validate(config)
    return config


def normalize(values):
    """Accept flat JSON or the documented nested YAML structure."""
    result = {k: v for k, v in values.items() if k not in ['aws', 'privacy', 'detection', 'agent', 'storage', 'classification']}
    aws = values.get('aws', {})
    result.update({k: aws[k] for k in ['regions', 'profile'] if k in aws})
    storage = values.get('storage', {})
    if 'path' in storage:
        result['db'] = storage['path']
    detection = values.get('detection', {})
    result['detectors'] = {**result.get('detectors', {}), **detection}
    privacy = values.get('privacy', {})
    if privacy.get('allow_raw_phi_remote_llm') or privacy.get('allow_raw_pii_remote_llm'):
        raise ValueError('Raw sensitive-data transfer is not supported')
    if 'classification' in values:
        result['classification_taxonomy'] = values['classification']
    if 'custom_patterns' in values.get('sensitive_data', {}):
        result['custom_patterns'] = values['sensitive_data']['custom_patterns']
    agent = values.get('agent', {})
    if 'interval' in agent:
        result['agent_interval'] = agent['interval']
    if 'minimum_incident_confidence' in agent:
        result['minimum_incident_confidence'] = agent['minimum_incident_confidence']
    return result


def validate(config):
    for key in ['baseline_days', 'min_baseline_days', 'bulk_threshold', 'max_investigation_steps', 'max_agent_investigations', 'max_retention_days', 'max_backup_age_days']:
        if type(config[key]) is not int or config[key] < 1:
            raise ValueError('Invalid configuration: ' + key)
    if config['baseline_days'] > 90 or config['min_baseline_days'] > config['baseline_days']:
        raise ValueError('Invalid baseline window')
    for region in config['regions']:
        if not isinstance(region, str) or not re.fullmatch(r'[a-z]{2}(?:-gov)?-[a-z]+-\d', region):
            raise ValueError('Invalid region')
    for pattern in config['custom_patterns']:
        if not isinstance(pattern.get('name'), str) or len(pattern.get('regex', '')) > 2000:
            raise ValueError('Invalid custom pattern')
        re.compile(pattern['regex'])
    if not 30 <= config.get('agent_interval', 300) <= 86400:
        raise ValueError('Invalid agent interval')
    for target in config.get('db_samples', []):
        if target.get('service') not in ['dynamodb', 'postgresql', 'redshift'] or not target.get('table') or not target.get('region') or type(target.get('limit', 5)) is not int or not 1 <= target.get('limit', 5) <= 10:
            raise ValueError('Invalid database sampling target')
    if not 0 <= config.get('minimum_incident_confidence', 0) <= 1:
        raise ValueError('Invalid minimum incident evidence confidence')
    if config['llm'].get('allow_remote'):
        raise ValueError('Remote inference is prohibited')
    for rule in config.get('approved_activity', []):
        from .timeutil import parse_time
        if not rule.get('identity') or not rule.get('resource') or parse_time(rule['from']) >= parse_time(rule['to']):
            raise ValueError('Invalid approved activity window')
    for category, spec in config['classification_taxonomy'].items():
        if not isinstance(spec, dict) or not 0 <= spec.get('sensitivity', 20) <= 40:
            raise ValueError('Invalid classification taxonomy')
    if config['llm']['provider'] not in ['none', 'ollama', 'local']:
        raise ValueError('Unknown LLM provider')
    if not 1 <= config['llm']['timeout'] <= 300 or not 1 <= config['llm']['max_context_records'] <= 1000:
        raise ValueError('Invalid LLM limits')
    import ipaddress
    for cidr in config['approved_cidrs']:
        ipaddress.ip_network(cidr)
