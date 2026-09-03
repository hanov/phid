"""Resolve configuration edges, inherit backup sensitivity, and export DOT."""
import json
from .privacy import merge_classification


def enrich(collector):
    resources = collector.resources
    aliases = {}
    for resource in resources:
        for key in ['arn', 'id', 'name']:
            aliases.setdefault(resource[key], []).append(resource['arn'])
    for edge in collector.edges:
        for key in ['from', 'to']:
            matches = aliases.get(edge[key], [])
            if len(matches) == 1:
                edge[key] = matches[0]
    for resource in resources:
        source = resource.get('sourceResource')
        candidates = [r for r in resources if source and source in [r['arn'], r['name'], r['id']]]
        if len(candidates) == 1:
            parent = candidates[0]
            collector.edge(parent['arn'], resource['arn'], 'backup_of', parent.get('evidence', []) + resource['evidence'])
            merge_classification(resource, parent['classification'], parent.get('detectedTypes', []), 'inherited_backup_metadata', collector.config)
    for r in resources:
        key = r.get('encryption', {}).get('keyId')
        matches = [k for k in resources if k['type'] == 'KMS' and key in [k['arn'], k['name']]]
        for target in matches:
            collector.edge(target['arn'], r['arn'], 'encrypts', r['evidence'] + target['evidence'])


def dot(graph):
    def quote(value):
        return json.dumps(str(value), ensure_ascii=True)
    lines = ['digraph SensitiveData {', '  rankdir=LR;']
    for node in graph['nodes']:
        lines.append('  ' + quote(node['id']) + ' [label=' + quote(node.get('label', node['id']) + '\n' + node.get('classification', node.get('type', ''))) + '];')
    for edge in graph['edges']:
        lines.append('  ' + quote(edge['from']) + ' -> ' + quote(edge['to']) + ' [label=' + quote(edge.get('relation', 'related')) + '];')
    return '\n'.join(lines + ['}']) + '\n'
