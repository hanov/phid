"""Synthetic-only local model smoke check; never reads the evidence database."""
from phi_security.llm import Router

result = Router({'llm': {'provider': 'ollama', 'model': 'qwen2.5:3b', 'timeout': 60}}).query(
    'Summarize this synthetic test record only.',
    [{'id': 'synthetic-e1', 'source': 'cloudtrail', 'eventType': 'GetObject', 'successful': True}],
)
print({key: result[key] for key in ['provider', 'model', 'latencyMs']})
print({'evidenceIds': result['result']['evidenceIds']})
