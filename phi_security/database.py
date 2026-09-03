"""Optional direct PostgreSQL-compatible sampling under a read-only transaction."""
import os
import re
from .privacy import detect, fingerprint, merge_classification


def postgres_samples(collector, region):
    for target in collector.config.get('db_samples', []):
        if target.get('service') not in ['postgresql', 'redshift'] or target.get('region') != region:
            continue
        # No arbitrary SQL from config, models or data. Only simple identifiers.
        schema, table = target.get('schema', 'public'), target['table']
        if not all(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,62}', part) for part in [schema, table]):
            raise ValueError('Invalid sampling table identifier')
        limit = target.get('limit', 5)
        if type(limit) is not int or not 1 <= limit <= 10:
            raise ValueError('Sampling limit must be 1..10')
        env_name = target.get('dsn_env', '')
        if not env_name or not os.environ.get(env_name):
            raise ValueError('Database DSN environment variable is required')
        import psycopg
        # Read-only is set by the database, not inferred from a SQL prefix.
        with psycopg.connect(os.environ[env_name], connect_timeout=5, options='-c default_transaction_read_only=on -c statement_timeout=5000', autocommit=False) as connection:
            with connection.cursor() as cursor:
                cursor.execute('SET TRANSACTION READ ONLY')
                cursor.execute('SELECT column_name FROM information_schema.columns WHERE table_schema=%s AND table_name=%s', (schema, table))
                columns = [row[0] for row in cursor.fetchall()]
                # Character conversion and per-column cap prevent fetching unrestricted cell payloads.
                selected = [column for column in target.get('columns', columns) if column in columns]
                if not selected or not all(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,62}', column) for column in selected):
                    raise ValueError('No valid sample columns')
                from psycopg import sql
                expressions = sql.SQL(', ').join(sql.SQL('left(CAST({} AS TEXT), 1024)').format(sql.Identifier(column)) for column in selected[:50])
                query = sql.SQL('SELECT {} FROM {}.{} LIMIT %s').format(expressions, sql.Identifier(schema), sql.Identifier(table))
                cursor.execute(query, (limit,))
                rows = cursor.fetchmany(limit)
            connection.rollback()
        import json
        for row in rows:
            payload = json.dumps(dict(zip(selected, row)), default=str)
            detection = detect(payload, collector.config['custom_patterns'], collector.config.get('pattern_classifications'))
            resource = next((r for r in collector.resources if r['arn'] == target.get('resource')), None)
            arn = target.get('resource')
            eid = collector.evidence_item('database-sample', 'SensitiveSample', arn,
                reference=fingerprint([arn, schema, table, payload]), contentHash=fingerprint(payload),
                detectedTypes=detection['detectedTypes'], classification=detection['classification'],
                schema=schema, table=table, query='bounded_read_only_sample', columns=selected)
            if resource:
                merge_classification(resource, detection['classification'], detection['detectedTypes'], 'database_sample', collector.config)
                resource['evidence'].append(eid)
