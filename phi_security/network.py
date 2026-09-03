"""Read-only application routing relationships; reachability remains conditional."""
import re


def collect(collector, region):
    aws = collector.aws
    for table in aws.pages('ec2', 'describe_route_tables', region, 'RouteTables'):
        route_id = 'arn:aws:ec2:' + region + ':' + collector.account + ':route-table/' + table['RouteTableId']
        evidence = collector.evidence_item('ec2', 'RoutesObserved', route_id, reference=table['RouteTableId'] + ':' + collector.end.isoformat(), vpcId=table.get('VpcId'))
        for route in table.get('Routes', []):
            destination = route.get('GatewayId') or route.get('NatGatewayId') or route.get('TransitGatewayId') or route.get('VpcPeeringConnectionId')
            if destination:
                collector.edge(route_id, destination, 'configured_route', [evidence])
        for resource in collector.resources:
            if resource.get('vpcId') == table.get('VpcId'):
                collector.edge(resource['arn'], route_id, 'vpc_route_candidate', [evidence])
    for endpoint in aws.pages('ec2', 'describe_vpc_endpoints', region, 'VpcEndpoints'):
        collector.evidence_item('ec2', 'VpcEndpointObserved', endpoint['VpcEndpointId'], reference=endpoint['VpcEndpointId'] + ':' + collector.end.isoformat(), vpcId=endpoint.get('VpcId'), service=endpoint.get('ServiceName'), state=endpoint.get('State'))
    for resource in list(collector.resources):
        if resource['region'] != region:
            continue
        if resource['type'] == 'APIGateway':
            api_id = resource['arn'].rsplit('/', 1)[-1]
            for stage in (aws.call('apigateway', 'get_stages', region, restApiId=api_id) or {}).get('item', []):
                settings = stage.get('methodSettings', {})
                collector.evidence_item('apigateway', 'StageLogging', resource['arn'], reference=api_id + ':' + stage['stageName'], dataTraceEnabled=any(s.get('dataTraceEnabled') for s in settings.values()), accessLogDestination=stage.get('accessLogSettings', {}).get('destinationArn'))
            for route in aws.pages('apigateway', 'get_resources', region, 'items', restApiId=api_id):
                for method in route.get('resourceMethods', {}):
                    integration = aws.call('apigateway', 'get_integration', region, restApiId=api_id, resourceId=route['id'], httpMethod=method)
                    uri = (integration or {}).get('uri', '')
                    match = re.search(r'functions/(arn:[^/]+)/invocations', uri)
                    target = match.group(1) if match else uri.split('?')[0]
                    if target:
                        collector.edge(resource['arn'], target, 'configured_integration', resource['evidence'])
        if resource['type'] == 'LoadBalancer':
            for listener in aws.pages('elbv2', 'describe_listeners', region, 'Listeners', LoadBalancerArn=resource['arn']):
                collector.evidence_item('elbv2', 'ListenerObserved', resource['arn'], reference=listener['ListenerArn'], protocol=listener.get('Protocol'), port=listener.get('Port'), tlsPolicy=listener.get('SslPolicy'))
            for group in aws.pages('elbv2', 'describe_target_groups', region, 'TargetGroups', LoadBalancerArn=resource['arn']):
                for target in (aws.call('elbv2', 'describe_target_health', region, TargetGroupArn=group['TargetGroupArn']) or {}).get('TargetHealthDescriptions', []):
                    collector.edge(resource['arn'], target.get('Target', {}).get('Id'), 'configured_target', resource['evidence'])
