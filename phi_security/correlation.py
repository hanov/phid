"""Conservative correlation: configuration, observed reads, and network activity stay distinct."""
import ipaddress
from datetime import datetime
from .analysis import READ_EVENTS
from .privacy import sensitive, fingerprint
from .storage import now
from .events import unique_events, touches

def ts(value):
    try:return datetime.fromisoformat(value.replace('Z','+00:00')).timestamp()
    except (TypeError,ValueError,AttributeError):return None

def correlate(resources, events, config):
    events = unique_events(events)
    findings=[]
    by_identity={}
    for e in events:
        if e.get('source')=='cloudtrail' and e.get('eventType') in READ_EVENTS and e.get('successful'):
            by_identity.setdefault(e.get('identity'),[]).append(e)
    for identity,reads in by_identity.items():
        if not identity:continue
        for resource in resources:
            if not sensitive(resource):continue
            selected=[e for e in reads if touches(e, resource['arn'])]
            if len(selected)<config['bulk_threshold']:continue
            from .behavior import approved
            selected = [e for e in selected if not approved(e, resource, config)]
            selected=sorted(selected,key=lambda e:e.get('timestamp',''))
            # Require a bounded 1-hour window; do not sum unrelated days into a bulk event.
            best=[];left=0
            for right,event in enumerate(selected):
                current=ts(event.get('timestamp'))
                if current is None:continue
                while left<right and current-(ts(selected[left].get('timestamp')) or 0)>3600:left+=1
                if right-left+1>len(best):best=selected[left:right+1]
            if len(best)<config['bulk_threshold']:continue
            refs=[e['id'] for e in best]
            first=ts(best[0]['timestamp']);last=ts(best[-1]['timestamp'])
            decrypt=[e for e in events if e.get('identity')==identity and e.get('eventType')=='Decrypt' and e.get('successful') and ts(e.get('timestamp')) is not None and first-300<=ts(e['timestamp'])<=last+900]
            # Link flows through an observed workload source IP/interface, never by egress alone.
            source_ips={e.get('sourceIp') for e in best}
            workload_interfaces={i for r in resources if r.get('privateIp') in source_ips for i in r.get('networkInterfaces',[])}
            flows=[]
            for e in events:
                if e.get('source')!='vpc-flow' or e.get('action')!='ACCEPT' or e.get('logStatus')!='OK':continue
                if e.get('sourceIp') not in source_ips and e.get('resource') not in workload_interfaces:continue
                when=ts(e.get('timestamp'))
                if when is None or not first-300<=when<=last+900:continue
                try:
                    destination=ipaddress.ip_address(e.get('destinationIp'))
                    approved=any(destination in ipaddress.ip_network(cidr) for cidr in config['approved_cidrs'])
                except (ValueError,TypeError):continue
                if destination.is_global and not approved and e.get('bytes',0)>1024*1024:flows.append(e)
            identifier='finding-'+fingerprint([resource['id'],identity,'bulk_correlation'])[:20]
            findings.append({'id':identifier,'resourceId':resource['id'],'resource':resource['arn'],'classification':resource['classification'],'type':'POSSIBLE_EXFILTRATION' if flows and decrypt else 'BULK_SENSITIVE_READS','severity':'HIGH','title':'Bulk sensitive-data reads with correlated decrypt and outbound activity' if flows and decrypt else 'Bulk sensitive-data reads observed','assessment':'possible_exfiltration' if flows and decrypt else 'confirmed_access','status':'OPEN','createdAt':now(),'updatedAt':now(),'evidence':refs+[e['id'] for e in decrypt+flows],'observedReadEvents':len(best),'estimatedRecordsAffected':None,'description':'Successful API reads are confirmed. Record counts, destination ownership and business authorization remain unverified.','recommendations':['Validate the session owner and approved workload.','Review object scope, destination ownership and change records.','Preserve telemetry; involve privacy/security personnel if warranted.']})
    return findings
