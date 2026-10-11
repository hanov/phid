import json
import logging
import re
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote

from .aws import AWS
from .privacy import (
    detect,
    fingerprint,
    merge_classification,
    metadata_classification,
    safe,
)
from .storage import now

logger = logging.getLogger("phid")


def tags(values):
    if isinstance(values, dict):
        return values
    return {
        x.get("Key", x.get("key", "")): x.get("Value", x.get("value", ""))
        for x in values or []
    }


def document(value):
    if isinstance(value, dict):
        return value
    try:
        return json.loads(unquote(value or "{}"))
    except (ValueError, TypeError):
        return {}


class Collector:
    def __init__(self, config, aws=None):
        self.config, self.aws = config, aws or AWS(config)
        self.resources, self.evidence, self.principals, self.edges = [], [], [], []
        self.account = None
        self.events_scanned = 0
        self.start = datetime.now(timezone.utc) - timedelta(
            hours=config["lookback_hours"]
        )
        self.end = datetime.now(timezone.utc)

    def evidence_item(
        self,
        source,
        event,
        resource=None,
        identity=None,
        timestamp=None,
        reference=None,
        **details,
    ):
        ev = {
            "source": source,
            "eventType": event,
            "resource": resource,
            "identity": identity,
            "timestamp": timestamp or now(),
            "reference": reference,
            **details,
        }
        ev["id"] = "ev-" + fingerprint([source, reference or ev])[:24]
        self.evidence.append(ev)
        return ev["id"]

    def asset(self, kind, name, arn, region, tagset=None, **extra):
        tagset = tags(tagset)
        classification, types, basis = metadata_classification(
            name, tagset, self.config
        )
        r = {
            "id": "res-" + fingerprint(arn)[:20],
            "arn": arn,
            "name": name,
            "type": kind,
            "region": region,
            "account": self.account,
            "classification": classification,
            "classificationBasis": basis,
            "detectedTypes": types,
            "isSensitive": self.config.get("classification_taxonomy", {})
            .get(classification, {})
            .get("sensitive", False),
            "tags": safe(tagset),
            "encryption": {"type": "unknown"},
            "publicAccess": None,
            "riskLevel": "UNKNOWN",
            "observedAt": now(),
            **extra,
        }
        if extra.get("sensitiveColumns"):
            from .detection import schema_type

            labels = [
                schema_type(c) for c in extra["sensitiveColumns"] if schema_type(c)
            ]
            from .privacy import classify

            merge_classification(
                r, classify(labels), labels, "schema_metadata", self.config
            )
        ev = self.evidence_item(
            "configuration",
            "ResourceObserved",
            arn,
            reference=arn + ":" + self.end.isoformat(),
            details={
                k: r[k]
                for k in [
                    "type",
                    "classification",
                    "classificationBasis",
                    "encryption",
                    "publicAccess",
                ]
            },
        )
        r["evidence"] = [ev]
        self.resources.append(r)
        return r

    def edge(self, source, target, relation, evidence=None):
        if source and target:
            self.edges.append(
                {
                    "id": fingerprint([source, target, relation])[:24],
                    "from": source,
                    "to": target,
                    "relation": relation,
                    "evidence": evidence or [],
                    "observedDataMovement": relation == "observed_copy",
                }
            )

    def collect(self, scope="all", resource=None):
        skip = set(self.config.get("skip_services", []))
        region = self.config["regions"][0]
        identity = self.aws.call("sts", "get_caller_identity", region)
        if not identity:
            raise RuntimeError(
                "AWS identity could not be verified; check credential chain and network access"
            )
        self.account = identity["Account"]
        logger.info(
            "account  %s  regions  %s", self.account, ", ".join(self.config["regions"])
        )
        if scope in ["all", "s3"] and "s3" not in skip:
            logger.info("collecting  s3")
            self.s3(resource)
        if scope == "all" and "iam" not in skip:
            logger.info("collecting  iam  region=%s", region)
            self.iam(region)
        for region in self.config["regions"]:
            if time.monotonic() > self.aws.deadline:
                break
            if scope in ["all", "databases"] and "databases" not in skip:
                logger.info("collecting  databases  region=%s", region)
                self.databases(region)
            if scope in ["all", "logs"] and "logs" not in skip:
                logger.info("collecting  logs  region=%s", region)
                self.logs(region)
                from .discovery import ingest_log_objects

                ingest_log_objects(self, region)
            if scope == "investigation":
                logger.info("collecting  telemetry  region=%s", region)
                self.telemetry(region)
                configured = (
                    self.config["cloudtrail_log_groups"]
                    + self.config["flow_log_groups"]
                )
                if configured:
                    self.config["log_groups"] = configured
                    self.logs(region)
            if scope == "all":
                if "infrastructure" not in skip:
                    logger.info("collecting  infrastructure  region=%s", region)
                    self.infrastructure(region)
                    from .network import collect as collect_network

                    collect_network(self, region)
                if "telemetry" not in skip:
                    logger.info("collecting  telemetry  region=%s", region)
                    self.telemetry(region)
                if "integrations" not in skip:
                    logger.info("collecting  integrations  region=%s", region)
                    self.integrations(region)
        if scope == "all":
            self.aws.coverage.append(
                {
                    "service": "cloudtrail",
                    "status": "LIMITATION",
                    "detail": "LookupEvents contains management events only. Data events require configured CloudTrail CloudWatch log groups.",
                }
            )
            self.aws.coverage.append(
                {
                    "service": "databases",
                    "status": "LIMITATION",
                    "detail": "Schemas use Glue catalog metadata where available. No direct database connections or record reads are performed.",
                }
            )
        from .topology import enrich

        enrich(self)
        return {
            "account": self.account,
            "resources": self.resources,
            "principals": self.principals,
            "evidence": self.evidence,
            "edges": self.edges,
            "coverage": self.aws.coverage,
            "eventsScanned": self.events_scanned,
        }

    def s3(self, target):
        region = self.config["regions"][0]
        account_block = self.aws.call(
            "s3control", "get_public_access_block", region, AccountId=self.account
        )
        buckets = self.aws.pages("s3", "list_buckets", region, "Buckets")
        for b in buckets:
            name = b["Name"]
            if (
                target
                and target not in [name, "s3://" + name, "arn:aws:s3:::" + name]
                and target not in name
            ):
                continue
            loc = self.aws.call("s3", "get_bucket_location", region, Bucket=name)
            actual = (loc or {}).get("LocationConstraint") or region
            if loc is not None:
                actual = loc.get("LocationConstraint") or "us-east-1"
            if actual == "EU":
                actual = "eu-west-1"
            if actual not in self.config["regions"]:
                continue
            logger.info("  s3  %s  region=%s", name, actual or "unknown")
            enc = self.aws.call("s3", "get_bucket_encryption", actual, Bucket=name)
            encryption = {"type": "unknown"}
            if enc:
                rules = enc.get("ServerSideEncryptionConfiguration", {}).get(
                    "Rules", []
                )
                if rules:
                    settings = rules[0].get("ApplyServerSideEncryptionByDefault", {})
                    encryption = {
                        "type": "SSE-KMS"
                        if "kms" in settings.get("SSEAlgorithm", "")
                        else "SSE-S3",
                        "keyId": settings.get("KMSMasterKeyID"),
                        "scope": "bucket_default_not_all_existing_objects",
                    }
            tagset = self.aws.call("s3", "get_bucket_tagging", actual, Bucket=name)
            block = self.aws.call("s3", "get_public_access_block", actual, Bucket=name)
            policy_status = self.aws.call(
                "s3", "get_bucket_policy_status", actual, Bucket=name
            )
            policy = self.aws.call("s3", "get_bucket_policy", actual, Bucket=name)
            acl = self.aws.call("s3", "get_bucket_acl", actual, Bucket=name)
            blocks = [
                (block or {}).get("PublicAccessBlockConfiguration", {}),
                (account_block or {}).get("PublicAccessBlockConfiguration", {}),
            ]
            public_acl = any(
                g.get("Grantee", {})
                .get("URI", "")
                .endswith(("/AllUsers", "/AuthenticatedUsers"))
                for g in (acl or {}).get("Grants", [])
            )
            public_policy = (
                (policy_status or {}).get("PolicyStatus", {}).get("IsPublic")
            )
            acl_blocked = any(x.get("IgnorePublicAcls") for x in blocks)
            policy_blocked = any(x.get("RestrictPublicBuckets") for x in blocks)
            public = (
                bool(
                    (public_acl and not acl_blocked)
                    or (public_policy and not policy_blocked)
                )
                if acl is not None and policy_status is not None
                else None
            )
            if acl_blocked and policy_blocked:
                public = False
            r = self.asset(
                "S3",
                name,
                "arn:aws:s3:::" + name,
                actual,
                (tagset or {}).get("TagSet"),
                encryption=encryption,
                publicAccess=public,
                policy=document((policy or {}).get("Policy")),
                publicAccessBlock=blocks,
                versioning=self.aws.call(
                    "s3", "get_bucket_versioning", actual, Bucket=name
                ),
                logging=self.aws.call("s3", "get_bucket_logging", actual, Bucket=name),
            )
            from .discovery import objects

            objects(self, r)
            replication = self.aws.call(
                "s3", "get_bucket_replication", actual, Bucket=name
            )
            for rule in (
                (replication or {}).get("ReplicationConfiguration", {}).get("Rules", [])
            ):
                if rule.get("Status") == "Enabled":
                    self.edge(
                        r["arn"],
                        rule.get("Destination", {}).get("Bucket"),
                        "configured_replication",
                        r["evidence"],
                    )
            for sample in (
                self.config.get("sample_keys", [])
                if self.config.get("sample_objects")
                else []
            ):
                if sample["bucket"] != name:
                    continue
                obj = self.aws.call(
                    "s3",
                    "get_object",
                    actual,
                    Bucket=name,
                    Key=sample["key"],
                    Range="bytes=0-" + str(self.config["sample_bytes"] - 1),
                )
                if obj:
                    try:
                        data = (
                            obj["Body"]
                            .read(self.config["sample_bytes"])
                            .decode("utf-8", errors="replace")
                        )
                    finally:
                        obj["Body"].close()
                    result = detect(
                        data,
                        self.config["custom_patterns"],
                        self.config.get("pattern_classifications"),
                    )
                    if result["detectedTypes"]:
                        merge_classification(
                            r,
                            result["classification"],
                            result["detectedTypes"],
                            "sample_pattern",
                            self.config,
                        )
                    r["evidence"].append(
                        self.evidence_item(
                            "s3",
                            "ContentSample",
                            r["arn"],
                            reference=fingerprint(sample),
                            detectedTypes=result["detectedTypes"],
                            contentHash=fingerprint(data),
                            sampleBytes=len(data.encode()),
                            classification=result["classification"],
                        )
                    )

    def databases(self, region):
        for service, operation, key, kind in [
            ("rds", "describe_db_instances", "DBInstances", "RDS"),
            ("rds", "describe_db_clusters", "DBClusters", "Aurora"),
            ("docdb", "describe_db_clusters", "DBClusters", "DocumentDB"),
            ("redshift", "describe_clusters", "Clusters", "Redshift"),
        ]:
            for db in self.aws.pages(service, operation, region, key):
                name = (
                    db.get("DBInstanceIdentifier")
                    or db.get("DBClusterIdentifier")
                    or db.get("ClusterIdentifier")
                )
                arn = (
                    db.get("DBInstanceArn")
                    or db.get("DBClusterArn")
                    or "arn:aws:redshift:"
                    + region
                    + ":"
                    + self.account
                    + ":cluster:"
                    + name
                )
                encrypted = db.get("StorageEncrypted", db.get("Encrypted"))
                self.asset(
                    kind,
                    name,
                    arn,
                    region,
                    db.get("TagList", db.get("Tags")),
                    encryption={
                        "type": "SSE-KMS"
                        if encrypted
                        else "none"
                        if encrypted is False
                        else "unknown",
                        "keyId": db.get("KmsKeyId"),
                    },
                    publicAccess=db.get("PubliclyAccessible"),
                    engine=db.get("Engine"),
                    vpcId=db.get("DBSubnetGroup", {}).get("VpcId"),
                    securityGroups=[
                        g.get("VpcSecurityGroupId")
                        for g in db.get("VpcSecurityGroups", [])
                    ],
                    backupRetentionDays=db.get("BackupRetentionPeriod"),
                )
        for name in self.aws.pages("dynamodb", "list_tables", region, "TableNames"):
            response = self.aws.call(
                "dynamodb", "describe_table", region, TableName=name
            )
            if not response:
                continue
            db = response["Table"]
            arn = db["TableArn"]
            tagset = self.aws.call(
                "dynamodb", "list_tags_of_resource", region, ResourceArn=arn
            )
            self.asset(
                "DynamoDB",
                name,
                arn,
                region,
                (tagset or {}).get("Tags"),
                encryption={
                    "type": "SSE-KMS"
                    if db.get("SSEDescription", {}).get("KMSMasterKeyArn")
                    else "AWS_OWNED_KEY"
                },
                itemCount=db.get("ItemCount"),
                sensitiveColumns=[
                    a["AttributeName"]
                    for a in db.get("AttributeDefinitions", [])
                    if re.search(
                        "mrn|ssn|email|dob|patient", a["AttributeName"], re.IGNORECASE
                    )
                ],
            )
        for domain in self.aws.pages(
            "opensearch", "list_domain_names", region, "DomainNames"
        ):
            resp = self.aws.call(
                "opensearch", "describe_domain", region, DomainName=domain["DomainName"]
            )
            if resp:
                db = resp["DomainStatus"]
                self.asset(
                    "OpenSearch",
                    db["DomainName"],
                    db["ARN"],
                    region,
                    encryption={
                        "type": "SSE-KMS"
                        if db.get("EncryptionAtRestOptions", {}).get("Enabled")
                        else "none"
                    },
                    publicAccess=False
                    if db.get("VPCOptions", {}).get("VPCId")
                    else None,
                    policy=document(db.get("AccessPolicies")),
                )
        for db in self.aws.pages("glue", "get_databases", region, "DatabaseList"):
            for table in self.aws.pages(
                "glue", "get_tables", region, "TableList", DatabaseName=db["Name"]
            ):
                columns = [
                    c["Name"]
                    for c in table.get("StorageDescriptor", {}).get("Columns", [])
                    if re.search(
                        "patient|mrn|dob|birth|ssn|email|phone|address|diagnosis|medication|insurance|passport|credit_card",
                        c["Name"],
                        re.IGNORECASE,
                    )
                ]
                location = table.get("StorageDescriptor", {}).get("Location", "")
                if columns:
                    ev = self.evidence_item(
                        "glue",
                        "SensitiveSchema",
                        location,
                        reference=db["Name"] + "." + table["Name"],
                        columns=columns,
                    )
                    for r in self.resources:
                        if r["type"] == "S3" and location.startswith(
                            "s3://" + r["name"] + "/"
                        ):
                            merge_classification(
                                r,
                                "PHI"
                                if any(
                                    re.search(
                                        "patient|mrn|diagnos|medication",
                                        c,
                                        re.IGNORECASE,
                                    )
                                    for c in columns
                                )
                                else "PII",
                                columns,
                                "schema_metadata",
                                self.config,
                            )
                            r["sensitiveColumns"] = columns
                            r["evidence"].append(ev)

        from .discovery import database_samples

        database_samples(self, region)

    def iam(self, region):
        details = []
        for key in ["RoleDetailList", "UserDetailList", "GroupDetailList", "Policies"]:
            details.append(
                self.aws.pages("iam", "get_account_authorization_details", region, key)
            )
        roles, users, groups, policies = details
        managed = {
            p["Arn"]: next(
                (
                    document(v.get("Document"))
                    for v in p.get("PolicyVersionList", [])
                    if v.get("IsDefaultVersion")
                ),
                {},
            )
            for p in policies
        }
        group_map = {g["GroupName"]: g for g in groups}
        for p in roles + users:
            is_role = "RoleName" in p
            name = p.get("RoleName") or p.get("UserName")
            docs = [
                document(x.get("PolicyDocument"))
                for x in p.get("RolePolicyList", p.get("UserPolicyList", []))
            ]
            docs += [
                managed.get(x["PolicyArn"], {})
                for x in p.get("AttachedManagedPolicies", [])
            ]
            for group in p.get("GroupList", []):
                g = group_map.get(group, {})
                docs += [
                    document(x.get("PolicyDocument"))
                    for x in g.get("GroupPolicyList", [])
                ]
                docs += [
                    managed.get(x["PolicyArn"], {})
                    for x in g.get("AttachedManagedPolicies", [])
                ]
            principal = {
                "id": "principal-" + fingerprint(p["Arn"])[:20],
                "arn": p["Arn"],
                "name": name,
                "type": "Role" if is_role else "User",
                "policies": docs,
                "trustPolicy": document(p.get("AssumeRolePolicyDocument")),
                "permissionsBoundary": p.get("PermissionsBoundary"),
                "resourcesAccessed": [],
                "riskLevel": "UNKNOWN",
                "observedAt": now(),
            }
            principal["evidence"] = [
                self.evidence_item(
                    "iam",
                    "PolicyObserved",
                    p["Arn"],
                    reference=p["Arn"] + ":" + self.end.isoformat(),
                )
            ]
            if not is_role:
                mfa = self.aws.call("iam", "list_mfa_devices", region, UserName=name)
                principal["mfaEnabled"] = (
                    bool(mfa.get("MFADevices")) if mfa is not None else None
                )
            self.principals.append(principal)

    def logs(self, region):
        for group in self.aws.pages("logs", "describe_log_groups", region, "logGroups"):
            name = group["logGroupName"]
            if (
                self.config["log_groups"]
                and name
                not in self.config["log_groups"]
                + self.config["cloudtrail_log_groups"]
                + self.config["flow_log_groups"]
            ):
                continue
            logger.info("  logs  %s  region=%s", name, region)
            r = self.asset(
                "CloudWatchLogs",
                name,
                group.get("arn", name).removesuffix(":*"),
                region,
                encryption={
                    "type": "SSE-KMS" if group.get("kmsKeyId") else "AWS_MANAGED"
                },
                retentionDays=group.get("retentionInDays"),
                storedBytes=group.get("storedBytes"),
            )
            if not self.config["scan_logs"]:
                continue
            items = self.aws.pages(
                "logs",
                "filter_log_events",
                region,
                "events",
                item_limit=self.config["max_log_events"],
                logGroupName=name,
                startTime=int(self.start.timestamp() * 1000),
                endTime=int(self.end.timestamp() * 1000),
                limit=min(self.config["max_log_events"], 10000),
            )
            for event in items[: self.config["max_log_events"]]:
                message = event.get("message", "")
                self.events_scanned += 1
                timestamp = datetime.fromtimestamp(
                    event["timestamp"] / 1000, timezone.utc
                ).isoformat()
                if name in self.config["cloudtrail_log_groups"]:
                    try:
                        payload = json.loads(message)
                        for e in payload.get("Records", [payload]):
                            self.cloudtrail_event(e, region)
                    except (ValueError, TypeError, KeyError):
                        pass
                    continue
                if name in self.config["flow_log_groups"]:
                    self.flow_event(message, name, event, timestamp)
                    continue
                result = detect(
                    message,
                    self.config["custom_patterns"],
                    self.config.get("pattern_classifications"),
                )
                if (
                    result["classification"] == "PII"
                    and self.config.get("detectors", {}).get("pii_detection") is False
                ):
                    continue
                if self.config.get("nlp_model"):
                    from .detection import nlp_types

                    extra = nlp_types(message, self.config["nlp_model"])
                    result["detectedTypes"] = sorted(
                        set(result["detectedTypes"] + extra)
                    )
                    if extra and result["classification"] == "UNCLASSIFIED":
                        result["classification"] = "PII"
                if self.config.get("requested_patterns") and not set(
                    result["detectedTypes"]
                ) & set(self.config["requested_patterns"]):
                    continue
                if result["detectedTypes"]:
                    # Keep type labels and fingerprint only, never persist the original log line.
                    eid = self.evidence_item(
                        "cloudwatch",
                        "SensitiveLogEntry",
                        r["arn"],
                        timestamp=timestamp,
                        reference=event.get("eventId") or fingerprint(event),
                        resourceId=r["id"],
                        logGroup=name,
                        logStream=event.get("logStreamName"),
                        detectedTypes=result["detectedTypes"],
                        classification=result["classification"],
                        contentHash=fingerprint(message),
                        redactedSnippet="Detected: "
                        + ", ".join(result["detectedTypes"]),
                        payloadLeak=bool(
                            re.search(
                                r"request[_ ]?body|response[_ ]?body|request_payload|response_payload",
                                message,
                                re.IGNORECASE,
                            )
                        ),
                        rootCauseCandidate="HTTP payload logging"
                        if re.search(
                            r"request[_ ]?body|response[_ ]?body",
                            message,
                            re.IGNORECASE,
                        )
                        else "Exception handler logging"
                        if re.search(
                            r"exception|traceback|stacktrace", message, re.IGNORECASE
                        )
                        else "Application logging",
                    )
                    r["evidence"].append(eid)
                    r["detectedTypes"] = list(
                        set(r["detectedTypes"] + result["detectedTypes"])
                    )
                    merge_classification(
                        r,
                        result["classification"],
                        result["detectedTypes"],
                        "log_pattern",
                        self.config,
                    )

    def cloudtrail_event(self, e, region):
        name = e.get("eventName")
        if not name:
            return
        uid = e.get("userIdentity", {})
        identity = (
            uid.get("sessionContext", {}).get("sessionIssuer", {}).get("arn")
            or uid.get("arn")
            or uid.get("principalId")
        )
        params = e.get("requestParameters") or {}
        resources = [
            r.get("ARN", r.get("resourceName"))
            for r in e.get("resources", [])
            if r.get("ARN") or r.get("resourceName")
        ]
        if params.get("bucketName"):
            resources.append("arn:aws:s3:::" + params["bucketName"])
        resources = list(dict.fromkeys(resources))
        resource = next(
            (
                r
                for r in resources
                if params.get("key") and r.endswith("/" + params["key"])
            ),
            resources[0] if resources else None,
        )
        if params.get("bucketName") and params.get("key"):
            resource = "arn:aws:s3:::" + params["bucketName"] + "/" + params["key"]
            resources = list(dict.fromkeys([resource, *resources]))
        self.evidence_item(
            "cloudtrail",
            name,
            resource,
            identity,
            e.get("eventTime"),
            reference=str(e.get("eventID", fingerprint(e))),
            sourceEventId=str(e.get("eventID", fingerprint(e))),
            resources=resources,
            objectPrefix=params.get("key", "").rsplit("/", 1)[0]
            if "/" in params.get("key", "")
            else "",
            region=region,
            sourceIp=e.get("sourceIPAddress"),
            session=uid.get("principalId"),
            successful=not bool(e.get("errorCode")),
            errorCode=e.get("errorCode"),
            managementEvent=e.get("managementEvent"),
            eventCategory=e.get("eventCategory"),
            userAgent=safe(e.get("userAgent")),
            destinationAccount=params.get("destinationAccountId"),
            bytesTransferred=(e.get("additionalEventData") or {}).get(
                "bytesTransferredOut"
            ),
            authenticationMethod=(e.get("additionalEventData") or {}).get(
                "AuthenticationMethod"
            ),
            mfaAuthenticated=uid.get("sessionContext", {})
            .get("attributes", {})
            .get("mfaAuthenticated"),
        )
        if (
            name in ["CopyObject", "ReplicateObject"]
            and params.get("x-amz-copy-source")
            and params.get("bucketName")
        ):
            source = str(params["x-amz-copy-source"]).lstrip("/").split("/")[0]
            self.edge(
                "arn:aws:s3:::" + source,
                "arn:aws:s3:::" + params["bucketName"],
                "observed_copy",
                [self.evidence[-1]["id"]],
            )

    def flow_event(self, message, group, event, timestamp):
        # Default VPC flow-log format only; custom formats must be normalized before import.
        fields = message.split()
        if len(fields) != 14 or not fields[0].isdigit():
            return
        try:
            self.evidence_item(
                "vpc-flow",
                "NetworkFlow",
                fields[2],
                timestamp=timestamp,
                reference=event.get("eventId") or fingerprint(event),
                sourceIp=fields[3],
                destinationIp=fields[4],
                port=int(fields[6]),
                bytes=int(fields[9]),
                action=fields[12],
                logStatus=fields[13],
                logGroup=group,
            )
        except ValueError:
            return

    def telemetry(self, region):
        lookup = {}
        if self.config.get("lookup_username"):
            lookup["LookupAttributes"] = [
                {
                    "AttributeKey": "Username",
                    "AttributeValue": self.config["lookup_username"],
                }
            ]
        for item in self.aws.pages(
            "cloudtrail",
            "lookup_events",
            region,
            "Events",
            StartTime=self.start,
            EndTime=self.end,
            MaxResults=50,
            **lookup,
        ):
            try:
                self.cloudtrail_event(json.loads(item["CloudTrailEvent"]), region)
            except (ValueError, KeyError):
                pass
        for trail in (self.aws.call("cloudtrail", "describe_trails", region) or {}).get(
            "trailList", []
        ):
            selectors = self.aws.call(
                "cloudtrail", "get_event_selectors", region, TrailName=trail["TrailARN"]
            )
            status = self.aws.call(
                "cloudtrail", "get_trail_status", region, Name=trail["TrailARN"]
            )
            self.evidence_item(
                "cloudtrail",
                "TelemetryCoverage",
                trail["TrailARN"],
                selectors=selectors,
                isLogging=(status or {}).get("IsLogging"),
            )
        from .discovery import metrics

        metrics(self, region)

    def infrastructure(self, region):
        for reservation in self.aws.pages(
            "ec2", "describe_instances", region, "Reservations"
        ):
            for instance in reservation.get("Instances", []):
                arn = (
                    "arn:aws:ec2:"
                    + region
                    + ":"
                    + self.account
                    + ":instance/"
                    + instance["InstanceId"]
                )
                r = self.asset(
                    "EC2",
                    instance["InstanceId"],
                    arn,
                    region,
                    instance.get("Tags"),
                    publicAccess=None,
                    publicEndpoint=bool(instance.get("PublicIpAddress")),
                    privateIp=instance.get("PrivateIpAddress"),
                    vpcId=instance.get("VpcId"),
                    subnetId=instance.get("SubnetId"),
                    networkInterfaces=[
                        n["NetworkInterfaceId"]
                        for n in instance.get("NetworkInterfaces", [])
                    ],
                    securityGroups=[
                        g["GroupId"] for g in instance.get("SecurityGroups", [])
                    ],
                )
                self.edge(
                    instance.get("IamInstanceProfile", {}).get("Arn"),
                    arn,
                    "instance_profile",
                    r["evidence"],
                )
        for sg in self.aws.pages(
            "ec2", "describe_security_groups", region, "SecurityGroups"
        ):
            self.asset(
                "SecurityGroup",
                sg["GroupId"],
                "arn:aws:ec2:"
                + region
                + ":"
                + self.account
                + ":security-group/"
                + sg["GroupId"],
                region,
                sg.get("Tags"),
                ingress=sg.get("IpPermissions", []),
            )
        for v in self.aws.pages("ec2", "describe_volumes", region, "Volumes"):
            self.asset(
                "EBS",
                v["VolumeId"],
                "arn:aws:ec2:"
                + region
                + ":"
                + self.account
                + ":volume/"
                + v["VolumeId"],
                region,
                v.get("Tags"),
                encryption={"type": "SSE-KMS" if v.get("Encrypted") else "none"},
            )
        for snap in self.aws.pages(
            "ec2", "describe_snapshots", region, "Snapshots", OwnerIds=["self"]
        ):
            attr = self.aws.call(
                "ec2",
                "describe_snapshot_attribute",
                region,
                SnapshotId=snap["SnapshotId"],
                Attribute="createVolumePermission",
            )
            permissions = (attr or {}).get("CreateVolumePermissions", [])
            self.asset(
                "EBSSnapshot",
                snap["SnapshotId"],
                "arn:aws:ec2:"
                + region
                + ":"
                + self.account
                + ":snapshot/"
                + snap["SnapshotId"],
                region,
                snap.get("Tags"),
                sourceResource=snap.get("VolumeId") or snap.get("ClusterIdentifier"),
                createdAt=str(
                    snap.get("StartTime") or snap.get("SnapshotCreateTime") or ""
                ),
                encryption={"type": "SSE-KMS" if snap.get("Encrypted") else "none"},
                publicAccess=any(x.get("Group") == "all" for x in permissions)
                if attr
                else None,
                sharedAccounts=[x["UserId"] for x in permissions if "UserId" in x],
            )
        for image in self.aws.pages(
            "ec2", "describe_images", region, "Images", Owners=["self"]
        ):
            self.asset(
                "AMI",
                image["ImageId"],
                "arn:aws:ec2:"
                + region
                + ":"
                + self.account
                + ":image/"
                + image["ImageId"],
                region,
                image.get("Tags"),
                publicAccess=image.get("Public"),
            )
        for snap in self.aws.pages(
            "rds", "describe_db_snapshots", region, "DBSnapshots", SnapshotType="manual"
        ):
            resp = self.aws.call(
                "rds",
                "describe_db_snapshot_attributes",
                region,
                DBSnapshotIdentifier=snap["DBSnapshotIdentifier"],
            )
            vals = [
                v
                for a in (resp or {})
                .get("DBSnapshotAttributesResult", {})
                .get("DBSnapshotAttributes", [])
                if a.get("AttributeName") == "restore"
                for v in a.get("AttributeValues", [])
            ]
            self.asset(
                "RDSSnapshot",
                snap["DBSnapshotIdentifier"],
                snap["DBSnapshotArn"],
                region,
                snap.get("TagList"),
                sourceResource=snap.get("DBInstanceIdentifier"),
                createdAt=str(snap.get("SnapshotCreateTime") or ""),
                encryption={"type": "SSE-KMS" if snap.get("Encrypted") else "none"},
                publicAccess="all" in vals if resp else None,
                sharedAccounts=[v for v in vals if v != "all"],
            )
        for snap in self.aws.pages(
            "redshift",
            "describe_cluster_snapshots",
            region,
            "Snapshots",
            OwnerAccount=self.account,
        ):
            name = snap["SnapshotIdentifier"]
            self.asset(
                "RedshiftSnapshot",
                name,
                "arn:aws:redshift:" + region + ":" + self.account + ":snapshot:" + name,
                region,
                snap.get("Tags"),
                sourceResource=snap.get("VolumeId") or snap.get("ClusterIdentifier"),
                createdAt=str(
                    snap.get("StartTime") or snap.get("SnapshotCreateTime") or ""
                ),
                encryption={"type": "SSE-KMS" if snap.get("Encrypted") else "none"},
                sharedAccounts=[
                    a["AccountId"] for a in snap.get("AccountsWithRestoreAccess", [])
                ],
            )
        for flow in self.aws.pages("ec2", "describe_flow_logs", region, "FlowLogs"):
            self.evidence_item(
                "ec2",
                "FlowLogCoverage",
                flow.get("ResourceId"),
                flowLogId=flow.get("FlowLogId"),
                destination=flow.get("LogDestination"),
                logGroup=flow.get("LogGroupName"),
                status=flow.get("FlowLogStatus"),
            )
        for fn in self.aws.pages("lambda", "list_functions", region, "Functions"):
            # Never persist function environment variables.
            r = self.asset(
                "Lambda",
                fn["FunctionName"],
                fn["FunctionArn"],
                region,
                runtime=fn.get("Runtime"),
                vpcId=fn.get("VpcConfig", {}).get("VpcId"),
                securityGroups=fn.get("VpcConfig", {}).get("SecurityGroupIds", []),
            )
            self.edge(fn.get("Role"), r["arn"], "execution_role", r["evidence"])
            self.edge(
                r["arn"],
                "arn:aws:logs:"
                + region
                + ":"
                + self.account
                + ":log-group:/aws/lambda/"
                + fn["FunctionName"],
                "writes_logs",
                r["evidence"],
            )
        for cluster in self.aws.pages("ecs", "list_clusters", region, "clusterArns"):
            services = self.aws.pages(
                "ecs", "list_services", region, "serviceArns", cluster=cluster
            )
            for offset in range(0, len(services), 10):
                response = self.aws.call(
                    "ecs",
                    "describe_services",
                    region,
                    cluster=cluster,
                    services=services[offset : offset + 10],
                )
                for svc in (response or {}).get("services", []):
                    r = self.asset(
                        "ECS",
                        svc["serviceName"],
                        svc["serviceArn"],
                        region,
                        svc.get("tags"),
                    )
                    task = self.aws.call(
                        "ecs",
                        "describe_task_definition",
                        region,
                        taskDefinition=svc["taskDefinition"],
                    )
                    definition = (task or {}).get("taskDefinition", {})
                    self.edge(
                        definition.get("taskRoleArn"),
                        r["arn"],
                        "execution_role",
                        r["evidence"],
                    )
                    for container in definition.get("containerDefinitions", []):
                        group = (
                            container.get("logConfiguration", {})
                            .get("options", {})
                            .get("awslogs-group")
                        )
                        if group:
                            self.edge(
                                r["arn"],
                                "arn:aws:logs:"
                                + region
                                + ":"
                                + self.account
                                + ":log-group:"
                                + group,
                                "writes_logs",
                                r["evidence"],
                            )
        for name in self.aws.pages("eks", "list_clusters", region, "clusters"):
            response = self.aws.call("eks", "describe_cluster", region, name=name)
            if response:
                c = response["cluster"]
                r = self.asset(
                    "EKS",
                    name,
                    c["arn"],
                    region,
                    c.get("tags"),
                    publicEndpoint=c.get("resourcesVpcConfig", {}).get(
                        "endpointPublicAccess"
                    ),
                )
                self.edge(c.get("roleArn"), r["arn"], "execution_role", r["evidence"])
        for api in self.aws.pages("apigateway", "get_rest_apis", region, "items"):
            self.asset(
                "APIGateway",
                api["name"],
                "arn:aws:apigateway:" + region + "::/restapis/" + api["id"],
                region,
                api.get("tags"),
                endpointTypes=api.get("endpointConfiguration", {}).get("types", []),
            )
        for lb in self.aws.pages(
            "elbv2", "describe_load_balancers", region, "LoadBalancers"
        ):
            self.asset(
                "LoadBalancer",
                lb["LoadBalancerName"],
                lb["LoadBalancerArn"],
                region,
                publicEndpoint=lb.get("Scheme") == "internet-facing",
                securityGroups=lb.get("SecurityGroups", []),
            )
        for key in self.aws.pages("kms", "list_keys", region, "Keys"):
            resp = self.aws.call("kms", "describe_key", region, KeyId=key["KeyId"])
            policy = self.aws.call(
                "kms",
                "get_key_policy",
                region,
                KeyId=key["KeyId"],
                PolicyName="default",
            )
            grants = self.aws.pages(
                "kms", "list_grants", region, "Grants", KeyId=key["KeyId"]
            )
            if resp:
                r = self.asset(
                    "KMS",
                    key["KeyId"],
                    key["KeyArn"],
                    region,
                    keyState=resp["KeyMetadata"].get("KeyState"),
                    policy=document((policy or {}).get("Policy")),
                    grants=[
                        {
                            k: g.get(k)
                            for k in ["GranteePrincipal", "Operations", "Constraints"]
                        }
                        for g in grants
                    ],
                )
                for g in grants:
                    self.edge(
                        g.get("GranteePrincipal"), r["arn"], "kms_grant", r["evidence"]
                    )
        for vault in self.aws.pages(
            "backup", "list_backup_vaults", region, "BackupVaultList"
        ):
            r = self.asset(
                "BackupVault",
                vault["BackupVaultName"],
                vault["BackupVaultArn"],
                region,
                encryption={"type": "SSE-KMS", "keyId": vault.get("EncryptionKeyArn")},
            )
            for point in self.aws.pages(
                "backup",
                "list_recovery_points_by_backup_vault",
                region,
                "RecoveryPoints",
                BackupVaultName=vault["BackupVaultName"],
            ):
                self.asset(
                    "RecoveryPoint",
                    point["RecoveryPointArn"],
                    point["RecoveryPointArn"],
                    region,
                    sourceResource=point.get("ResourceArn"),
                    createdAt=str(point.get("CreationDate", "")),
                    encryption={
                        "type": "SSE-KMS" if point.get("IsEncrypted") else "none"
                    },
                )

    def integrations(self, region):
        ids = self.aws.pages(
            "macie2", "list_findings", region, "findingIds", maxResults=50
        )
        for offset in range(0, len(ids), 50):
            resp = self.aws.call(
                "macie2", "get_findings", region, findingIds=ids[offset : offset + 50]
            )
            for finding in (resp or {}).get("findings", []):
                bucket = (
                    finding.get("resourcesAffected", {}).get("s3Bucket", {}).get("name")
                )
                arn = "arn:aws:s3:::" + bucket if bucket else None
                details = finding.get("classificationDetails", {}).get("result", {})
                types = [
                    d.get("type")
                    for category in details.get("sensitiveData", [])
                    for d in category.get("detections", [])
                    if d.get("type")
                ]
                eid = self.evidence_item(
                    "macie",
                    "SensitiveDataFinding",
                    arn,
                    reference=finding["id"],
                    detectedTypes=types,
                    severity=finding.get("severity"),
                    count=details.get("sensitiveData", []),
                    category=finding.get("category"),
                )
                for r in self.resources:
                    if r["arn"] == arn and types:
                        category = (
                            "PHI_HIGH"
                            if any(
                                re.search(
                                    "medical|health|drug|patient", t, re.IGNORECASE
                                )
                                for t in types
                            )
                            else "CREDENTIAL"
                            if any(
                                re.search("credential|secret|key", t, re.IGNORECASE)
                                for t in types
                            )
                            else "FINANCIAL"
                            if any(
                                re.search("credit|bank|financial", t, re.IGNORECASE)
                                for t in types
                            )
                            else "PII"
                        )
                        merge_classification(r, category, types, "macie", self.config)
                        r["evidence"].append(eid)
        for detector in self.aws.pages(
            "guardduty", "list_detectors", region, "DetectorIds"
        ):
            ids = self.aws.pages(
                "guardduty", "list_findings", region, "FindingIds", DetectorId=detector
            )
            for offset in range(0, len(ids), 50):
                resp = self.aws.call(
                    "guardduty",
                    "get_findings",
                    region,
                    DetectorId=detector,
                    FindingIds=ids[offset : offset + 50],
                )
                for f in (resp or {}).get("Findings", []):
                    meta = f.get("Resource", {})
                    key = meta.get("AccessKeyDetails", {})
                    username = key.get("UserName")
                    identity = next(
                        (p["arn"] for p in self.principals if p["name"] == username),
                        None,
                    )
                    affected = [
                        r["arn"]
                        for r in self.resources
                        if r["name"]
                        == meta.get("InstanceDetails", {}).get("InstanceId")
                        or any(
                            b.get("Name") == r["name"]
                            for b in meta.get("S3BucketDetails", [])
                        )
                    ]
                    if identity:
                        affected += [
                            r["arn"]
                            for r in self.resources
                            if any(
                                e.get("identity") == identity
                                and e.get("resource", "")
                                and (
                                    e["resource"] == r["arn"]
                                    or e["resource"].startswith(r["arn"] + "/")
                                )
                                for e in self.evidence
                            )
                        ]
                    for resource in list(dict.fromkeys(affected)) or [None]:
                        self.evidence_item(
                            "guardduty",
                            f.get("Type"),
                            resource,
                            identity,
                            reference=f["Id"] + str(resource),
                            severity=f.get("Severity"),
                            resourceMetadata=safe(meta),
                            timestamp=f.get("UpdatedAt"),
                        )
        for f in self.aws.pages(
            "securityhub", "get_findings", region, "Findings", MaxResults=100
        ):
            for resource in f.get("Resources", []):
                self.evidence_item(
                    "securityhub",
                    "SecurityFinding",
                    resource.get("Id"),
                    reference=f["Id"] + resource.get("Id", ""),
                    severity=f.get("Severity", {}).get("Label"),
                    title=safe(f.get("Title")),
                    recordState=f.get("RecordState"),
                    timestamp=f.get("UpdatedAt"),
                )
        for analyzer in self.aws.pages(
            "accessanalyzer", "list_analyzers", region, "analyzers"
        ):
            for f in self.aws.pages(
                "accessanalyzer",
                "list_findings",
                region,
                "findings",
                analyzerArn=analyzer["arn"],
            ):
                self.evidence_item(
                    "accessanalyzer",
                    "ExternalAccess",
                    f.get("resource"),
                    reference=f["id"],
                    isPublic=f.get("isPublic"),
                    principal=f.get("principal"),
                    actions=f.get("action"),
                    status=f.get("status"),
                    conditions=f.get("condition"),
                )
        for row in self.aws.pages(
            "config",
            "select_resource_config",
            region,
            "Results",
            Expression="SELECT resourceId, resourceType, arn, relationships, configurationItemCaptureTime",
        ):
            item = document(row)
            from .discovery import config_history

            config_history(self, region, item)
            eid = self.evidence_item(
                "config",
                "ResourceRelationships",
                item.get("arn"),
                timestamp=item.get("configurationItemCaptureTime"),
                reference=fingerprint(item),
            )
            for relation in item.get("relationships", []):
                self.edge(
                    item.get("arn"),
                    relation.get("resourceId"),
                    "configuration_relationship",
                    [eid],
                )
        if region == self.config["regions"][0]:
            if self.config.get("organizations"):
                for account in self.aws.pages(
                    "organizations", "list_accounts", region, "Accounts"
                ):
                    self.evidence_item(
                        "organizations",
                        "AccountObserved",
                        reference=account["Id"],
                        accountId=account["Id"],
                        state=account.get("State", account.get("Status")),
                    )
            response = self.aws.call("cloudfront", "list_distributions", region)
            for distribution in (
                (response or {}).get("DistributionList", {}).get("Items", [])
            ):
                r = self.asset(
                    "CloudFront",
                    distribution["Id"],
                    distribution["ARN"],
                    "global",
                    publicEndpoint=distribution.get("Enabled"),
                )
                for origin in distribution.get("Origins", {}).get("Items", []):
                    self.edge(
                        r["arn"],
                        origin.get("DomainName"),
                        "configured_origin",
                        r["evidence"],
                    )
