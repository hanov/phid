import copy
from datetime import datetime, timezone


class FakeCollector:
    def __init__(self, data):
        self.data = data

    def collect(self, *args):
        return copy.deepcopy(self.data)


def fixture():
    timestamp = datetime.now(timezone.utc).isoformat()
    return {
        "account": "123456789012",
        "resources": [
            {
                "id": "r1",
                "arn": "arn:aws:s3:::medical",
                "name": "medical",
                "type": "S3",
                "region": "us-east-1",
                "account": "123456789012",
                "classification": "PHI_HIGH",
                "classificationBasis": "tag",
                "detectedTypes": ["MRN"],
                "encryption": {"type": "none"},
                "publicAccess": True,
                "riskLevel": "UNKNOWN",
                "tags": {},
                "evidence": ["e1"],
            },
            {
                "id": "l1",
                "arn": "arn:aws:logs:us-east-1:123456789012:log-group:/app",
                "name": "/app",
                "type": "CloudWatchLogs",
                "region": "us-east-1",
                "classification": "PHI_HIGH",
                "classificationBasis": "log_pattern",
                "detectedTypes": ["MRN"],
                "encryption": {"type": "AWS_MANAGED"},
                "publicAccess": None,
                "riskLevel": "UNKNOWN",
                "tags": {},
                "evidence": ["e2"],
            },
        ],
        "principals": [
            {
                "id": "p1",
                "arn": "arn:aws:iam::123456789012:role/app",
                "name": "app",
                "type": "Role",
                "policies": [
                    {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "s3:GetObject",
                                "Resource": "arn:aws:s3:::medical/*",
                            }
                        ]
                    }
                ],
                "trustPolicy": {},
                "evidence": ["e3"],
            }
        ],
        "evidence": [
            {
                "id": "e1",
                "source": "configuration",
                "eventType": "ResourceObserved",
                "timestamp": timestamp,
                "resource": "arn:aws:s3:::medical",
            },
            {
                "id": "e2",
                "source": "cloudwatch",
                "eventType": "SensitiveLogEntry",
                "timestamp": timestamp,
                "resource": "arn:aws:logs:us-east-1:123456789012:log-group:/app",
                "resourceId": "l1",
                "classification": "PHI_HIGH",
                "detectedTypes": ["MRN"],
                "logGroup": "/app",
            },
            {
                "id": "e3",
                "source": "iam",
                "eventType": "PolicyObserved",
                "timestamp": timestamp,
            },
        ],
        "edges": [],
        "coverage": [{"service": "cloudtrail", "status": "AccessDenied"}],
        "eventsScanned": 1,
    }
