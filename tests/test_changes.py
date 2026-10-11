import unittest

from phi_security.config import DEFAULT


class ChangesBoundaryTest(unittest.TestCase):
    def test_permission_change_requires_prior_observation(self):
        from phi_security.changes import detect

        resource = {
            "id": "r",
            "arn": "arn:aws:s3:::b",
            "classification": "PHI",
            "type": "S3",
        }
        principal = {
            "id": "p",
            "arn": "arn:aws:iam::123456789012:role/test",
            "candidateResources": ["r"],
            "evidence": ["e"],
        }
        self.assertEqual(detect([resource], [principal], [], [], DEFAULT), [])
        result = detect(
            [resource],
            [principal],
            [{**principal, "candidateResources": []}],
            [],
            DEFAULT,
        )
        self.assertEqual(result[0]["type"], "NEW_SENSITIVE_PERMISSION")
