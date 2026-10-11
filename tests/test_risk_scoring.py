import unittest

from phi_security.config import DEFAULT
from phi_security.engine import Engine
from tests.helpers import FakeCollector, fixture


class RiskScoringTest(unittest.TestCase):
    def _resource(self, classification, public=False, encrypted=True):
        return {
            "id": "r-" + classification,
            "arn": "arn:test:" + classification,
            "classification": classification,
            "publicAccess": bool(public),
            "encryption": {"type": "SSE-KMS" if encrypted else "none"},
        }

    def test_phi_high_scores_higher_than_pii(self):
        from phi_security.analysis import compute_risk_score

        phi_high = self._resource("PHI_HIGH")
        pii = self._resource("PII")
        self.assertGreater(
            compute_risk_score(phi_high, [], [], {})["score"],
            compute_risk_score(pii, [], [], {})["score"],
        )

    def test_public_exposure_increases_score(self):
        from phi_security.analysis import compute_risk_score

        private = self._resource("PHI")
        public = self._resource("PHI", public=True)
        self.assertGreater(
            compute_risk_score(public, [], [], {})["score"],
            compute_risk_score(private, [], [], {})["score"],
        )

    def test_unencrypted_increases_score(self):
        from phi_security.analysis import compute_risk_score

        enc = self._resource("PHI")
        plain = self._resource("PHI", encrypted=False)
        self.assertGreater(
            compute_risk_score(plain, [], [], {})["score"],
            compute_risk_score(enc, [], [], {})["score"],
        )

    def test_score_bounded_0_to_100(self):
        from phi_security.analysis import compute_risk_score

        worst = self._resource("PHI_HIGH", public=True, encrypted=False)
        result = compute_risk_score(worst, [], [], {})
        self.assertGreaterEqual(result["score"], 0)
        self.assertLessEqual(result["score"], 100)

    def test_factors_list_populated_for_sensitive_resource(self):
        from phi_security.analysis import compute_risk_score

        r = self._resource("PHI_HIGH", public=True, encrypted=False)
        result = compute_risk_score(r, [], [], {})
        factor_names = [f["factor"] for f in result["factors"]]
        self.assertIn("data_sensitivity", factor_names)
        self.assertIn("public_exposure", factor_names)
        self.assertIn("unencrypted", factor_names)

    def test_level_string_reflects_score(self):
        from phi_security.analysis import compute_risk_score

        r = self._resource("PHI_HIGH", public=True, encrypted=False)
        result = compute_risk_score(r, [], [], {})
        self.assertIn(result["level"], ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])

    def test_unclassified_resource_has_zero_sensitivity_contribution(self):
        from phi_security.analysis import compute_risk_score

        r = self._resource("UNCLASSIFIED")
        result = compute_risk_score(r, [], [], {})
        self.assertFalse(
            any(f["factor"] == "data_sensitivity" for f in result["factors"])
        )

    def test_scan_attaches_risk_score_to_resources(self):
        import tempfile

        tmp = tempfile.TemporaryDirectory()
        config = {**DEFAULT, "db": tmp.name + "/test.db"}
        engine = Engine(config, FakeCollector(fixture()))
        report = engine.scan({})
        engine.store.close()
        tmp.cleanup()
        for r in report["resources"]:
            self.assertIn("riskScore", r, msg=f"riskScore missing from {r['id']}")
            self.assertIn("score", r["riskScore"])
            self.assertIn("level", r["riskScore"])
