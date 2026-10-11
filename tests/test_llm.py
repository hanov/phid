import json
import unittest
from unittest.mock import Mock, patch

from phi_security.llm import NoRedirect, Router


class LocalModelTest(unittest.TestCase):
    def setUp(self):
        self.config = {
            "llm": {
                "provider": "ollama",
                "models": {"reasoning": "local-model"},
                "base_url": "http://127.0.0.1:11434",
            }
        }
        self.context = [
            {
                "id": "e1",
                "source": "cloudtrail",
                "eventType": "GetObject",
                "rawMessage": "patient secret",
            }
        ]

    def response(self, value):
        response = Mock()
        response.read.return_value = json.dumps(
            {"message": {"content": json.dumps(value)}}
        ).encode()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        return response

    def test_loopback_inference_redacts_and_validates_refs(self):
        opener = Mock()
        opener.open.return_value = self.response(
            {"summary": "Observed read.", "evidenceIds": ["e1"]}
        )
        with patch("phi_security.llm.build_opener", return_value=opener):
            result = Router(self.config).query("Review this", self.context)
        self.assertTrue(result["advisory"])
        self.assertFalse(result["verifiedConclusion"])
        sent = json.loads(opener.open.call_args.args[0].data)
        self.assertNotIn("patient secret", str(sent))
        self.assertFalse(sent["stream"])

    def test_unknown_evidence_rejected(self):
        opener = Mock()
        opener.open.return_value = self.response(
            {"summary": "Invented", "evidenceIds": ["fake"]}
        )
        with (
            patch("phi_security.llm.build_opener", return_value=opener),
            self.assertRaises(ValueError),
        ):
            Router(self.config).query("Review", self.context)

    def test_remote_ollama_and_credentials_rejected_before_network(self):
        for url in [
            "http://example.com",
            "http://127.0.0.1:11434/evil",
            "http://user:secret@localhost:11434",
        ]:
            self.config["llm"]["base_url"] = url
            with (
                patch("phi_security.llm.build_opener") as network,
                self.assertRaises(ValueError),
            ):
                Router(self.config).query("Review", self.context)
            network.assert_not_called()


class LlmBoundaryTest(unittest.TestCase):
    def test_redirects_are_blocked(self):
        with self.assertRaises(ValueError):
            NoRedirect().redirect_request(
                None, None, None, None, None, "http://external"
            )

    def test_model_raw_data_is_not_in_context(self):
        from phi_security.llm import minimized_context

        rows = minimized_context(
            [
                {
                    "id": "e",
                    "message": "raw patient record",
                    "password": "secret",
                    "title": "Contact patient@example.com",
                }
            ],
            1,
        )
        self.assertNotIn("raw patient record", str(rows))
        self.assertNotIn("patient@example.com", str(rows))
        self.assertNotIn("password", rows[0])

    def test_model_cannot_request_arbitrary_tools(self):
        response = Mock()
        response.read.return_value = json.dumps(
            {
                "message": {
                    "content": json.dumps(
                        {
                            "summary": "Review",
                            "evidenceIds": ["e1"],
                            "queries": ["delete_bucket"],
                        }
                    )
                }
            }
        ).encode()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        opener = Mock()
        opener.open.return_value = response
        with (
            patch("phi_security.llm.build_opener", return_value=opener),
            self.assertRaises(ValueError),
        ):
            Router({"llm": {"provider": "ollama", "model": "test"}}).query(
                "Review", [{"id": "e1"}], role="fast"
            )
