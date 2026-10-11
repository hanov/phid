import unittest


class StorageBoundaryTest(unittest.TestCase):
    def test_storage_drops_raw_payload_and_credentials(self):
        from phi_security.storage import Store

        store = Store(":memory:")
        self.addCleanup(store.close)
        store.put(
            "evidence",
            {
                "id": "e",
                "request_body": "raw patient",
                "nested": {"secret": "hidden"},
                "resource": "arn:example",
            },
        )
        value = store.get("evidence", "e")
        self.assertNotIn("raw patient", str(value))
        self.assertNotIn("hidden", str(value))
        self.assertEqual(value["resource"], "arn:example")
