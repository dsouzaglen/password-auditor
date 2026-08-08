import unittest

from password_auditor.audit import audit_password


class PasswordAuditTests(unittest.TestCase):
    def test_common_password_is_critical(self) -> None:
        result = audit_password("password")
        self.assertEqual(result.rating, "critical")
        self.assertIn("COMMON_PASSWORD", {finding.code for finding in result.findings})

    def test_long_passphrase_scores_strong(self) -> None:
        result = audit_password("Orbit!Cedar7-Glass?River")
        self.assertEqual(result.rating, "strong")
        self.assertGreaterEqual(result.entropy_bits, 100)

    def test_sequences_are_reported(self) -> None:
        result = audit_password("Abcd9876!secure")
        self.assertIn("PREDICTABLE_SEQUENCE", {finding.code for finding in result.findings})

    def test_password_is_not_returned(self) -> None:
        password = "DoNotStoreThis!2026"
        serialized = str(audit_password(password).to_dict())
        self.assertNotIn(password, serialized)


if __name__ == "__main__":
    unittest.main()
