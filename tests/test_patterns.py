import unittest

from help_api_finder.patterns import scan_text


class PatternTests(unittest.TestCase):
    def setUp(self):
        self.key = b"unit-test-fingerprint-key"

    def test_detects_and_redacts_openai_shape(self):
        # Split prefixes so this test fixture never looks like a leaked key to
        # repository secret scanners.
        candidate = "sk-" + "proj-" + "aB3dE5fG7hJ9kL2mN4pQ6rS8tV0xY1zC"
        detections = scan_text(f'OPENAI_API_KEY="{candidate}"', self.key)
        self.assertEqual(len(detections), 1)
        finding = detections[0]
        self.assertEqual(finding.provider, "OpenAI")
        self.assertNotIn(candidate, finding.evidence)
        self.assertNotIn(candidate, finding.masked_secret)
        self.assertIn("[REDACTED]", finding.evidence)
        self.assertTrue(finding.masked_secret.endswith(candidate[-4:]))

    def test_ignores_obvious_placeholder(self):
        text = "OPENAI_API_KEY=" + "sk-" + "proj-" + ("x" * 32)
        self.assertEqual(scan_text(text, self.key), [])

    def test_fingerprint_is_stable_but_key_is_not_returned(self):
        candidate = "gsk_" + "aB3dE5fG7hJ9kL2mN4pQ6rS8tV0xY1zC"
        first = scan_text(candidate, self.key)[0]
        second = scan_text(candidate, self.key)[0]
        self.assertEqual(first.fingerprint, second.fingerprint)
        self.assertNotEqual(first.fingerprint, candidate)


if __name__ == "__main__":
    unittest.main()
