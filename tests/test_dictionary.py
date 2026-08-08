import hashlib
import tempfile
import unittest
from pathlib import Path

from password_auditor.dictionary import simulate_dictionary_match


class DictionarySimulationTests(unittest.TestCase):
    def test_finds_authorized_lab_candidate(self) -> None:
        candidate = "lab-example-only"
        target = hashlib.sha256(candidate.encode()).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            wordlist = Path(directory) / "words.txt"
            wordlist.write_text("first\nlab-example-only\nthird\n", encoding="utf-8")
            result = simulate_dictionary_match(target, wordlist)
        self.assertTrue(result.matched)
        self.assertEqual(result.matched_candidate, candidate)
        self.assertEqual(result.attempts, 2)

    def test_rejects_invalid_hash(self) -> None:
        with self.assertRaises(ValueError):
            simulate_dictionary_match("not-a-hash", Path("missing.txt"))


if __name__ == "__main__":
    unittest.main()
