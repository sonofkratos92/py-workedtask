import os
import tempfile
import unittest
from unittest import mock

import anticheat


class TestIntegrityVerification(unittest.TestCase):
    def test_verify_passes_when_env_not_set(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertTrue(anticheat.verify_script_integrity())

    def test_verify_passes_with_matching_sha256(self):
        with tempfile.NamedTemporaryFile("wb", delete=False) as tmp:
            tmp.write(b"print('hello javelin')\n")
            tmp_path = tmp.name

        try:
            expected = anticheat.compute_file_sha256(tmp_path)
            with mock.patch.dict(os.environ, {"JAVELIN_EXPECTED_SHA256": expected.upper()}):
                self.assertTrue(anticheat.verify_script_integrity(script_path=tmp_path))
        finally:
            os.remove(tmp_path)

    def test_verify_fails_with_tampered_file_or_mismatch(self):
        with tempfile.NamedTemporaryFile("wb", delete=False) as tmp:
            tmp.write(b"print('hello javelin')\n")
            tmp_path = tmp.name

        try:
            wrong_hash = "0" * 64
            with mock.patch.dict(os.environ, {"JAVELIN_EXPECTED_SHA256": wrong_hash}):
                self.assertFalse(anticheat.verify_script_integrity(script_path=tmp_path))
                with mock.patch.object(anticheat, "check_debugger", return_value=False), \
                     mock.patch.object(anticheat, "check_suspicious_processes", return_value=False):
                    self.assertEqual(
                        anticheat.main(script_path=tmp_path),
                        anticheat.EXIT_INTEGRITY_FAILED,
                    )
        finally:
            os.remove(tmp_path)

    def test_verify_fails_with_malformed_hash(self):
        with mock.patch.dict(os.environ, {"JAVELIN_EXPECTED_SHA256": "not-a-valid-sha256"}):
            self.assertFalse(anticheat.verify_script_integrity())


if __name__ == "__main__":
    unittest.main()
