import io
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

import publish_crates


class PublishTests(unittest.TestCase):
    def test_registry_responses(self):
        with patch.object(publish_crates, "urlopen", return_value=io.BytesIO(
            b'{"version":{"crate":"cose2","num":"0.5.0"}}'
        )):
            self.assertTrue(publish_crates.is_published("cose2", "0.5.0"))
        with patch.object(publish_crates, "urlopen", side_effect=HTTPError("url", 404, "missing", {}, None)):
            self.assertFalse(publish_crates.is_published("cose2", "0.5.0"))
        with patch.object(publish_crates, "urlopen", side_effect=HTTPError("url", 503, "unavailable", {}, None)):
            with self.assertRaises(HTTPError):
                publish_crates.is_published("cose2", "0.5.0")
        with patch.object(publish_crates, "urlopen", return_value=io.BytesIO(
            b'{"version":{"crate":"cose2","num":"0.4.0"}}'
        )):
            with self.assertRaises(ValueError):
                publish_crates.is_published("cose2", "0.5.0")

    @patch.object(publish_crates.subprocess, "run")
    def test_existing_version_and_dry_run_do_not_upload(self, run):
        with patch.object(publish_crates, "is_published", return_value=True):
            publish_crates.publish("cose2", "0.5.0")
        with patch.object(publish_crates, "is_published", return_value=False):
            publish_crates.publish("sd-cwt", "0.3.0", dry_run=True)
        run.assert_not_called()

    @patch.object(publish_crates.time, "sleep")
    @patch.object(publish_crates.subprocess, "run")
    def test_retry_recovers_an_upload_that_reached_the_registry(self, run, sleep):
        run.return_value.returncode = 1
        with patch.object(publish_crates, "is_published", side_effect=[False, True]):
            publish_crates.publish("cose2", "0.5.0")
        run.assert_called_once_with(["cargo", "publish", "--locked", "-p", "cose2"], cwd=publish_crates.ROOT)
        sleep.assert_called_once_with(20)

    @patch.object(publish_crates.time, "sleep")
    @patch.object(publish_crates.subprocess, "run")
    def test_success_and_bounded_failures(self, run, sleep):
        with patch.object(publish_crates, "is_published", return_value=False):
            run.return_value.returncode = 0
            publish_crates.publish("cose2", "0.5.0")
            self.assertEqual(run.call_count, 1)
            sleep.assert_not_called()
            run.reset_mock()
            run.return_value.returncode = 1
            with self.assertRaises(RuntimeError):
                publish_crates.publish("cose2", "0.5.0")
            self.assertEqual(run.call_count, 5)
            self.assertEqual(sleep.call_count, 4)


if __name__ == "__main__":
    unittest.main()
