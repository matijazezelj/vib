import os
import subprocess
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import scanner  # noqa: E402

DIGEST = "gotenberg/gotenberg@sha256:abc"
BROKEN = subprocess.CompletedProcess([], 1, stdout="", stderr="FATAL failed to analyze layer")
OK = subprocess.CompletedProcess([], 0, stdout='{"Results": []}', stderr="")


class ScanImageTest(unittest.TestCase):
    def scan(self, results, digest=DIGEST):
        with mock.patch.object(scanner.subprocess, "run", side_effect=results) as run, \
             mock.patch.object(scanner, "_registry_ref", return_value=digest):
            return scanner.scan_image("gotenberg/gotenberg:latest", "tcp://docker-vm:2377"), run

    def test_broken_daemon_export_retries_the_digest_from_the_registry(self):
        result, run = self.scan([BROKEN, OK])
        self.assertEqual(result, {"Results": []})
        retry = run.call_args_list[1].args[0]
        self.assertEqual(retry[-3:], ["--image-src", "remote", DIGEST])
        self.assertNotIn("--docker-host", retry)

    def test_empty_output_is_a_failure_not_zero_findings(self):
        result, _ = self.scan([BROKEN, BROKEN])
        self.assertIsNone(result)
        result, run = self.scan([BROKEN], digest=None)
        self.assertIsNone(result)
        self.assertEqual(run.call_count, 1)

    def test_failed_image_is_reported_and_left_out_of_zeroing(self):
        with mock.patch.object(scanner, "_parse_docker_hosts", return_value=[("docker-vm", "tcp://docker-vm:2377")]), \
             mock.patch.object(scanner, "discover_images", return_value=["gotenberg/gotenberg:latest"]), \
             mock.patch.object(scanner, "scan_image", return_value=None), \
             mock.patch.object(scanner, "push_scan_error") as error, \
             mock.patch.object(scanner, "push_metrics") as push, \
             mock.patch.object(scanner, "zero_stale_series") as zero, \
             mock.patch.object(scanner, "push_scan_summary"):
            scanner.run_scan()
        error.assert_called_once()
        push.assert_not_called()
        self.assertIn(("gotenberg/gotenberg:latest", "docker-vm"), zero.call_args.args[2])


if __name__ == "__main__":
    unittest.main()
