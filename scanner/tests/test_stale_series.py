import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import scanner  # noqa: E402

TS = 1791213946.759


def vm_response(results_by_metric):
    def fake_get(url, params, timeout):
        name = params["query"].split("(", 1)[1].split("[", 1)[0]
        resp = mock.Mock()
        resp.json.return_value = {"data": {"result": [{"metric": m, "value": [TS, "1"]}
                                                      for m in results_by_metric.get(name, [])]}}
        return resp
    return fake_get


def counts(image, host):
    return [{"image": image, "severity": sev, "has_fix": fix, "host": host}
            for sev in scanner.SEVERITIES for fix in ("true", "false")]


class ZeroStaleSeriesTest(unittest.TestCase):
    def run_zero(self, previous, emitted, scanned_hosts, failed=frozenset()):
        with mock.patch.object(scanner.requests, "get", side_effect=vm_response(previous)), \
             mock.patch.object(scanner.requests, "post") as post:
            scanner.zero_stale_series(emitted, set(scanned_hosts), set(failed), TS)
        if not post.called:
            return set()
        return set(post.call_args.kwargs["data"].split("\n"))

    def emit(self, image, vulns, host):
        with mock.patch.object(scanner.requests, "post") as post:
            post.return_value.status_code = 204
            return scanner.push_metrics(image, vulns, TS, host=host)

    def test_removed_image_and_fixed_cve_are_zeroed(self):
        kept_cve = {"cve_id": "CVE-1", "package": "openssl", "severity": "HIGH", "has_fix": True, "cvss_score": 7.5}
        fixed_cve = {"image": "app:1", "cve_id": "CVE-2", "package": "zlib", "severity": "CRITICAL",
                     "has_fix": "true", "host": "docker-vm"}
        previous = {
            "vib_vulnerabilities_total": counts("app:1", "docker-vm") + counts("old:1", "docker-vm"),
            "vib_image_vulnerabilities_total": [{"image": "app:1", "host": "docker-vm"},
                                                {"image": "old:1", "host": "docker-vm"}],
            "vib_cve_info": [
                {"image": "app:1", "cve_id": "CVE-1", "package": "openssl", "severity": "HIGH",
                 "has_fix": "true", "host": "docker-vm"},
                fixed_cve,
            ],
        }
        emitted = self.emit("app:1", [kept_cve], "docker-vm")
        lines = self.run_zero(previous, emitted, {"docker-vm"})

        ts_ms = int(TS * 1000)
        self.assertIn(f'vib_image_vulnerabilities_total{{host="docker-vm",image="old:1"}} 0 {ts_ms}', lines)
        self.assertIn(f'vib_vulnerabilities_total{{has_fix="true",host="docker-vm",image="old:1",'
                      f'severity="CRITICAL"}} 0 {ts_ms}', lines)
        self.assertIn(f'vib_cve_info{{cve_id="CVE-2",has_fix="true",host="docker-vm",image="app:1",'
                      f'package="zlib",severity="CRITICAL"}} 0 {ts_ms}', lines)
        self.assertFalse([line for line in lines if 'image="app:1"' in line and "CVE-2" not in line])
        self.assertEqual(len(lines), 1 + 2 * len(scanner.SEVERITIES) + 1)

    def test_unscanned_host_and_failed_image_keep_their_values(self):
        previous = {
            "vib_image_vulnerabilities_total": [{"image": "a:1", "host": "offline-vm"},
                                                {"image": "b:1", "host": "docker-vm"}],
        }
        lines = self.run_zero(previous, set(), {"docker-vm"}, failed={("b:1", "docker-vm")})
        self.assertEqual(lines, set())

    def test_labels_round_trip_through_escaping(self):
        image = 'reg.example/we"ird:1'
        previous = {"vib_image_vulnerabilities_total": [{"image": image, "host": "docker-vm"}]}
        emitted = self.emit(image, [], "docker-vm")
        self.assertEqual(self.run_zero(previous, emitted, {"docker-vm"}), set())

    def test_unreadable_vm_skips_cleanup(self):
        with mock.patch.object(scanner.requests, "get", side_effect=scanner.requests.ConnectionError("down")), \
             mock.patch.object(scanner.requests, "post") as post:
            scanner.zero_stale_series(set(), {"docker-vm"}, set(), TS)
        post.assert_not_called()


if __name__ == "__main__":
    unittest.main()
