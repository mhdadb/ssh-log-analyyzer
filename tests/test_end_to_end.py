import json
import os
import tempfile
import unittest

from loganalyzer import generator
from loganalyzer.cli import main


class EndToEndTests(unittest.TestCase):
    def test_generator_is_deterministic(self):
        self.assertEqual(generator.generate(seed=1), generator.generate(seed=1))

    def test_full_pipeline_finds_known_attackers(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = os.path.join(tmp, "auth.log")
            out = os.path.join(tmp, "out")
            generator.write_sample(log)
            self.assertEqual(main(["analyze", log, "--year", "2026", "-o", out]), 0)

            for name in ("report.html", "alerts.csv", "summary.json"):
                self.assertTrue(os.path.isfile(os.path.join(out, name)), name)

            with open(os.path.join(out, "summary.json")) as fh:
                data = json.load(fh)
            flagged = {a["ip"] for a in data["alerts"]}
            # Ground truth from the generator:
            for attacker in ("203.0.113.50", "203.0.113.99", "198.51.100.23"):
                self.assertIn(attacker, flagged)
            rules = {(a["ip"], a["rule"]) for a in data["alerts"]}
            self.assertIn(("203.0.113.99", "success_after_failures"), rules)
            # Legitimate internal users are never flagged.
            self.assertFalse(any(ip.startswith("10.0.0.") for ip in flagged))

    def test_report_escapes_malicious_usernames(self):
        line = (
            'Oct  3 10:00:00 web01 sshd[1]: Failed password for invalid user '
            '<script>alert(1)</script> from 203.0.113.9 port 22 ssh2\n'
        )
        with tempfile.TemporaryDirectory() as tmp:
            log = os.path.join(tmp, "auth.log")
            with open(log, "w") as fh:
                fh.write(line * 6)
            out = os.path.join(tmp, "out")
            self.assertEqual(main(["analyze", log, "--year", "2026", "-o", out, "--no-ml"]), 0)
            with open(os.path.join(out, "report.html")) as fh:
                html_doc = fh.read()
            self.assertNotIn("<script>alert(1)</script>", html_doc)

    def test_missing_file_returns_error(self):
        self.assertEqual(main(["analyze", "/nonexistent/auth.log"]), 2)


if __name__ == "__main__":
    unittest.main()
