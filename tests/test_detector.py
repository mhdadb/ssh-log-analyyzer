import unittest
from datetime import datetime, timedelta

from loganalyzer import detector
from loganalyzer.parser import ACCEPTED, FAILED, Event

T0 = datetime(2026, 10, 3, 12, 0, 0)


def ev(offset_s, kind=FAILED, user="root", ip="203.0.113.5"):
    return Event(T0 + timedelta(seconds=offset_s), "web01", kind, user, ip, 22)


class BruteForceTests(unittest.TestCase):
    def test_flags_at_threshold(self):
        events = [ev(i) for i in range(5)]
        alerts = detector.detect_brute_force(events, threshold=5, window_seconds=60)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].ip, "203.0.113.5")

    def test_below_threshold_not_flagged(self):
        events = [ev(i) for i in range(4)]
        self.assertEqual(detector.detect_brute_force(events, threshold=5), [])

    def test_spread_out_failures_not_flagged(self):
        events = [ev(i * 120) for i in range(20)]  # one every 2 minutes
        self.assertEqual(detector.detect_brute_force(events, threshold=5, window_seconds=60), [])

    def test_ips_are_counted_separately(self):
        events = [ev(i, ip="1.1.1.1") for i in range(3)] + [ev(i, ip="2.2.2.2") for i in range(3)]
        self.assertEqual(detector.detect_brute_force(events, threshold=5), [])

    def test_high_severity_for_large_bursts(self):
        events = [ev(i) for i in range(20)]
        alert = detector.detect_brute_force(events, threshold=5)[0]
        self.assertEqual(alert.severity, "high")


class EnumerationTests(unittest.TestCase):
    def test_many_users_quickly(self):
        events = [ev(i * 5, user=f"user{i}") for i in range(6)]
        alerts = detector.detect_user_enumeration(events, min_users=5)
        self.assertEqual(len(alerts), 1)

    def test_same_users_over_days_not_flagged(self):
        events = [ev(i * 86400, user=f"user{i}") for i in range(6)]
        self.assertEqual(detector.detect_user_enumeration(events, min_users=5), [])


class SuccessAfterFailuresTests(unittest.TestCase):
    def test_detects_compromise_pattern(self):
        events = [ev(i * 3) for i in range(6)] + [ev(30, kind=ACCEPTED, user="deploy")]
        alerts = detector.detect_success_after_failures(events, min_failures=5)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, "high")

    def test_normal_typo_then_login_not_flagged(self):
        events = [ev(0), ev(10, kind=ACCEPTED, user="alice")]
        self.assertEqual(detector.detect_success_after_failures(events, min_failures=5), [])

    def test_old_failures_expire(self):
        events = [ev(i) for i in range(6)] + [ev(5000, kind=ACCEPTED)]
        self.assertEqual(
            detector.detect_success_after_failures(events, min_failures=5, lookback_seconds=600), []
        )


class SummaryTests(unittest.TestCase):
    def test_counts(self):
        events = [ev(0), ev(1), ev(2, kind=ACCEPTED, user="alice", ip="10.0.0.1")]
        s = detector.summarize(events)
        self.assertEqual(s["failed_logins"], 2)
        self.assertEqual(s["successful_logins"], 1)
        self.assertEqual(s["unique_ips"], 2)
        self.assertEqual(s["top_ips"][0], ("203.0.113.5", 2))

    def test_empty(self):
        self.assertEqual(detector.summarize([])["total_events"], 0)


if __name__ == "__main__":
    unittest.main()
