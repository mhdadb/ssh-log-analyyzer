import unittest
from datetime import datetime

from loganalyzer.parser import ACCEPTED, FAILED, INVALID_USER, parse_line


class ParserTests(unittest.TestCase):
    def test_failed_password(self):
        e = parse_line(
            "Oct  3 10:15:32 web01 sshd[1234]: Failed password for root from 203.0.113.5 port 4022 ssh2",
            2026,
        )
        self.assertEqual(e.kind, FAILED)
        self.assertEqual((e.user, e.ip, e.port), ("root", "203.0.113.5", 4022))
        self.assertEqual(e.timestamp, datetime(2026, 10, 3, 10, 15, 32))

    def test_failed_for_invalid_user(self):
        e = parse_line(
            "Oct 13 01:02:03 web01 sshd[9]: Failed password for invalid user admin from 198.51.100.1 port 22 ssh2",
            2026,
        )
        self.assertEqual(e.kind, FAILED)
        self.assertEqual(e.user, "admin")

    def test_invalid_user_line(self):
        e = parse_line("Oct  3 10:16:01 web01 sshd[1]: Invalid user test from 203.0.113.5 port 4023", 2026)
        self.assertEqual(e.kind, INVALID_USER)
        self.assertEqual(e.user, "test")

    def test_accepted(self):
        e = parse_line(
            "Oct  3 10:15:40 web01 sshd[1]: Accepted publickey for alice from 10.0.0.12 port 51522 ssh2", 2026
        )
        self.assertEqual(e.kind, ACCEPTED)
        self.assertEqual(e.user, "alice")

    def test_ipv6(self):
        e = parse_line(
            "Oct  3 10:15:40 web01 sshd[1]: Failed password for bob from 2001:db8::1 port 5000 ssh2", 2026
        )
        self.assertEqual(e.ip, "2001:db8::1")

    def test_ignores_unrelated_and_garbage(self):
        self.assertIsNone(parse_line("Oct  3 10:15:40 web01 cron[1]: job started", 2026))
        self.assertIsNone(parse_line("this is not a log line", 2026))
        self.assertIsNone(parse_line("", 2026))

    def test_invalid_date_is_ignored(self):
        self.assertIsNone(
            parse_line("Feb 30 10:15:40 web01 sshd[1]: Failed password for a from 1.2.3.4 port 1 ssh2", 2026)
        )


if __name__ == "__main__":
    unittest.main()
