import unittest

from minisoc.normalizer.ssh_parser import parse_line


class TestSSHParser(unittest.TestCase):

    def test_failed_password(self):
        line = (
            "2026-10-28T16:34:17.105280+05:30 omkarvm "
            "sshd[4468]: Failed password for omkarubuntu "
            "from 192.168.50.10 port 54830 ssh2"
        )

        event = parse_line(line)

        self.assertEqual(event["event_type"], "failed_password")
        self.assertEqual(event["username"], "omkarubuntu")
        self.assertEqual(event["source_ip"], "192.168.50.10")
        self.assertEqual(event["source_port"], 54830)

    def test_accepted_password(self):
        line = (
            "2026-10-28T16:34:26.465008+05:30 omkarvm "
            "sshd[4468]: Accepted password for omkarubuntu "
            "from 192.168.50.10 port 54830 ssh2"
        )

        event = parse_line(line)

        self.assertEqual(event["event_type"], "accepted_password")

    def test_accepted_publickey(self):
        line = (
            "2026-10-29T16:12:50+05:30 omkarvm "
            "sshd[4862]: Accepted publickey for omkarubuntu "
            "from 192.168.50.10 port 54812 ssh2: ED25519"
        )

        event = parse_line(line)

        self.assertEqual(event["event_type"], "accepted_publickey")

    def test_invalid_user(self):
        line = (
            "2026-10-27T16:40:22+05:30 omkarvm "
            "sshd[6090]: Invalid user invaliduser "
            "from 192.168.50.10 port 33230"
        )

        event = parse_line(line)

        self.assertEqual(event["event_type"], "invalid_user")
        self.assertEqual(event["username"], "invaliduser")

    def test_connection_closed(self):
        line = (
            "2026-10-29T16:12:07+05:30 omkarvm "
            "sshd[4775]: Connection closed by authenticating "
            "user omkarubuntu 192.168.50.10 port 52468 [preauth]"
        )

        event = parse_line(line)

        self.assertEqual(event["event_type"], "connection_closed")
        self.assertEqual(event["username"], "omkarubuntu")

    def test_unrelated_line_is_ignored(self):
        line = (
            "2026-10-29T16:12:07+05:30 omkarvm "
            "systemd[1]: Started ssh.service"
        )

        self.assertIsNone(parse_line(line))


if __name__ == "__main__":
    unittest.main()
