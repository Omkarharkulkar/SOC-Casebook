import unittest

from minisoc.normalizer.ssh_parser import parse_line


class TestSSHParser(unittest.TestCase):

    def test_failed_password(self):
        line = (
            "2026-10-28T16:34:17.105280+05:30 lab-ubuntu-01 "
            "sshd[4468]: Failed password for labuser "
            "from 192.168.50.10 port 54830 ssh2"
        )

        event = parse_line(line)

        self.assertEqual(event["event_type"], "failed_password")
        self.assertEqual(event["username"], "labuser")
        self.assertEqual(event["source_ip"], "192.168.50.10")
        self.assertEqual(event["source_port"], 54830)
        self.assertEqual(
            event["timestamp_utc"],
            "2026-10-28T11:04:17.105280+00:00",
        )

    def test_failed_password_for_invalid_user(self):
        line = (
            "2026-10-28T16:34:17+05:30 lab-ubuntu-01 "
            "sshd[4468]: Failed password for invalid user testuser "
            "from 192.168.50.10 port 54830 ssh2"
        )

        event = parse_line(line)

        self.assertEqual(event["event_type"], "failed_password")
        self.assertEqual(event["username"], "testuser")

    def test_failed_publickey(self):
        line = (
            "2026-10-29T16:12:50+05:30 lab-ubuntu-01 "
            "sshd[4862]: Failed publickey for labuser "
            "from 192.168.50.10 port 54812 ssh2"
        )

        event = parse_line(line)

        self.assertEqual(event["event_type"], "failed_publickey")

    def test_accepted_password(self):
        line = (
            "2026-10-28T16:34:26.465008+05:30 lab-ubuntu-01 "
            "sshd[4468]: Accepted password for labuser "
            "from 192.168.50.10 port 54830 ssh2"
        )

        event = parse_line(line)

        self.assertEqual(event["event_type"], "accepted_password")

    def test_accepted_publickey(self):
        line = (
            "2026-10-29T16:12:50+05:30 lab-ubuntu-01 "
            "sshd[4862]: Accepted publickey for labuser "
            "from 192.168.50.10 port 54812 ssh2: ED25519"
        )

        event = parse_line(line)

        self.assertEqual(event["event_type"], "accepted_publickey")

    def test_invalid_user(self):
        line = (
            "2026-10-27T16:40:22+05:30 lab-ubuntu-01 "
            "sshd[6090]: Invalid user invaliduser "
            "from 192.168.50.10 port 33230"
        )

        event = parse_line(line)

        self.assertEqual(event["event_type"], "invalid_user")
        self.assertEqual(event["username"], "invaliduser")

    def test_connection_closed(self):
        line = (
            "2026-10-29T16:12:07+05:30 lab-ubuntu-01 "
            "sshd[4775]: Connection closed by authenticating "
            "user labuser 192.168.50.10 port 52468 [preauth]"
        )

        event = parse_line(line)

        self.assertEqual(event["event_type"], "connection_closed")
        self.assertEqual(event["username"], "labuser")

    def test_connection_closed_invalid_user(self):
        line = (
            "2026-10-29T16:12:07+05:30 lab-ubuntu-01 "
            "sshd[4775]: Connection closed by invalid user testuser "
            "192.168.50.10 port 52468 [preauth]"
        )

        event = parse_line(line)

        self.assertEqual(event["event_type"], "connection_closed")
        self.assertEqual(event["username"], "testuser")

    def test_disconnected_invalid_user(self):
        line = (
            "2026-10-29T16:12:07+05:30 lab-ubuntu-01 "
            "sshd[4775]: Disconnected from invalid user testuser "
            "192.168.50.10 port 52468"
        )

        event = parse_line(line)

        self.assertEqual(event["event_type"], "disconnected")
        self.assertEqual(event["username"], "testuser")

    def test_sshd_session_process(self):
        line = (
            "2026-10-29T16:12:07+05:30 lab-ubuntu-01 "
            "sshd-session[4775]: Accepted password for labuser "
            "from 192.168.50.10 port 52468 ssh2"
        )

        event = parse_line(line)

        self.assertEqual(event["event_type"], "accepted_password")
        self.assertEqual(event["process_id"], 4775)

    def test_classic_syslog_timestamp(self):
        line = (
            "Nov  2 15:30:00 lab-ubuntu-01 sshd[4775]: "
            "Invalid user testuser from 192.168.50.10 port 52468"
        )

        event = parse_line(line)

        self.assertEqual(event["event_type"], "invalid_user")
        self.assertEqual(event["timestamp"], "Nov  2 15:30:00")
        self.assertIsNone(event["timestamp_utc"])

    def test_pam_auth_failure(self):
        line = (
            "Oct 28 16:34:15 lab-ubuntu-01 sshd[4468]: "
            "pam_unix(sshd:auth): authentication failure; "
            "logname= uid=0 euid=0 tty=ssh ruser= "
            "rhost=192.168.50.10  user=labuser"
        )

        event = parse_line(line)

        self.assertEqual(event["event_type"], "pam_auth_failure")
        self.assertEqual(event["username"], "labuser")
        self.assertEqual(event["source_ip"], "192.168.50.10")
        self.assertIsNone(event["source_port"])

    def test_pam_session_opened(self):
        line = (
            "Oct 28 16:34:26 lab-ubuntu-01 sshd[4468]: "
            "pam_unix(sshd:session): session opened for user "
            "labuser(uid=1000) by labuser(uid=0)"
        )

        event = parse_line(line)

        self.assertEqual(event["event_type"], "pam_session_opened")
        self.assertEqual(event["username"], "labuser")

    def test_pam_session_closed(self):
        line = (
            "Oct 28 16:34:27 lab-ubuntu-01 sshd[4468]: "
            "pam_unix(sshd:session): session closed for user labuser"
        )

        event = parse_line(line)

        self.assertEqual(event["event_type"], "pam_session_closed")
        self.assertEqual(event["username"], "labuser")

    def test_ssh_server_listening(self):
        line = (
            "Oct 27 16:22:56 lab-ubuntu-01 sshd[5934]: "
            "Server listening on 0.0.0.0 port 22."
        )

        event = parse_line(line)

        self.assertEqual(event["event_type"], "ssh_server_listening")
        self.assertEqual(event["listening_address"], "0.0.0.0")
        self.assertEqual(event["listening_port"], 22)

    def test_unrelated_line_is_ignored(self):
        line = (
            "2026-10-29T16:12:07+05:30 lab-ubuntu-01 "
            "systemd[1]: Started ssh.service"
        )

        self.assertIsNone(parse_line(line))


if __name__ == "__main__":
    unittest.main()
