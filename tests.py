"""Basic tests for the WireGuard Monitor web application."""
import importlib
import os
import sys
import time
import unittest
from unittest.mock import patch, MagicMock

# Ensure the repo root is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Use a fixed secret key for tests
os.environ.setdefault("SECRET_KEY", "test-secret-key")
os.environ.setdefault("ADMIN_USERNAME", "admin")
os.environ.setdefault("ADMIN_PASSWORD", "testpass")


class TestConfig(unittest.TestCase):
    def test_defaults(self):
        import config
        importlib.reload(config)
        from config import Config
        self.assertIsNotNone(Config.SECRET_KEY)
        self.assertEqual(Config.ADMIN_USERNAME, "admin")


class TestAppFactory(unittest.TestCase):
    def setUp(self):
        from app import create_app
        self.app = create_app()
        self.app.testing = True
        self.client = self.app.test_client()

    def test_login_page_loads(self):
        resp = self.client.get("/login")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"WireGuard Monitor", resp.data)

    def test_redirect_to_login_when_unauthenticated(self):
        resp = self.client.get("/", follow_redirects=False)
        self.assertIn(resp.status_code, (301, 302))
        self.assertIn("/login", resp.headers.get("Location", ""))

    def test_login_with_wrong_credentials(self):
        resp = self.client.post(
            "/login",
            data={"username": "admin", "password": "wrongpassword"},
            follow_redirects=True,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Invalid username or password", resp.data)

    def test_login_with_correct_credentials(self):
        resp = self.client.post(
            "/login",
            data={"username": "admin", "password": "testpass"},
            follow_redirects=True,
        )
        self.assertEqual(resp.status_code, 200)
        # Should land on dashboard
        self.assertIn(b"WireGuard", resp.data)

    def _login(self):
        self.client.post(
            "/login",
            data={"username": "admin", "password": "testpass"},
        )

    def test_dashboard_requires_login(self):
        resp = self.client.get("/")
        self.assertIn(resp.status_code, (301, 302))

    def test_dashboard_after_login(self):
        self._login()
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Dashboard", resp.data)

    def test_firewall_page_after_login(self):
        self._login()
        resp = self.client.get("/firewall")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Firewall", resp.data)

    def test_api_status_after_login(self):
        self._login()
        resp = self.client.get("/api/status")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("available", data)

    def test_api_peers_after_login(self):
        self._login()
        resp = self.client.get("/api/peers")
        self.assertEqual(resp.status_code, 200)
        self.assertIsInstance(resp.get_json(), list)

    def test_api_throughput_after_login(self):
        self._login()
        resp = self.client.get("/api/throughput")
        self.assertEqual(resp.status_code, 200)
        self.assertIsInstance(resp.get_json(), dict)

    def test_api_ping_after_login(self):
        self._login()
        resp = self.client.get("/api/ping")
        self.assertEqual(resp.status_code, 200)
        self.assertIsInstance(resp.get_json(), dict)

    def test_logout(self):
        self._login()
        resp = self.client.get("/logout", follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"logged out", resp.data)


class TestWireguardParser(unittest.TestCase):
    def test_parse_interface_block(self):
        from app.wireguard import _parse_interface_block

        sample = """interface: wg0
  public key: abcdefghijklmnopqrstuvwxyz123456
  listening port: 51820

peer: PEERPUBKEY1234567890abcdefghijklmnop
  endpoint: 1.2.3.4:51820
  allowed ips: 10.0.0.2/32
  latest handshake: 1 minute, 30 seconds ago
  transfer: 1.23 MiB received, 456 KiB sent
"""
        result = _parse_interface_block("wg0", sample)
        self.assertEqual(result["name"], "wg0")
        self.assertEqual(result["listening_port"], "51820")
        self.assertEqual(len(result["peers"]), 1)
        self.assertEqual(result["peers"][0]["endpoint"], "1.2.3.4:51820")

    def test_get_wg_status_no_wg(self):
        """When wg binary is not available the status should reflect unavailable."""
        from app import wireguard

        with patch.object(wireguard, "_run", return_value=(1, "", "not found")):
            status = wireguard.get_wg_status()
        self.assertFalse(status["available"])

    def test_get_peers_parses_dump(self):
        from app import wireguard

        dump_output = (
            "privatekey\tpubkey_iface\t0.0.0.0:51820\t0\n"
            "pubkey1\t(none)\t10.0.0.1:12345\t10.0.0.2/32\t{ts}\t102400\t51200\t0\n".format(
                ts=int(time.time()) - 30
            )
        )

        def fake_run(cmd):
            if "interfaces" in cmd:
                return (0, "wg0\n", "")
            if "dump" in cmd:
                return (0, dump_output, "")
            return (1, "", "")

        with patch.object(wireguard, "_run", side_effect=fake_run):
            peers = wireguard.get_peers()

        self.assertEqual(len(peers), 1)
        self.assertTrue(peers[0]["connected"])
        self.assertEqual(peers[0]["rx_bytes"], 102400)

    def test_throughput_history_calculation(self):
        from app import wireguard

        key = "testkey"
        now = time.time()
        with wireguard._history_lock:
            wireguard._peer_history[key] = __import__("collections").deque(maxlen=60)
            wireguard._peer_history[key].append((now - 5, 0, 0))
            wireguard._peer_history[key].append((now, 5000, 2500))

        hist = wireguard.get_throughput_history()
        self.assertIn(key, hist)
        self.assertEqual(len(hist[key]["rx_bps"]), 1)
        self.assertAlmostEqual(hist[key]["rx_bps"][0], 1000.0, delta=10)


class TestFirewall(unittest.TestCase):
    def test_parse_iptables_output(self):
        from app.firewall import _parse_iptables_output

        sample = """Chain INPUT (policy ACCEPT 1234 packets, 5678 bytes)
 pkts bytes target     prot opt in     out     source               destination
    0     0 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0

Chain FORWARD (policy DROP 0 packets, 0 bytes)
Chain OUTPUT (policy ACCEPT 42 packets, 1024 bytes)
"""
        result = _parse_iptables_output(sample)
        self.assertIn("chains", result)
        self.assertIn("INPUT", result["chains"])
        self.assertIn("FORWARD", result["chains"])

    def test_get_firewall_rules_keys(self):
        from app import firewall

        with patch.object(firewall, "_run", return_value=(1, "", "permission denied")):
            rules = firewall.get_firewall_rules()

        self.assertIn("iptables", rules)
        self.assertIn("nftables", rules)


if __name__ == "__main__":
    unittest.main()
