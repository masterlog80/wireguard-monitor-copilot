"""Basic tests for the WireGuard Monitor web application."""
import importlib
import os
import sys
import time
import unittest
from unittest.mock import patch, MagicMock

# Ensure the repo root is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Use a fixed secret key for tests and a temp users file
os.environ.setdefault("SECRET_KEY", "test-secret-key")
os.environ.setdefault("ADMIN_USERNAME", "admin")
os.environ.setdefault("ADMIN_PASSWORD", "testpass")
os.environ["USERS_FILE"] = "/tmp/test_users_wireguard.json"


def _reset_user_store():
    """Remove temp users file and reset the module-level singleton."""
    import app.auth as auth_mod
    auth_mod._user_store = None
    try:
        os.remove("/tmp/test_users_wireguard.json")
    except FileNotFoundError:
        pass


class TestConfig(unittest.TestCase):
    def test_defaults(self):
        import config
        importlib.reload(config)
        from config import Config
        self.assertIsNotNone(Config.SECRET_KEY)
        self.assertEqual(Config.ADMIN_USERNAME, "admin")


class TestAppFactory(unittest.TestCase):
    def setUp(self):
        # Remove any leftover temp users file and reset the singleton
        _reset_user_store()
        from app import create_app
        self.app = create_app()
        self.app.testing = True
        self.client = self.app.test_client()

    def tearDown(self):
        _reset_user_store()

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


class TestUserManagement(unittest.TestCase):
    """Tests for the user management blueprint and UserStore."""

    def setUp(self):
        _reset_user_store()
        from app import create_app
        self.app = create_app()
        self.app.testing = True
        self.client = self.app.test_client()
        self._login()

    def tearDown(self):
        _reset_user_store()

    def _login(self):
        self.client.post(
            "/login",
            data={"username": "admin", "password": "testpass"},
        )

    # ------------------------------------------------------------------
    # UserStore unit tests
    # ------------------------------------------------------------------

    def test_user_store_seeds_admin(self):
        from app.auth import get_user_store
        store = get_user_store()
        self.assertIn("admin", store.list_users())

    def test_user_store_create_and_get(self):
        from app.auth import get_user_store
        store = get_user_store()
        self.assertTrue(store.create_user("alice", "secret123"))
        user = store.get_user("alice")
        self.assertIsNotNone(user)
        self.assertTrue(user.check_password("secret123"))

    def test_user_store_create_duplicate_fails(self):
        from app.auth import get_user_store
        store = get_user_store()
        store.create_user("bob", "pass1")
        self.assertFalse(store.create_user("bob", "pass2"))

    def test_user_store_change_password(self):
        from app.auth import get_user_store
        store = get_user_store()
        store.create_user("carol", "oldpass")
        self.assertTrue(store.change_password("carol", "newpass"))
        user = store.get_user("carol")
        self.assertTrue(user.check_password("newpass"))
        self.assertFalse(user.check_password("oldpass"))

    def test_user_store_delete(self):
        from app.auth import get_user_store
        store = get_user_store()
        store.create_user("dave", "pass")
        self.assertTrue(store.delete_user("dave"))
        self.assertIsNone(store.get_user("dave"))

    def test_user_store_persists_to_file(self):
        from app.auth import get_user_store, UserStore
        store = get_user_store()
        store.create_user("eve", "pass123")
        # Load a fresh store from the same file
        store2 = UserStore("/tmp/test_users_wireguard.json")
        self.assertIn("eve", store2.list_users())

    # ------------------------------------------------------------------
    # Route tests
    # ------------------------------------------------------------------

    def test_users_page_loads(self):
        resp = self.client.get("/users/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"User Management", resp.data)

    def test_users_page_requires_login(self):
        self.client.get("/logout")
        resp = self.client.get("/users/", follow_redirects=False)
        self.assertIn(resp.status_code, (301, 302))
        self.assertIn("/login", resp.headers.get("Location", ""))

    def test_create_user_via_route(self):
        resp = self.client.post(
            "/users/create",
            data={"username": "frank", "password": "pw1234", "confirm_password": "pw1234"},
            follow_redirects=True,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"frank", resp.data)

    def test_create_user_mismatched_passwords(self):
        resp = self.client.post(
            "/users/create",
            data={"username": "grace", "password": "abc", "confirm_password": "xyz"},
            follow_redirects=True,
        )
        self.assertIn(b"Passwords do not match", resp.data)

    def test_create_duplicate_user(self):
        self.client.post(
            "/users/create",
            data={"username": "heidi", "password": "p", "confirm_password": "p"},
        )
        resp = self.client.post(
            "/users/create",
            data={"username": "heidi", "password": "p2", "confirm_password": "p2"},
            follow_redirects=True,
        )
        self.assertIn(b"already exists", resp.data)

    def test_change_password_via_route(self):
        from app.auth import get_user_store
        store = get_user_store()
        store.create_user("ivan", "oldpw")
        resp = self.client.post(
            "/users/ivan/change-password",
            data={"new_password": "newpw", "confirm_password": "newpw"},
            follow_redirects=True,
        )
        self.assertIn(b"updated successfully", resp.data)
        user = store.get_user("ivan")
        self.assertTrue(user.check_password("newpw"))

    def test_delete_user_via_route(self):
        from app.auth import get_user_store
        store = get_user_store()
        store.create_user("judy", "pw")
        resp = self.client.post(
            "/users/judy/delete",
            follow_redirects=True,
        )
        self.assertIn(b"deleted", resp.data)
        self.assertIsNone(store.get_user("judy"))

    def test_cannot_delete_self(self):
        resp = self.client.post(
            "/users/admin/delete",
            follow_redirects=True,
        )
        self.assertIn(b"cannot delete your own account", resp.data.lower())


if __name__ == "__main__":
    unittest.main()
