import socket
import threading
import unittest

import portscan


class ParsePortsTests(unittest.TestCase):
    def test_list_and_range(self):
        self.assertEqual(portscan.parse_ports("80,22,100-102"), [22, 80, 100, 101, 102])

    def test_dedupes(self):
        self.assertEqual(portscan.parse_ports("80,80,79-80"), [79, 80])

    def test_out_of_range(self):
        with self.assertRaises(ValueError):
            portscan.parse_ports("0,70000")

    def test_bad_range(self):
        with self.assertRaises(ValueError):
            portscan.parse_ports("10-5")


class ScanTests(unittest.TestCase):
    def setUp(self):
        self.server = socket.socket()
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(5)
        self.port = self.server.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            conn.sendall(b"SSH-2.0-TestServer_1.0\r\n")
            conn.close()

    def tearDown(self):
        self.server.close()

    def test_finds_open_port_and_banner(self):
        closed = self.port + 1 if self.port < 65535 else self.port - 1
        results = portscan.scan("127.0.0.1", [self.port, closed], timeout=1.0)
        ports = [r["port"] for r in results]
        self.assertIn(self.port, ports)
        self.assertNotIn(closed, ports)
        banner = next(r["banner"] for r in results if r["port"] == self.port)
        self.assertEqual(banner, "SSH-2.0-TestServer_1.0")


if __name__ == "__main__":
    unittest.main()
