import unittest
from tool import validate_ports, validate_target

class SafetyTests(unittest.TestCase):
    def test_allows_private_single_ipv4(self): self.assertEqual("10.0.0.8", validate_target("10.0.0.8"))
    def test_blocks_public_loopback_and_ranges(self):
        for value in ("8.8.8.8", "127.0.0.1", "203.0.113.8", "10.0.0.0/24", "host.local", "fe80::1"):
            with self.assertRaises(ValueError): validate_target(value)
    def test_port_count_is_bounded(self):
        with self.assertRaises(ValueError): validate_ports(list(range(1, 34)))

if __name__ == "__main__": unittest.main()
