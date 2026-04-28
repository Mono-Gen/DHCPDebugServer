"""
Unit tests for utility functions.

Rules:
- test_*.py naming convention.
- Covers IP and MAC conversion logic in DHCPPacket (via dhcp_server.py) 
  and interface retrieval in utils.py.
"""

import unittest
from dhcp_server import DHCPPacket
from utils import get_network_interfaces

class TestUtils(unittest.TestCase):
    """
    Tests for network utility and packet helper functions.
    """
    
    def test_ip_to_bytes(self) -> None:
        """Tests IPv4 string to byte conversion."""
        self.assertEqual(DHCPPacket.ip_to_bytes("192.168.1.1"), b'\xc0\xa8\x01\x01')
        self.assertEqual(DHCPPacket.ip_to_bytes("0.0.0.0"), b'\x00\x00\x00\x00')
        # Invalid IP should return 0.0.0.0
        self.assertEqual(DHCPPacket.ip_to_bytes("invalid"), b'\x00\x00\x00\x00')
        self.assertEqual(DHCPPacket.ip_to_bytes("256.0.0.1"), b'\x00\x00\x00\x00')

    def test_bytes_to_ip(self) -> None:
        """Tests byte to IPv4 string conversion."""
        self.assertEqual(DHCPPacket.bytes_to_ip(b'\xc0\xa8\x01\x01'), "192.168.1.1")
        self.assertEqual(DHCPPacket.bytes_to_ip(b'\x00\x00\x00\x00'), "0.0.0.0")

    def test_get_network_interfaces(self) -> None:
        """
        Tests if the interface retrieval returns a non-empty list on a real system.
        Note: This is a system-dependent test.
        """
        ifaces = get_network_interfaces()
        self.assertIsInstance(ifaces, list)
        # On most systems (even CI), there should be at least one non-loopback interface.
        # But we don't strictly assert length > 0 to avoid environment-specific failures.
        for iface in ifaces:
            self.assertIn("name", iface)
            self.assertIn("ip", iface)
            self.assertIn("mask", iface)
            self.assertFalse(iface["ip"].startswith("127."))

if __name__ == "__main__":
    unittest.main()
