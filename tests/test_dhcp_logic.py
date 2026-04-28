"""
Unit tests for DHCP packet parsing and building logic.

Reference: RFC 2131
"""

import unittest
from dhcp_server import (
    DHCPPacket, 
    DHCP_OP_BOOTREQUEST, 
    DHCP_MSG_DISCOVER, 
    DHCP_OPT_MSG_TYPE,
    DHCP_MAGIC_COOKIE
)

class TestDHCPLogic(unittest.TestCase):
    """
    Tests for DHCPPacket parsing and building.
    """
    
    def test_packet_build_and_parse(self) -> None:
        """
        Tests a full cycle of building a packet and parsing it back.
        """
        pkt = DHCPPacket()
        pkt.op = DHCP_OP_BOOTREQUEST
        pkt.xid = 0x12345678
        pkt.chaddr = b'\x00\x11\x22\x33\x44\x55'
        pkt.options[DHCP_OPT_MSG_TYPE] = bytes([DHCP_MSG_DISCOVER])
        
        data = pkt.build()
        
        # Verify basic structure in built data
        self.assertEqual(data[0], DHCP_OP_BOOTREQUEST)
        self.assertEqual(data[4:8], b'\x12\x34\x56\x78') # xid
        self.assertEqual(data[236:240], DHCP_MAGIC_COOKIE)
        
        # Parse back
        parsed = DHCPPacket.parse(data)
        self.assertIsNotNone(parsed)
        if parsed:
            self.assertEqual(parsed.xid, 0x12345678)
            self.assertEqual(parsed.chaddr, b'\x00\x11\x22\x33\x44\x55')
            self.assertEqual(parsed.options[DHCP_OPT_MSG_TYPE], bytes([DHCP_MSG_DISCOVER]))

    def test_malformed_packet_parsing(self) -> None:
        """
        Tests parsing of invalid data.
        """
        # Too small
        self.assertIsNone(DHCPPacket.parse(b'\x01' * 10))
        
        # Invalid Magic Cookie
        data = b'\x01' * 236 + b'\x00\x00\x00\x00' + b'\xff'
        self.assertIsNone(DHCPPacket.parse(data))

if __name__ == "__main__":
    unittest.main()
