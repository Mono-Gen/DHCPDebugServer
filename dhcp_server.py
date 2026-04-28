"""
DHCP Server Core Module

Protocol: DHCP (RFC 2131)
This module implements a basic DHCP server with debugging capabilities, 
including packet parsing, building, and handling of lease logic.
"""

import socket
import struct
import threading
import time
import random
from typing import Optional, Dict, List, Set, Any, Callable

# DHCP Constants (RFC 2131)
DHCP_OP_BOOTREQUEST = 1
DHCP_OP_BOOTREPLY = 2
DHCP_HTYPE_ETHERNET = 1
DHCP_HLEN_ETHERNET = 6
DHCP_MAGIC_COOKIE = b'\x63\x82\x53\x63'

# DHCP Options (RFC 1533 / RFC 2132)
DHCP_OPT_NETMASK = 1
DHCP_OPT_ROUTER = 3
DHCP_OPT_DNS = 6
DHCP_OPT_BROADCAST_ADDR = 28
DHCP_OPT_REQ_IP = 50
DHCP_OPT_LEASE_TIME = 51
DHCP_OPT_MSG_TYPE = 53
DHCP_OPT_SERVER_ID = 54
DHCP_OPT_END = 255

# DHCP Message Types
DHCP_MSG_DISCOVER = 1
DHCP_MSG_OFFER = 2
DHCP_MSG_REQUEST = 3
DHCP_MSG_DECLINE = 4
DHCP_MSG_ACK = 5
DHCP_MSG_NAK = 6
DHCP_MSG_RELEASE = 7
DHCP_MSG_INFORM = 8

class DHCPPacket:
    """
    Represents a DHCP packet as defined in RFC 2131.
    
    Responsibilities:
    - Parse raw binary data into a structured DHCPPacket object.
    - Build a structured DHCPPacket object back into raw binary data.
    """
    def __init__(self):
        self.op: int = DHCP_OP_BOOTREQUEST
        self.htype: int = DHCP_HTYPE_ETHERNET
        self.hlen: int = DHCP_HLEN_ETHERNET
        self.hops: int = 0
        self.xid: int = 0
        self.secs: int = 0
        self.flags: int = 0
        self.ciaddr: str = "0.0.0.0"
        self.yiaddr: str = "0.0.0.0"
        self.siaddr: str = "0.0.0.0"
        self.giaddr: str = "0.0.0.0"
        self.chaddr: bytes = b'\x00' * 16
        self.magic_cookie: bytes = DHCP_MAGIC_COOKIE
        self.options: Dict[int, bytes] = {}

    @staticmethod
    def ip_to_bytes(ip: str) -> bytes:
        """Converts an IPv4 string to a 4-byte packed binary format."""
        try:
            return socket.inet_aton(ip)
        except (socket.error, TypeError):
            return b'\x00\x00\x00\x00'

    @staticmethod
    def bytes_to_ip(b: bytes) -> str:
        """Converts a 4-byte packed binary IPv4 address to a string."""
        return socket.inet_ntoa(b)

    @classmethod
    def parse(cls, data: bytes) -> Optional['DHCPPacket']:
        """
        Parses raw binary DHCP data.
        
        Args:
            data (bytes): The raw data received from the wire.
            
        Returns:
            Optional[DHCPPacket]: A populated DHCPPacket object if valid, else None.
        """
        # Minimum DHCP packet size without options
        if len(data) < 240: 
            return None
            
        pkt = cls()
        # Unpack header: ! (Network/Big-endian), BBBB (4x 1b), I (4b xid), HH (2x 2b secs/flags), 4s (ciaddr), ...
        header = struct.unpack("!BBBBIHH4s4s4s4s16s", data[:44])
        pkt.op, pkt.htype, pkt.hlen, pkt.hops, pkt.xid, pkt.secs, pkt.flags, ci, yi, si, gi, ch = header
        pkt.ciaddr, pkt.yiaddr, pkt.siaddr, pkt.giaddr = map(cls.bytes_to_ip, [ci, yi, si, gi])
        pkt.chaddr = ch[:pkt.hlen]
        
        # Verify Magic Cookie
        if data[236:240] != pkt.magic_cookie: 
            return None
            
        # Parse Options
        ptr = 240
        while ptr < len(data):
            opt_type = data[ptr]
            if opt_type == DHCP_OPT_END: 
                break
            if opt_type == 0: # PAD option
                ptr += 1
                continue
            if ptr + 1 >= len(data): 
                break
            opt_len = data[ptr + 1]
            if ptr + 2 + opt_len > len(data): 
                break
            pkt.options[opt_type] = data[ptr + 2 : ptr + 2 + opt_len]
            ptr += 2 + opt_len
        return pkt

    @staticmethod
    def msg_type_to_str(mtype: int) -> str:
        """Converts a DHCP message type code to its string representation."""
        mapping = {
            1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE",
            5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM"
        }
        return mapping.get(mtype, f"UNKNOWN({mtype})")

    def build(self) -> bytes:
        """
        Builds the binary DHCP packet.
        
        Returns:
            bytes: The assembled binary packet.
        """
        res = struct.pack("!BBBBIHH4s4s4s4s16s",
            self.op, self.htype, self.hlen, self.hops, self.xid, self.secs, self.flags,
            self.ip_to_bytes(self.ciaddr), self.ip_to_bytes(self.yiaddr),
            self.ip_to_bytes(self.siaddr), self.ip_to_bytes(self.giaddr),
            self.chaddr.ljust(16, b'\x00')
        )
        # Add 64 bytes sname, 128 bytes file, and 4 bytes magic cookie
        res += b'\x00' * 64 + b'\x00' * 128 + self.magic_cookie
        # Add Options
        for ot, ov in self.options.items():
            res += struct.pack("!BB", ot, len(ov)) + ov
        res += struct.pack("!B", DHCP_OPT_END)
        # Ensure minimum size (often 312 for compatibility/legacy reasons)
        if len(res) < 312: 
            res += b'\x00' * (312 - len(res))
        return res

class DHCPServer:
    """
    Main DHCP Server implementation.
    
    Responsibilities:
    - Listen for DHCP requests on UDP port 67.
    - Manage IP address leases and pools.
    - Provide debugging features (drop, delay, NAK, MAC filtering).
    """
    def __init__(self, cfg: Dict[str, Any]):
        self.cfg: Dict[str, Any] = cfg
        self.running: bool = False
        self.sock: Optional[socket.socket] = None
        self.on_packet: Optional[Callable[[DHCPPacket, tuple], None]] = None
        self.on_status: Optional[Callable[[str], None]] = None
        self.leases: Dict[str, Dict[str, Any]] = {}  # MAC -> {ip, expiry}
        self.offered_ips: Dict[str, Dict[str, Any]] = {} # MAC -> {ip, time}
        
        # Debug members
        self.drop_all: bool = False
        self.ignored_types: Set[int] = set()
        self.ignore_renewals: bool = False
        self.delay_ms: int = 0
        self.mac_filters: Set[str] = set()
        self.nak_mode: bool = False

    def start(self) -> None:
        """Starts the DHCP server in a background thread."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            # Binding to port 67 (DHCP Server port). 
            # On Windows, binding to '' (INADDR_ANY) is recommended for broadcast.
            self.sock.bind(('', 67))
            self.running = True
            threading.Thread(target=self._run, daemon=True).start()
        except Exception as e:
            if self.on_status: 
                self.on_status(f"Startup Error: {e}")
            raise e

    def stop(self) -> None:
        """Stops the DHCP server."""
        self.running = False
        if self.sock:
            try: 
                self.sock.close()
            except socket.error: 
                pass

    def _run(self) -> None:
        """Main receive loop running in a background thread."""
        while self.running:
            try:
                data, addr = self.sock.recvfrom(2048)
                pkt = DHCPPacket.parse(data)
                if pkt:
                    self._handle_packet(pkt, addr)
            except Exception as e:
                if self.running and self.on_status:
                    self.on_status(f"Socket Error: {e}")

    def _handle_packet(self, pkt: DHCPPacket, addr: tuple) -> None:
        """Process an incoming DHCP packet."""
        try:
            if self.drop_all: 
                return
            
            # 1. Interface/Subnet Filtering
            # Ensure the source IP (for unicast requests) is in our subnet.
            src_ip = addr[0]
            if not self._is_in_subnet(src_ip):
                return
            
            # 2. Heuristic Filter: Option 50 (Requested IP)
            req_ip_data = pkt.options.get(DHCP_OPT_REQ_IP)
            if req_ip_data:
                req_ip = socket.inet_ntoa(req_ip_data)
                if not self._is_in_subnet(req_ip):
                    return

            # 3. Heuristic Filter: Option 54 (Server Identifier)
            # If the client is explicitly talking to another server, ignore it.
            server_id_data = pkt.options.get(DHCP_OPT_SERVER_ID)
            if server_id_data:
                server_id = socket.inet_ntoa(server_id_data)
                if server_id != self.cfg['interface_ip']:
                    return

            # 4. Filter: Relay Agent (giaddr)
            # If it's being relayed from another network segment, ignore.
            if pkt.giaddr != "0.0.0.0" and not self._is_in_subnet(pkt.giaddr):
                return
            
            # 2. MAC Filtering
            mac_str = pkt.chaddr.hex(":")
            if mac_str in self.mac_filters: 
                return
            
            # 3. Callback for logging (only reached if filtered in)
            if self.on_packet: 
                self.on_packet(pkt, addr)

            # Extract Message Type (Option 53)
            msg_type = pkt.options.get(DHCP_OPT_MSG_TYPE, b'\x00')[0]
            if msg_type in self.ignored_types: 
                return
            
            # Simulated Latency
            if self.delay_ms > 0: 
                time.sleep(self.delay_ms / 1000.0)

            if msg_type == DHCP_MSG_DISCOVER:
                self._send_offer(pkt)
            elif msg_type == DHCP_MSG_REQUEST:
                # Renewal/Rebinding often uses ciaddr != 0.0.0.0
                if pkt.ciaddr != "0.0.0.0" and self.ignore_renewals: 
                    return
                
                if self.nak_mode: 
                    self._send_nak(pkt)
                else: 
                    self._send_ack(pkt)
            elif msg_type == DHCP_MSG_RELEASE:
                if mac_str in self.leases:
                    del self.leases[mac_str]
                    if self.on_status: 
                        self.on_status(f"Released {mac_str}")
        except Exception as e:
            if self.on_status: 
                self.on_status(f"Logic Error: {e}")

    def _is_in_subnet(self, ip: str) -> bool:
        """
        Heuristic filter: Check if the IP or target belongs to the interface subnet.
        If the IP is 0.0.0.0, it is considered potentially in-subnet for DHCP discovery.
        """
        if ip == "0.0.0.0":
            return True
        
        try:
            mask_str = self.cfg.get('mask', '255.255.255.0')
            iface_ip = self.cfg['interface_ip']
            
            ip_val = struct.unpack("!I", socket.inet_aton(ip))[0]
            mask_val = struct.unpack("!I", socket.inet_aton(mask_str))[0]
            iface_val = struct.unpack("!I", socket.inet_aton(iface_ip))[0]
            
            return (ip_val & mask_val) == (iface_val & mask_val)
        except (socket.error, struct.error):
            return False

    def _get_next_ip(self, mac: str, requested_ip: Optional[str] = None) -> Optional[str]:
        """
        Determines the next available IP address for a client.
        
        Args:
            mac (str): Client MAC address.
            requested_ip (Optional[str]): The IP client requested (Option 50).
            
        Returns:
            Optional[str]: Available IPv4 as a string, else None.
        """
        # 1. Cleanup expired temporary offers
        now = time.time()
        expired_macs = [m for m, d in self.offered_ips.items() if now - d['time'] > 30]
        for m in expired_macs: 
            del self.offered_ips[m]

        # 2. Retain existing lease or offer if possible
        if mac in self.leases: 
            return self.leases[mac]['ip']
        if mac in self.offered_ips: 
            return self.offered_ips[mac]['ip']
        
        try:
            start_int = struct.unpack("!I", socket.inet_aton(self.cfg['pool_start']))[0]
            end_int = struct.unpack("!I", socket.inet_aton(self.cfg['pool_end']))[0]
            if start_int > end_int:
                if self.on_status: 
                    self.on_status("Pool Error: Start IP > End IP")
                return None
            
            # IPs to avoid: active leases or pending offers
            used_ips = {l['ip'] for l in self.leases.values()}
            offered_ips_val = {d['ip'] for d in self.offered_ips.values()}
            unavailable = used_ips | offered_ips_val
            
            # 3. Handle requested IP (Option 50)
            if requested_ip and requested_ip != "0.0.0.0":
                req_int = struct.unpack("!I", socket.inet_aton(requested_ip))[0]
                if start_int <= req_int <= end_int and requested_ip not in unavailable:
                    return requested_ip
            
            # 4. Search for next free IP
            for i in range(start_int, end_int + 1):
                ip = socket.inet_ntoa(struct.pack("!I", i))
                if ip not in unavailable and ip != self.cfg['interface_ip']:
                    return ip
        except (socket.error, struct.error):
            pass
        return None

    def _send_offer(self, discover_pkt: DHCPPacket) -> None:
        """Sends a DHCP OFFER in response to a DISCOVER."""
        mac = discover_pkt.chaddr.hex(":")
        # Check Option 50 (Requested IP)
        req_ip_data = discover_pkt.options.get(DHCP_OPT_REQ_IP)
        req_ip = socket.inet_ntoa(req_ip_data) if req_ip_data else None
        
        assigned = self._get_next_ip(mac, req_ip)
        if not assigned: 
            return
        
        # Store as pending offer
        self.offered_ips[mac] = {'ip': assigned, 'time': time.time()}
        
        if self.on_status: 
            self.on_status(f"Sending OFFER for {assigned} to {mac}")
        self._send_response(discover_pkt, assigned, DHCP_MSG_OFFER)

    def _send_ack(self, request_pkt: DHCPPacket) -> None:
        """Sends a DHCP ACK in response to a REQUEST."""
        mac = request_pkt.chaddr.hex(":")
        # Try Option 50 first, then fall back to ciaddr
        req_ip_data = request_pkt.options.get(DHCP_OPT_REQ_IP)
        req_ip = socket.inet_ntoa(req_ip_data) if req_ip_data else request_pkt.ciaddr
        
        assigned = self._get_next_ip(mac, req_ip)
        if not assigned:
            self._send_nak(request_pkt)
            return
        
        # Move from offered to active lease
        if mac in self.offered_ips: 
            del self.offered_ips[mac]
        
        if self.on_status: 
            self.on_status(f"Sending ACK for {assigned} to {mac}")
            
        self.leases[mac] = {
            'ip': assigned, 
            'expiry': time.time() + self.cfg['lease_time']
        }
        self._send_response(request_pkt, assigned, DHCP_MSG_ACK)

    def _send_response(self, req_pkt: DHCPPacket, assigned_ip: str, mtype: int) -> None:
        """Common logic to build and send a DHCP OFFER/ACK/NAK."""
        resp = DHCPPacket()
        resp.op = DHCP_OP_BOOTREPLY
        resp.xid = req_pkt.xid
        resp.yiaddr = assigned_ip
        resp.siaddr = "0.0.0.0"
        resp.chaddr = req_pkt.chaddr
        
        # --- ENHANCED COMPATIBILITY MODE (Standard) ---
        # 1. Force the destination IP to Global Broadcast
        # Necessary because clients in DISCOVER state may not recognize subnet broadcasts.
        dest_ip = "255.255.255.255"

        # 2. Force the DHCP Payload "Broadcast Flag" to 0x8000
        # Ensures embedded stacks (Soundcraft, etc.) accept the broadcast delivery.
        resp.flags = 0x8000 
        
        # Options - Standard Sequence
        resp.options[DHCP_OPT_MSG_TYPE] = bytes([mtype])
        resp.options[DHCP_OPT_SERVER_ID] = socket.inet_aton(self.cfg['interface_ip'])
        resp.options[DHCP_OPT_LEASE_TIME] = struct.pack("!I", self.cfg['lease_time'])
        resp.options[DHCP_OPT_NETMASK] = socket.inet_aton(self.cfg['mask'])
        resp.options[DHCP_OPT_ROUTER] = socket.inet_aton(self.cfg['router'])
        
        # DNS Fallback: always ensure DNS is provided for picky clients
        dns = self.cfg.get('dns')
        if not dns or dns == "0.0.0.0":
            dns = self.cfg['interface_ip'] 
        resp.options[DHCP_OPT_DNS] = socket.inet_aton(dns)

        # COMPATIBILITY HOOK: Add Broadcast Address (Option 28)
        try:
            m_str = self.cfg['mask']
            i_str = self.cfg['interface_ip']
            m_val = struct.unpack("!I", socket.inet_aton(m_str))[0]
            i_val = struct.unpack("!I", socket.inet_aton(i_str))[0]
            b_val = (i_val & m_val) | (~m_val & 0xFFFFFFFF)
            resp.options[DHCP_OPT_BROADCAST_ADDR] = struct.pack("!I", b_val)
        except Exception:
            pass
            
        if self.on_status:
            self.on_status(f"Sending {DHCPPacket.msg_type_to_str(mtype)} (Broadcast enforced for compatibility)")
            
        # Debugging: hex dump of response
        if self.on_status:
            pkt_data = resp.build()
            pkt_hex = pkt_data[:32].hex(" ")
            self.on_status(f"Response Hex Dump (first 32b): {pkt_hex}")

        self._send_packet(resp, dest_ip)

    def _send_nak(self, request_pkt: DHCPPacket) -> None:
        """Sends a DHCP NAK in response to a REQUEST."""
        nak = DHCPPacket()
        nak.op = DHCP_OP_BOOTREPLY
        nak.xid = request_pkt.xid
        nak.siaddr = self.cfg['interface_ip']
        nak.chaddr = request_pkt.chaddr
        nak.options[DHCP_OPT_MSG_TYPE] = bytes([DHCP_MSG_NAK])
        nak.options[DHCP_OPT_SERVER_ID] = socket.inet_aton(self.cfg['interface_ip'])
        
        # NAK is traditionally broadcast
        self._send_packet(nak, "255.255.255.255")

    def _send_packet(self, pkt: DHCPPacket, dest_ip: str) -> None:
        """
        Sends a DHCP packet to a specific destination.
        Attempts to bind to the specific interface IP for reliable transmission on multi-NIC hosts.
        """
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sender.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sender.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            # Bind to specific interface to ensure routing on desired NIC
            sender.bind((self.cfg['interface_ip'], 67))
            sender.sendto(pkt.build(), (dest_ip, 68))
        except socket.error as e:
            # Fallback to general socket if binding fails
            try:
                if self.sock:
                    self.sock.sendto(pkt.build(), (dest_ip, 68))
            except socket.error as e2:
                if self.on_status: 
                    self.on_status(f"Critical Transmission Error: {e2}")
        finally:
            sender.close()
