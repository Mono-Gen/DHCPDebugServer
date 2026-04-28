"""
DHCP Server Core Module

Device: General Network Interface (Ethernet)
Protocol: DHCP (RFC 2131)
Reference: RFC 2131 (DHCP), RFC 2132 (DHCP Options)

This module implements a robust DHCP server with debugging capabilities, 
including packet parsing, building, and handling of lease logic.
It is designed to follow strict resource management and documentation rules.
"""

import socket
import struct
import threading
import time
import random
from typing import Optional, Dict, List, Set, Any, Callable

# --- DHCP Constants (RFC 2131 / RFC 2132) ---
# Operation Codes
DHCP_OP_BOOTREQUEST = 1
DHCP_OP_BOOTREPLY = 2

# Hardware Types
DHCP_HTYPE_ETHERNET = 1
DHCP_HLEN_ETHERNET = 6

# Fixed Offsets and Lengths
# RFC 2131, Section 2: Magic Cookie is the first 4 bytes of the options field.
DHCP_MAGIC_COOKIE = b'\x63\x82\x53\x63'
DHCP_MIN_PACKET_SIZE = 240 # Minimum size to reach the end of the 236-byte header + 4-byte magic cookie.
DHCP_LEGACY_MIN_SIZE = 312 # Minimum size for compatibility with older clients.

# Port Numbers
DHCP_PORT_SERVER = 67
DHCP_PORT_CLIENT = 68

# Socket Settings
SOCKET_RECV_BUFFER_SIZE = 2048
SOCKET_TIMEOUT_SECONDS = 1.0 # 1s timeout to allow periodic check of 'running' flag.

# DHCP Options (RFC 2132)
DHCP_OPT_NETMASK = 1
DHCP_OPT_ROUTER = 3
DHCP_OPT_DNS = 6
DHCP_OPT_BROADCAST_ADDR = 28
DHCP_OPT_REQ_IP = 50
DHCP_OPT_LEASE_TIME = 51
DHCP_OPT_MSG_TYPE = 53
DHCP_OPT_SERVER_ID = 54
DHCP_OPT_END = 255

# DHCP Message Types (Option 53)
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
    - Validate the magic cookie and minimum packet requirements.
    - Build a structured DHCPPacket object back into raw binary data.
    - Provide helper methods for IP string and byte conversions.

    Out of Scope:
    - Networking/Socket management (handled by DHCPServer).
    - Business logic for leases or IP assignments.
    """
    def __init__(self) -> None:
        """Initializes a default DHCP request packet."""
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
        """
        Converts an IPv4 string to a 4-byte packed binary format.
        
        Args:
            ip (str): IPv4 address string (e.g., '192.168.1.1').
            
        Returns:
            bytes: 4-byte packed binary IPv4 address. Returns 0.0.0.0 on failure.
        """
        try:
            return socket.inet_aton(ip)
        except (socket.error, TypeError):
            # Fallback to empty IP if the string is invalid or not provided.
            return b'\x00\x00\x00\x00'

    @staticmethod
    def bytes_to_ip(b: bytes) -> str:
        """
        Converts a 4-byte packed binary IPv4 address to a string.
        
        Args:
            b (bytes): 4-byte packed binary IPv4 address.
            
        Returns:
            str: IPv4 address string.
        """
        return socket.inet_ntoa(b)

    @classmethod
    def parse(cls, data: bytes) -> Optional['DHCPPacket']:
        """
        Parses raw binary DHCP data from the wire.
        
        Args:
            data (bytes): The raw data received from a socket.
            
        Returns:
            Optional[DHCPPacket]: A populated DHCPPacket object if valid, else None.
            Returns None if the packet is too small or the magic cookie is missing.
        """
        # RFC 2131: A DHCP packet must be at least 240 bytes (236 header + 4 magic cookie).
        if len(data) < DHCP_MIN_PACKET_SIZE: 
            return None
            
        pkt = cls()
        # Unpack header: ! (Big-endian), BBBB (op/htype/hlen/hops), I (xid), HH (secs/flags), 
        # 4s (ciaddr), 4s (yiaddr), 4s (siaddr), 4s (giaddr), 16s (chaddr)
        # 4 + 4 + 4 + 4*4 + 16 = 44 bytes for these fields.
        header = struct.unpack("!BBBBIHH4s4s4s4s16s", data[:44])
        pkt.op, pkt.htype, pkt.hlen, pkt.hops, pkt.xid, pkt.secs, pkt.flags, ci, yi, si, gi, ch = header
        pkt.ciaddr, pkt.yiaddr, pkt.siaddr, pkt.giaddr = map(cls.bytes_to_ip, [ci, yi, si, gi])
        pkt.chaddr = ch[:pkt.hlen]
        
        # Verify Magic Cookie at offset 236
        if data[236:240] != pkt.magic_cookie: 
            return None
            
        # Parse Options starting at offset 240
        ptr = 240
        while ptr < len(data):
            opt_type = data[ptr]
            if opt_type == DHCP_OPT_END: 
                break
            if opt_type == 0: # PAD option (ignore)
                ptr += 1
                continue
            if ptr + 1 >= len(data): 
                break
            opt_len = data[ptr + 1]
            if ptr + 2 + opt_len > len(data): 
                # Malformed options: length exceeds packet size
                break
            pkt.options[opt_type] = data[ptr + 2 : ptr + 2 + opt_len]
            ptr += 2 + opt_len
        return pkt

    @staticmethod
    def msg_type_to_str(mtype: int) -> str:
        """
        Converts a DHCP message type code to its human-readable string.
        
        Args:
            mtype (int): Message type code (1-8).
            
        Returns:
            str: Human-readable name of the DHCP message type.
        """
        mapping = {
            DHCP_MSG_DISCOVER: "DISCOVER", 
            DHCP_MSG_OFFER: "OFFER", 
            DHCP_MSG_REQUEST: "REQUEST", 
            DHCP_MSG_DECLINE: "DECLINE",
            DHCP_MSG_ACK: "ACK", 
            DHCP_MSG_NAK: "NAK", 
            DHCP_MSG_RELEASE: "RELEASE", 
            DHCP_MSG_INFORM: "INFORM"
        }
        return mapping.get(mtype, f"UNKNOWN({mtype})")

    def build(self) -> bytes:
        """
        Assembles the internal fields into a binary DHCP packet.
        
        Returns:
            bytes: The assembled binary packet ready for transmission.
        """
        # Pack the fixed 44-byte header
        res = struct.pack("!BBBBIHH4s4s4s4s16s",
            self.op, self.htype, self.hlen, self.hops, self.xid, self.secs, self.flags,
            self.ip_to_bytes(self.ciaddr), self.ip_to_bytes(self.yiaddr),
            self.ip_to_bytes(self.siaddr), self.ip_to_bytes(self.giaddr),
            self.chaddr.ljust(16, b'\x00')
        )
        # RFC 2131: Add 64 bytes sname, 128 bytes file (all zeros for basic implementation)
        # and 4 bytes magic cookie.
        res += b'\x00' * 64 + b'\x00' * 128 + self.magic_cookie
        
        # Append Options
        for ot, ov in self.options.items():
            res += struct.pack("!BB", ot, len(ov)) + ov
        res += struct.pack("!B", DHCP_OPT_END)
        
        # Ensure minimum size (often 312 bytes) for legacy client compatibility.
        if len(res) < DHCP_LEGACY_MIN_SIZE: 
            res += b'\x00' * (DHCP_LEGACY_MIN_SIZE - len(res))
        return res

class DHCPServer:
    """
    Main DHCP Server implementation.
    
    Responsibilities:
    - Listen for DHCP requests on a specific network interface.
    - Manage IPv4 address leases and availability pools.
    - Handle standard DHCP state transitions (DISCOVER/OFFER/REQUEST/ACK).
    - Provide advanced debugging features (dropping, delaying, forcing NAK).
    - Implement robust resource management (socket timeouts, explicit binding).

    Out of Scope:
    - Low-level network interface management (requires external tool/OS API).
    - Permanent persistence of leases (currently in-memory only).
    """
    def __init__(self, cfg: Dict[str, Any]) -> None:
        """
        Initializes the DHCP server with the provided configuration.
        
        Args:
            cfg (Dict[str, Any]): Configuration dictionary containing:
                - 'interface_ip': The IP of the NIC to bind to.
                - 'mask': Subnet mask.
                - 'pool_start': Start of the IP pool.
                - 'pool_end': End of the IP pool.
                - 'lease_time': Duration of leases in seconds.
                - 'router': Default gateway IP.
                - 'dns': DNS server IP.
        """
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
        """
        Starts the DHCP server in a background thread.
        
        Raises:
            RuntimeError: If the socket cannot be opened or bound.
        """
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            
            # Bound to specific interface to ensure routing on desired NIC (Resource Management Rule 7).
            # Note: On some Windows versions, binding to a specific IP might restrict 255.255.255.255 broadcasts.
            # However, we prioritize the 'Explicit Binding' rule here.
            self.sock.bind((self.cfg['interface_ip'], DHCP_PORT_SERVER))
            
            # Set timeout to allow periodic checks of the 'running' flag (Resource Management Rule 5).
            self.sock.settimeout(SOCKET_TIMEOUT_SECONDS)
            
            self.running = True
            threading.Thread(target=self._run, name="DHCPServerLoop", daemon=True).start()
            
            if self.on_status:
                self.on_status(f"Server started on {self.cfg['interface_ip']}:{DHCP_PORT_SERVER}")
        except Exception as e:
            if self.on_status: 
                self.on_status(f"Startup Error: {e}")
            self.stop()
            raise RuntimeError(f"Failed to start DHCP server: {e}")

    def stop(self) -> None:
        """
        Stops the DHCP server and cleans up resources.
        
        Ensures the socket is closed correctly (Resource Management Rule 1).
        """
        self.running = False
        if self.sock:
            try: 
                self.sock.close()
            except socket.error: 
                pass
            self.sock = None
            if self.on_status:
                self.on_status("Server stopped.")

    def _run(self) -> None:
        """
        Main receive loop running in a background thread.
        
        Monitors the socket for incoming UDP packets and dispatches them for processing.
        """
        while self.running and self.sock:
            try:
                data, addr = self.sock.recvfrom(SOCKET_RECV_BUFFER_SIZE)
                pkt = DHCPPacket.parse(data)
                if pkt:
                    self._handle_packet(pkt, addr)
            except socket.timeout:
                # Normal timeout, just check the running flag and continue.
                continue
            except Exception as e:
                if self.running and self.on_status:
                    self.on_status(f"Receive Loop Error: {e}")
                time.sleep(0.1) # Prevent tight loop on persistent errors.

    def _handle_packet(self, pkt: DHCPPacket, addr: tuple) -> None:
        """
        Processes an incoming DHCP packet and determines the appropriate response.
        
        Args:
            pkt (DHCPPacket): The parsed DHCP packet.
            addr (tuple): Source address (IP, Port).
        """
        try:
            if self.drop_all: 
                return
            
            # 1. Interface/Subnet Filtering
            src_ip = addr[0]
            if not self._is_in_subnet(src_ip):
                # Ignore packets from outside the interface's subnet to prevent cross-network noise.
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
            if pkt.giaddr != "0.0.0.0" and not self._is_in_subnet(pkt.giaddr):
                return
            
            # 5. MAC Filtering
            mac_str = pkt.chaddr.hex(":")
            if mac_str in self.mac_filters: 
                return
            
            # 6. Callback for logging (only reached if filtered in)
            if self.on_packet: 
                self.on_packet(pkt, addr)

            # Extract Message Type (Option 53)
            msg_type_data = pkt.options.get(DHCP_OPT_MSG_TYPE)
            if not msg_type_data:
                return
            msg_type = msg_type_data[0]
            
            if msg_type in self.ignored_types: 
                return
            
            # Simulated Latency (Debug Feature)
            if self.delay_ms > 0: 
                time.sleep(self.delay_ms / 1000.0)

            # --- DHCP State Machine ---
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
                        self.on_status(f"Lease released for {mac_str}")
        except Exception as e:
            if self.on_status: 
                self.on_status(f"Packet Processing Error: {e}")

    def _is_in_subnet(self, ip: str) -> bool:
        """
        Heuristic filter to check if an IP belongs to the interface subnet.
        
        Args:
            ip (str): IP address string to check.
            
        Returns:
            bool: True if in subnet or 0.0.0.0, else False.
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
        except (socket.error, struct.error, KeyError):
            return False

    def _get_next_ip(self, mac: str, requested_ip: Optional[str] = None) -> Optional[str]:
        """
        Determines the next available IP address for a client based on pool and current leases.
        
        Args:
            mac (str): Client hardware address (MAC).
            requested_ip (Optional[str]): IP requested by the client.
            
        Returns:
            Optional[str]: Available IPv4 as a string, or None if pool is exhausted.
        """
        # 1. Cleanup expired temporary offers (30s expiry)
        now = time.time()
        expired_macs = [m for m, d in self.offered_ips.items() if now - d['time'] > 30]
        for m in expired_macs: 
            del self.offered_ips[m]

        # 2. Retain existing lease or pending offer if available
        if mac in self.leases: 
            return self.leases[mac]['ip']
        if mac in self.offered_ips: 
            return self.offered_ips[mac]['ip']
        
        try:
            start_int = struct.unpack("!I", socket.inet_aton(self.cfg['pool_start']))[0]
            end_int = struct.unpack("!I", socket.inet_aton(self.cfg['pool_end']))[0]
            
            if start_int > end_int:
                if self.on_status: 
                    self.on_status("Pool Config Error: Start IP is greater than End IP.")
                return None
            
            # Aggregate currently used IPs
            used_ips = {l['ip'] for l in self.leases.values()}
            offered_ips_val = {d['ip'] for d in self.offered_ips.values()}
            unavailable = used_ips | offered_ips_val
            
            # 3. Handle requested IP (Option 50) if it falls within our pool
            if requested_ip and requested_ip != "0.0.0.0":
                req_int = struct.unpack("!I", socket.inet_aton(requested_ip))[0]
                if start_int <= req_int <= end_int and requested_ip not in unavailable:
                    return requested_ip
            
            # 4. Sequential search for the first free IP in the pool
            for i in range(start_int, end_int + 1):
                ip = socket.inet_ntoa(struct.pack("!I", i))
                if ip not in unavailable and ip != self.cfg['interface_ip']:
                    return ip
        except (socket.error, struct.error, KeyError):
            pass
        return None

    def _send_offer(self, discover_pkt: DHCPPacket) -> None:
        """
        Sends a DHCP OFFER in response to a DISCOVER packet.
        
        Args:
            discover_pkt (DHCPPacket): The received DISCOVER packet.
        """
        mac = discover_pkt.chaddr.hex(":")
        # Check if the client requested a specific IP
        req_ip_data = discover_pkt.options.get(DHCP_OPT_REQ_IP)
        req_ip = socket.inet_ntoa(req_ip_data) if req_ip_data else None
        
        assigned = self._get_next_ip(mac, req_ip)
        if not assigned: 
            if self.on_status:
                self.on_status(f"Pool exhausted: Could not assign IP to {mac}")
            return
        
        # Mark as a pending offer to prevent double allocation
        self.offered_ips[mac] = {'ip': assigned, 'time': time.time()}
        
        if self.on_status: 
            self.on_status(f"Offering {assigned} to {mac}")
        self._send_response(discover_pkt, assigned, DHCP_MSG_OFFER)

    def _send_ack(self, request_pkt: DHCPPacket) -> None:
        """
        Sends a DHCP ACK in response to a REQUEST packet.
        
        Args:
            request_pkt (DHCPPacket): The received REQUEST packet.
        """
        mac = request_pkt.chaddr.hex(":")
        # REQUEST might contain the IP in Option 50 or ciaddr
        req_ip_data = request_pkt.options.get(DHCP_OPT_REQ_IP)
        req_ip = socket.inet_ntoa(req_ip_data) if req_ip_data else request_pkt.ciaddr
        
        assigned = self._get_next_ip(mac, req_ip)
        if not assigned:
            # If we cannot fulfill the request, send a NAK to force the client to restart.
            self._send_nak(request_pkt)
            return
        
        # Finalize the lease
        if mac in self.offered_ips: 
            del self.offered_ips[mac]
        
        self.leases[mac] = {
            'ip': assigned, 
            'expiry': time.time() + self.cfg['lease_time']
        }
        
        if self.on_status: 
            self.on_status(f"Acknowledged lease: {assigned} for {mac}")
            
        self._send_response(request_pkt, assigned, DHCP_MSG_ACK)

    def _send_response(self, req_pkt: DHCPPacket, assigned_ip: str, mtype: int) -> None:
        """
        Common logic to build and transmit a DHCP response (OFFER/ACK).
        
        Enforces broadcast response with high-compatibility flags.
        
        Args:
            req_pkt (DHCPPacket): The original request packet.
            assigned_ip (str): IP address being assigned.
            mtype (int): DHCP message type (OFFER or ACK).
        """
        resp = DHCPPacket()
        resp.op = DHCP_OP_BOOTREPLY
        resp.xid = req_pkt.xid
        resp.yiaddr = assigned_ip
        resp.siaddr = "0.0.0.0"
        resp.chaddr = req_pkt.chaddr
        
        # --- ENHANCED COMPATIBILITY MODE ---
        # 1. Force destination to Global Broadcast.
        # Many clients cannot receive unicast responses before they have a local IP.
        dest_ip = "255.255.255.255"

        # 2. Force the DHCP Broadcast Flag (0x8000).
        # Some embedded stacks ignore responses without this flag set.
        resp.flags = 0x8000 
        
        # Standard DHCP Options
        resp.options[DHCP_OPT_MSG_TYPE] = bytes([mtype])
        resp.options[DHCP_OPT_SERVER_ID] = socket.inet_aton(self.cfg['interface_ip'])
        resp.options[DHCP_OPT_LEASE_TIME] = struct.pack("!I", self.cfg['lease_time'])
        resp.options[DHCP_OPT_NETMASK] = socket.inet_aton(self.cfg['mask'])
        resp.options[DHCP_OPT_ROUTER] = socket.inet_aton(self.cfg['router'])
        
        # DNS Configuration
        dns = self.cfg.get('dns')
        if not dns or dns == "0.0.0.0":
            dns = self.cfg['interface_ip'] 
        resp.options[DHCP_OPT_DNS] = socket.inet_aton(dns)

        # Broadcast Address Option (Option 28)
        resp.options[DHCP_OPT_BROADCAST_ADDR] = socket.inet_aton(self._get_broadcast_address())
            
        # RAW Data Logging for diagnostics (Device Control Rule 13)
        if self.on_status:
            pkt_data = resp.build()
            pkt_hex = pkt_data[:48].hex(" ") # Log the first 48 bytes (header) for debugging
            self.on_status(f"TX {DHCPPacket.msg_type_to_str(mtype)} Raw Header: {pkt_hex}")

        self._send_packet(resp, dest_ip)

    def _send_nak(self, request_pkt: DHCPPacket) -> None:
        """
        Sends a DHCP NAK (Negative Acknowledgment) to reject a client's request.
        
        Args:
            request_pkt (DHCPPacket): The rejected REQUEST packet.
        """
        nak = DHCPPacket()
        nak.op = DHCP_OP_BOOTREPLY
        nak.xid = request_pkt.xid
        nak.siaddr = self.cfg['interface_ip']
        nak.chaddr = request_pkt.chaddr
        nak.options[DHCP_OPT_MSG_TYPE] = bytes([DHCP_MSG_NAK])
        nak.options[DHCP_OPT_SERVER_ID] = socket.inet_aton(self.cfg['interface_ip'])
        
        if self.on_status:
            self.on_status(f"Sending NAK to {request_pkt.chaddr.hex(':')}")
            
        # NAKs are typically broadcasted to reach clients without a valid IP.
        self._send_packet(nak, "255.255.255.255")

    def _get_broadcast_address(self) -> str:
        """
        Calculates the subnet broadcast address based on the current configuration.
        
        Returns:
            str: Subnet broadcast IP (e.g., '192.168.1.255'). 
                 Returns '255.255.255.255' as a fallback.
        """
        try:
            mask_val = struct.unpack("!I", socket.inet_aton(self.cfg['mask']))[0]
            ip_val = struct.unpack("!I", socket.inet_aton(self.cfg['interface_ip']))[0]
            # Bitwise OR of the network address and the inverted mask gives the broadcast address.
            b_val = (ip_val & mask_val) | (~mask_val & 0xFFFFFFFF)
            return socket.inet_ntoa(struct.pack("!I", b_val))
        except (socket.error, struct.error, KeyError):
            return "255.255.255.255"

    def _send_packet(self, pkt: DHCPPacket, dest_ip: str) -> None:
        """
        Low-level helper to send a DHCP packet over the wire.
        
        Args:
            pkt (DHCPPacket): The packet to send.
            dest_ip (str): Target IPv4 address.
            
        Note on Rule 7 Exception:
            For broadcast responses (255.255.255.255), this method uses an 
            unbound socket to satisfy RFC 2131. Windows restricts global 
            broadcast from sockets bound to a specific IP (WinError 10049).
        """
        data = pkt.build()
        
        if dest_ip == "255.255.255.255":
            # --- RFC 2131 Compliance Mode ---
            # Use a clean, unbound socket for global broadcast to avoid OS-level 
            # context errors (10049) on Windows while fulfilling the DHCP spec.
            try:
                broadcast_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                broadcast_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                # Note: No bind() here to ensure Windows allows global broadcast.
                broadcast_sock.sendto(data, (dest_ip, DHCP_PORT_CLIENT))
                broadcast_sock.close()
                return
            except socket.error as e:
                if self.on_status: 
                    self.on_status(f"Broadcast TX Error: {e}")
        
        # Standard Unicast or specific transmission using explicit bind (Rule 7)
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sender.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sender.bind((self.cfg['interface_ip'], 0)) # Explicit bind to selected NIC
            sender.sendto(data, (dest_ip, DHCP_PORT_CLIENT))
        except socket.error as e:
            if self.on_status: 
                self.on_status(f"Unicast TX Error: {e}")
        finally:
            sender.close()
