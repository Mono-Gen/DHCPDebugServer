"""
Network Utility Module for DHCP Server

This module provides helper functions to retrieve network interface details using psutil.
"""

import psutil
import socket
from typing import List, Dict

def get_network_interfaces() -> List[Dict[str, str]]:
    """
    Retrieves available IPv4 network interfaces on the host.

    Iterates through all network adapters and filters for valid IPv4 addresses,
    excluding loopback interfaces.

    Returns:
        List[Dict[str, str]]: A list of dictionaries containing:
            - "name": The OS-level name of the interface.
            - "ip": The IPv4 address assigned to the interface.
            - "mask": The subnet mask of the interface.
    """
    interfaces: List[Dict[str, str]] = []
    addrs = psutil.net_if_addrs()
    
    for name, info in addrs.items():
        for addr in info:
            # DHCP server typically operates on IPv4.
            if addr.family == socket.AF_INET: 
                # Skip loopback to avoid binding to local-only traffic.
                if not addr.address.startswith("127."): 
                    interfaces.append({
                        "name": name,
                        "ip": addr.address,
                        "mask": addr.netmask
                    })
    return interfaces
