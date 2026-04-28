"""
Network Utility Module for DHCP Server

Device: General Network Interface (Ethernet/Wi-Fi)
Protocol: IPv4 / Interface Retrieval

This module provides helper functions to retrieve network interface details 
(IP, Name, Subnet Mask) using the psutil library. It is essential for 
selecting the correct NIC to bind the DHCP server.
"""

import psutil
import socket
from typing import List, Dict

def get_network_interfaces() -> List[Dict[str, str]]:
    """
    Retrieves a list of available IPv4 network interfaces on the host.

    This function iterates through all network adapters detected by the OS, 
    filtering for valid IPv4 configurations and excluding loopback (127.0.0.1).

    Returns:
        List[Dict[str, str]]: A list of interface metadata dictionaries. 
            Each dictionary contains:
            - "name" (str): The OS-level identifier/name of the interface.
            - "ip" (str): The assigned IPv4 address.
            - "mask" (str): The subnet mask.
            
    Why:
        DHCP servers must bind to a specific physical or virtual network interface 
        to correctly process broadcast packets and manage IP pools for a specific segment.
    """
    interfaces: List[Dict[str, str]] = []
    # Fetch all address information for all interfaces.
    addrs = psutil.net_if_addrs()
    
    for name, info in addrs.items():
        for addr in info:
            # We only care about IPv4 for this DHCP server implementation.
            if addr.family == socket.AF_INET: 
                # Skip loopback to avoid binding to internal-only traffic.
                if not addr.address.startswith("127."): 
                    interfaces.append({
                        "name": name,
                        "ip": addr.address,
                        "mask": addr.netmask
                    })
    return interfaces
