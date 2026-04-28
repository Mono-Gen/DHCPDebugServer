# DHCPDebugServer Manual v1.0.0 (English)

## Overview
A DHCP server with specialized debugging features for testing DHCP client implementations and network troubleshooting.

## Requirements
1. **Administrative Privileges**: Requires binding to UDP port 67. You MUST run `DHCPDebugServer.exe` as an **Administrator**.
2. **Port Conflict**: Ensure "Internet Connection Sharing (ICS)" or other DHCP services are disabled on the host, as they will block port 67.

## Usage

### 1. Starting the Server
- **Network Interface**: Select the adapter to listen on. Click the Refresh button (↻) if your interface is not listed.
- **IP Pool Start/End**: Define the range of IP addresses to lease.
- **Start Server**: Click to begin. If it fails, check for Administrator privileges and port 67 availability.

### 2. Dashboard
- **Status**: Live indicator of server activity.
- **Active Leases**: Table showing assigned IP addresses, client MACs, and lease expiration.

### 3. Advanced Debugging (Debug Tab)
Manipulate server behavior to test client resilience:

- **Drop All Responses**: Silent mode. The server ignores all incoming packets.
- **Ignore Renewal Requests**: Ignores REQUEST packets sent during renewals.
- **Forced NAK**: Sends a DHCPNAK to force the client to restart discovery.
- **Response Delay (ms)**: Introduces latencies to test client timeouts.
- **MAC Filtering**: Deny-list specific clients by MAC address (newline separated). Supports both `00:11:22...` and `00-11-22...` formats.

### 4. Communication Log
- Real-time visualization of DHCP messages (DISCOVER, OFFER, REQUEST, ACK, NAK, etc.).
- **Display Filter**: Supports Wireshark-style logical operators (`&&`, `||`). Filtering is case-insensitive (e.g., `08:0d:d2 && ACK`).
- Color-coded messages and Transaction IDs (XID) for easy tracking.
- **Note (OS Limitation)**: Traffic Logs may display DHCP messages from all network interfaces due to Windows OS constraints.

## Features & Compatibility
- **High Compatibility**: The server always responds via Global Broadcast (255.255.255.255) with the Broadcast Flag (0x8000) set. This ensures connectivity for devices that reject unicast ACKs.
- **Noise Filtering**: The following packets are automatically ignored (and not logged):
    - Packets from outside the selected interface's subnet.
    - Packets addressed to other DHCP servers (mismatched Server Identifier).

## Troubleshooting
- **No logs appearing**: 
    - Verify the interface selection and physical connection.
    - Check Windows Firewall for UDP 67 and 68.
    - Ensure the client is set to "Obtain IP address automatically" (DHCP).
- **Startup Error**: Usually caused by missing Admin rights or port 67 being occupied by another service (e.g., ICS).
