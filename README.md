# DHCP Debug Server

A robust, standalone DHCP server designed for network troubleshooting and debugging DHCP client implementations.

## Features

- **Standard DHCP Operations**: Handles DISCOVER, OFFER, REQUEST, and ACK/NAK sequences.
- **Advanced Debugging Tools**:
  - **Drop All Responses**: Simulate a silent or unresponsive server.
  - **Ignore Renewals**: Test client behavior when renewal requests (T1/T2) are ignored.
  - **Forced NAK**: Force clients to release their current IP and restart discovery.
  - **Custom Response Delay**: Simulate network latency.
  - **MAC Filtering**: Ignore specific clients.
- **Real-time Logging**: Detailed packet inspection with Transaction ID tracking.
- **Portable GUI**: Built with CustomTkinter for a modern, standalone Windows interface.

## Prerequisites

- **Windows Administrator Privileges**: Required to bind to privileged UDP port 67.
- **Disable ICS**: Ensure "Internet Connection Sharing" is disabled to avoid port conflicts.

## Documentation

Manuals are available in English ([manual_EN.md](manual_EN.md)) and Japanese ([manual_JP.md](manual_JP.md)).

### Installation

1. Create a virtual environment: `python -m venv venv`
2. Install dependencies: `pip install -r requirements.txt`
3. Run the application: `python main.py`

### Building Standalone Executable

To build the standalone Windows executable (`.exe`) with the custom icon:

1. Ensure PyInstaller is installed: `pip install pyinstaller`
2. Run the build command: `pyinstaller DHCPDebugServer_v1.0.0.spec`
3. The executable will be generated in the `dist/` directory.

## License

Refer to the repository for licensing information.


