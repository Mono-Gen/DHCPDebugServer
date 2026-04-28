"""
DHCP Debug Server GUI Application

Built with CustomTkinter. 
This module provides a graphical interface to configure, monitor, and 
manipulate the DHCP server behavior for debugging purposes.

It follows the project's UI/UX and documentation rules.
"""

import customtkinter as ctk
import time
import threading
import socket
from typing import Optional, List, Set, Dict, Any, Tuple
from dhcp_server import (
    DHCPServer, DHCPPacket,
    DHCP_MSG_DISCOVER, DHCP_MSG_OFFER, DHCP_MSG_REQUEST, 
    DHCP_MSG_DECLINE, DHCP_MSG_ACK, DHCP_MSG_NAK, 
    DHCP_MSG_RELEASE, DHCP_MSG_INFORM
)
from utils import get_network_interfaces

# --- UI Aesthetics (UI/UX Rule 2) ---
COLOR_CONFIRMED = "#55ff55" # Green: Active / Normal / ON / Confirmed
COLOR_ERROR     = "#ff5555" # Red: Error / Offline / Dangerous
COLOR_PENDING   = "#ffff55" # Yellow: Warning / Pending / Transition
COLOR_OFFLINE   = "#888888" # Gray: Offline / Unconfirmed / Disabled

# Appearance settings
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class App(ctk.CTk):
    """
    Main Application Window class.
    
    Responsibilities:
    - Manage UI lifecycle and component initialization.
    - Synchronize UI state with the background DHCPServer instance.
    - Format and display real-time traffic logs and IP lease status.
    - Handle user interactions and configuration validation.

    Out of Scope:
    - Low-level DHCP protocol logic (handled by DHCPPacket/DHCPServer).
    - Direct network socket operations.
    """
    def __init__(self) -> None:
        """Initializes the main application window and its components."""
        super().__init__()

        self.title("DHCPDebugServer (v1.1.0)")
        self.geometry("1100x850")

        self.server: Optional[DHCPServer] = None
        self.interfaces: List[Dict[str, str]] = []
        self.saved_mac_filters: Set[str] = set()
        self.all_logs: List[Tuple[str, str]] = [] # (timestamp, message)

        # Grid layout (1x2: Sidebar and Content)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # --- Sidebar (Configuration & Control) ---
        self.sidebar = ctk.CTkScrollableFrame(self, width=300, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        
        self.logo_label = ctk.CTkLabel(self.sidebar, text="DHCP Server", font=ctk.CTkFont(size=24, weight="bold"))
        self.logo_label.pack(padx=20, pady=(20, 10))

        # Status Indicator (UI/UX Rule 1)
        self.status_label = ctk.CTkLabel(self.sidebar, text="● Offline", text_color=COLOR_OFFLINE, font=ctk.CTkFont(weight="bold"))
        self.status_label.pack(pady=5)

        # NIC Selection with Refresh
        ctk.CTkLabel(self.sidebar, text="Network Interface:").pack(padx=20, pady=(20, 0), anchor="w")
        self.nic_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        self.nic_frame.pack(padx=20, pady=5, fill="x")
        
        self.nic_var = ctk.StringVar()
        self.nic_menu = ctk.CTkOptionMenu(self.nic_frame, values=[], command=self.on_nic_change_ev)
        self.nic_menu.pack(side="left", fill="x", expand=True)
        
        self.btn_refresh = ctk.CTkButton(self.nic_frame, text="↻", width=30, command=self.refresh_interfaces)
        self.btn_refresh.pack(side="right", padx=(5, 0))

        ctk.CTkLabel(self.sidebar, text="IP Pool Start:").pack(padx=20, pady=(10, 0), anchor="w")
        self.entry_start = ctk.CTkEntry(self.sidebar)
        self.entry_start.insert(0, "192.168.1.100")
        self.entry_start.pack(padx=20, pady=5, fill="x")

        ctk.CTkLabel(self.sidebar, text="IP Pool End:").pack(padx=20, pady=(10, 0), anchor="w")
        self.entry_end = ctk.CTkEntry(self.sidebar)
        self.entry_end.insert(0, "192.168.1.200")
        self.entry_end.pack(padx=20, pady=5, fill="x")

        ctk.CTkLabel(self.sidebar, text="Subnet Mask:").pack(padx=20, pady=(10, 0), anchor="w")
        self.entry_mask = ctk.CTkEntry(self.sidebar)
        self.entry_mask.insert(0, "255.255.255.0")
        self.entry_mask.pack(padx=20, pady=5, fill="x")

        ctk.CTkLabel(self.sidebar, text="Default Gateway:").pack(padx=20, pady=(10, 0), anchor="w")
        self.entry_router = ctk.CTkEntry(self.sidebar)
        self.entry_router.insert(0, "0.0.0.0")
        self.entry_router.pack(padx=20, pady=5, fill="x")

        ctk.CTkLabel(self.sidebar, text="DNS Server:").pack(padx=20, pady=(10, 0), anchor="w")
        self.entry_dns = ctk.CTkEntry(self.sidebar)
        self.entry_dns.insert(0, "8.8.8.8")
        self.entry_dns.pack(padx=20, pady=5, fill="x")

        ctk.CTkLabel(self.sidebar, text="Lease Duration (sec):").pack(padx=20, pady=(10, 0), anchor="w")
        self.entry_lease = ctk.CTkEntry(self.sidebar)
        self.entry_lease.insert(0, "86400")
        self.entry_lease.pack(padx=20, pady=5, fill="x")

        self.btn_toggle = ctk.CTkButton(self.sidebar, text="Start Server", fg_color="#1f538d", command=self.toggle_server)
        self.btn_toggle.pack(padx=20, pady=(30, 20), fill="x")

        # --- Content Area ---
        self.tabview = ctk.CTkTabview(self)
        self.tabview.grid(row=0, column=1, padx=(20, 20), pady=(10, 20), sticky="nsew")
        self.tabview.add("Dashboard")
        self.tabview.add("Traffic Logs")
        self.tabview.add("Advanced Debug")

        # Tab: Dashboard
        self.dashboard_frame = self.tabview.tab("Dashboard")
        self.btn_clear_leases = ctk.CTkButton(self.dashboard_frame, text="Reset Lease Info", width=150, height=24, fg_color="#444444", command=self.clear_leases)
        self.btn_clear_leases.pack(pady=(5, 0), anchor="e", padx=10)
        
        self.lease_list = ctk.CTkTextbox(self.dashboard_frame, font=("monospace", 13))
        self.lease_list.pack(fill="both", expand=True, padx=10, pady=10)

        # Tab: Logs
        self.logs_frame = self.tabview.tab("Traffic Logs")
        
        # Log Control Frame (Filter + Clear)
        self.log_ctrl_frame = ctk.CTkFrame(self.logs_frame, fg_color="transparent")
        self.log_ctrl_frame.pack(fill="x", padx=10, pady=(5, 0))
        
        self.log_filter_var = ctk.StringVar()
        self.log_filter_var.trace_add("write", lambda *args: self.refresh_log())
        
        # Explicit label for filter operators (visibility improvement)
        self.log_filter_label = ctk.CTkLabel(self.log_ctrl_frame, text="Filter (&&, ||):", font=ctk.CTkFont(size=12, weight="bold"))
        self.log_filter_label.pack(side="left", padx=(0, 5))

        self.log_filter_entry = ctk.CTkEntry(
            self.log_ctrl_frame, 
            placeholder_text="e.g. ACK && 00:0f... || DISCOVER", 
            textvariable=self.log_filter_var
        )
        self.log_filter_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        self.btn_clear_logs = ctk.CTkButton(self.log_ctrl_frame, text="Clear Logs", width=80, height=24, fg_color="#444444", command=self.clear_log)
        self.btn_clear_logs.pack(side="right")
        
        self.log_text = ctk.CTkTextbox(self.logs_frame, font=("monospace", 12))
        self.log_text.pack(fill="both", expand=True, padx=10, pady=10)

        # Tab: Debug
        self.debug_frame = self.tabview.tab("Advanced Debug")
        self.silent_mode = ctk.BooleanVar(value=False)
        self.sw_silent = ctk.CTkSwitch(self.debug_frame, text="Drop all responses (Silent Mode)", variable=self.silent_mode, command=self.update_debug)
        self.sw_silent.pack(padx=20, pady=10, anchor="w")

        ctk.CTkLabel(self.debug_frame, text="Packet Type Filter (Ignore checked):", font=ctk.CTkFont(weight="bold")).pack(padx=20, pady=(10, 0), anchor="w")
        self.filter_vars: Dict[int, ctk.BooleanVar] = {
            DHCP_MSG_DISCOVER: ctk.BooleanVar(value=False),
            DHCP_MSG_REQUEST: ctk.BooleanVar(value=False),
            DHCP_MSG_INFORM: ctk.BooleanVar(value=False),
            DHCP_MSG_RELEASE: ctk.BooleanVar(value=False),
        }
        self.filter_frame = ctk.CTkFrame(self.debug_frame, fg_color="transparent")
        self.filter_frame.pack(padx=40, pady=5, anchor="w")
        
        ctk.CTkCheckBox(self.filter_frame, text="DISCOVER", variable=self.filter_vars[DHCP_MSG_DISCOVER], command=self.update_debug).pack(side="left", padx=10)
        ctk.CTkCheckBox(self.filter_frame, text="REQUEST", variable=self.filter_vars[DHCP_MSG_REQUEST], command=self.update_debug).pack(side="left", padx=10)
        ctk.CTkCheckBox(self.filter_frame, text="INFORM", variable=self.filter_vars[DHCP_MSG_INFORM], command=self.update_debug).pack(side="left", padx=10)
        ctk.CTkCheckBox(self.filter_frame, text="RELEASE", variable=self.filter_vars[DHCP_MSG_RELEASE], command=self.update_debug).pack(side="left", padx=10)

        self.ignore_renew = ctk.BooleanVar(value=False)
        self.sw_renew = ctk.CTkSwitch(self.debug_frame, text="Ignore Renew/Rebind only", variable=self.ignore_renew, command=self.update_debug)
        self.sw_renew.pack(padx=20, pady=10, anchor="w")

        self.nak_mode = ctk.BooleanVar(value=False)
        self.sw_nak = ctk.CTkSwitch(self.debug_frame, text="Force NAK responses (for NAK testing)", variable=self.nak_mode, command=self.update_debug)
        self.sw_nak.pack(padx=20, pady=10, anchor="w")

        self.delay_label = ctk.CTkLabel(self.debug_frame, text="Response Delay (ms): 0")
        self.delay_label.pack(padx=20, pady=(20, 0), anchor="w")
        self.delay_slider = ctk.CTkSlider(self.debug_frame, from_=0, to=10000, number_of_steps=100, command=self.update_debug)
        self.delay_slider.set(0)
        self.delay_slider.pack(padx=20, pady=5, fill="x")

        self.mac_filter_label = ctk.CTkLabel(self.debug_frame, text="MAC/Client Ignore (newline separated):")
        self.mac_filter_label.pack(padx=20, pady=(20, 0), anchor="w")
        self.mac_filter_text = ctk.CTkTextbox(self.debug_frame, height=80)
        self.mac_filter_text.pack(padx=20, pady=5, fill="x")
        self.btn_apply_filter = ctk.CTkButton(self.debug_frame, text="Apply Filter", command=self.apply_mac_filter)
        self.btn_apply_filter.pack(padx=20, pady=(5, 10))

        self.refresh_interfaces()

    def refresh_interfaces(self) -> None:
        """
        Updates the network interface list in the sidebar dropdown.
        
        Fetches current NICs from the OS and populates the UI menu.
        """
        try:
            self.interfaces = get_network_interfaces()
            # Format: 'Interface Name (IP Address)'
            vals = [f"{i['name']} ({i['ip']})" for i in self.interfaces]
            self.nic_menu.configure(values=vals)
            
            # Auto-select the first interface if nothing is selected.
            if vals and not self.nic_var.get():
                self.nic_menu.set(vals[0])
                self.nic_var.set(vals[0].split("(")[-1].strip(")"))
            self.add_log("Interface list refreshed.")
        except Exception as e:
            self.add_log(f"NIC Retrieval Error: {e}")

    def on_nic_change_ev(self, val: str) -> None:
        """
        Handles selection changes in the NIC dropdown and suggests network settings.
        
        Args:
            val (str): The selected item from the OptionMenu.
        """
        ip = val.split("(")[-1].strip(")")
        self.nic_var.set(ip)
        
        # Search for interface metadata to suggest appropriate subnet mask and defaults.
        iface = next((i for i in self.interfaces if i['ip'] == ip), None)
        if iface:
            # Update Mask
            self.entry_mask.delete(0, "end")
            self.entry_mask.insert(0, iface['mask'])
            
            # Suggest Router (usually the interface IP itself for simple debugging setups)
            self.entry_router.delete(0, "end")
            self.entry_router.insert(0, ip)
            
            # Suggest Pool Start/End (.100 to .150 on the same C-class subnet)
            try:
                base = ".".join(ip.split(".")[:3]) + "."
                self.entry_start.delete(0, "end")
                self.entry_start.insert(0, f"{base}100")
                self.entry_end.delete(0, "end")
                self.entry_end.insert(0, f"{base}150")
            except Exception:
                # Ignore failures in suggestion logic.
                pass

    def _match_filter(self, msg: str) -> bool:
        """
        Evaluates if a log message matches the current UI display filter.
        
        Supports Wireshark-style logical operators (&&, ||).
        
        Args:
            msg (str): The log message string.
            
        Returns:
            bool: True if it matches the filter, False otherwise.
        """
        f_text = self.log_filter_var.get().lower().strip()
        if not f_text:
            return True
        
        msg_l = msg.lower()
        # Evaluate OR groups first, then AND requirements within them.
        or_groups = f_text.split("||")
        for group in or_groups:
            and_requirements = [req.strip() for req in group.split("&&") if req.strip()]
            if not and_requirements:
                continue
            if all(req in msg_l for req in and_requirements):
                return True
        return False

    def add_log(self, msg: str) -> None:
        """
        Appends a message to the internal history and logs it to the UI if it matches filters.
        
        Args:
            msg (str): Message to log.
        """
        timestamp = time.strftime("%H:%M:%S")
        self.all_logs.append((timestamp, msg))
        
        # Limit history size to prevent memory leaks (Resource Management Rule 2).
        if len(self.all_logs) > 5000:
            self.all_logs.pop(0)
        
        # Apply filter in real-time for UI performance.
        if self._match_filter(msg):
            self.log_text.insert("end", f"[{timestamp}] {msg}\n")
            self.log_text.see("end")

    def refresh_log(self) -> None:
        """Clears and re-renders the log window based on the current filter."""
        self.log_text.delete("1.0", "end")
        for timestamp, msg in self.all_logs:
            if self._match_filter(msg):
                self.log_text.insert("end", f"[{timestamp}] {msg}\n")
        self.log_text.see("end")

    def clear_log(self) -> None:
        """Clears both internal history and the UI log window."""
        self.all_logs.clear()
        self.log_text.delete("1.0", "end")
        self.add_log("Log history cleared.")

    def update_leases(self) -> None:
        """
        Updates the IP lease table in the Dashboard tab.
        
        Reflects the current state of the DHCPServer's lease database.
        """
        self.lease_list.delete("1.0", "end")
        self.lease_list.insert("1.0", f"{'IP Address':<20} {'MAC Address':<20} {'Remaining'}\n")
        self.lease_list.insert("end", "-"*60 + "\n")
        
        if not self.server: 
            return
            
        now = time.time()
        for mac, data in self.server.leases.items():
            remaining = int(data['expiry'] - now)
            self.lease_list.insert("end", f"{data['ip']:<20} {mac:<20} {remaining}s\n")

    def on_packet(self, pkt: DHCPPacket, addr: tuple) -> None:
        """
        Callback triggered by the DHCPServer for each processed packet.
        
        Synchronizes packet details with the UI log.
        
        Args:
            pkt (DHCPPacket): The parsed DHCP packet.
            addr (tuple): Source address (IP, Port).
        """
        msg_types = {
            DHCP_MSG_DISCOVER: "DISCOVER",
            DHCP_MSG_OFFER: "OFFER",
            DHCP_MSG_REQUEST: "REQUEST",
            DHCP_MSG_DECLINE: "DECLINE",
            DHCP_MSG_ACK: "ACK",
            DHCP_MSG_NAK: "NAK",
            DHCP_MSG_RELEASE: "RELEASE",
            DHCP_MSG_INFORM: "INFORM"
        }
        
        mtype_data = pkt.options.get(53, b'\x00')
        mtype = mtype_data[0]
        type_name = msg_types.get(mtype, "UNKNOWN")
        
        info = f"Recv {type_name} from {pkt.chaddr.hex(':')} (XID: {hex(pkt.xid)})"
        
        # Schedule UI updates on the main thread (UI/UX Rule 3).
        self.after(0, lambda: self.add_log(info))
        self.after(0, self.update_leases)

    def clear_leases(self) -> None:
        """Resets active lease data on the server and clears the UI table."""
        if self.server:
            self.server.leases = {}
        self.update_leases()
        self.add_log("Lease data reset.")

    def toggle_server(self) -> None:
        """
        Starts or stops the DHCP server.
        
        Handles UI state transitions and error reporting.
        """
        if self.server and self.server.running:
            # Transition to Offline
            self.server.stop()
            self.server = None
            self.btn_toggle.configure(text="Start Server", fg_color="#1f538d")
            self.status_label.configure(text="● Offline", text_color=COLOR_OFFLINE)
            self.add_log("Server stopped.")
        else:
            try:
                # Transition to Pending (UI/UX Rule 1)
                self.status_label.configure(text="● Pending", text_color=COLOR_PENDING)
                self.update_idletasks() # Ensure the label update is visible immediately.
                
                ip = self.nic_var.get()
                if not ip: 
                    raise ValueError("Please select a network interface.")
                
                # Dynamic configuration from entry fields
                lease_time = int(self.entry_lease.get())
                if lease_time <= 0: 
                    raise ValueError("Lease time must be a positive integer.")

                gw = self.entry_router.get()
                if gw == "0.0.0.0" or not gw: 
                    # Default gateway suggestion
                    gw = ip 

                cfg = {
                    'interface_ip': ip,
                    'pool_start': self.entry_start.get(),
                    'pool_end': self.entry_end.get(),
                    'mask': self.entry_mask.get(),
                    'router': gw,
                    'dns': self.entry_dns.get(),
                    'lease_time': lease_time
                }
                
                self.server = DHCPServer(cfg)
                self.server.on_packet = self.on_packet
                self.server.on_status = lambda msg: self.after(0, lambda: self.add_log(f"Server Status: {msg}"))
                
                # Apply debug settings before starting
                self.update_debug() 
                self.apply_mac_filter()
                
                self.server.start()
                
                # Transition to Confirmed/Active
                self.btn_toggle.configure(text="Stop Server", fg_color="#8d1f1f")
                self.status_label.configure(text="● Active", text_color=COLOR_CONFIRMED)
                self.add_log(f"Server successfully started on {ip}:67")
                
            except ValueError as ve:
                self.status_label.configure(text="● Error", text_color=COLOR_ERROR)
                self.add_log(f"Configuration Error: {ve}")
            except Exception as e:
                self.status_label.configure(text="● Error", text_color=COLOR_ERROR)
                self.add_log(f"Critical Startup Failure: {e}")

    def update_debug(self, val: Any = None) -> None:
        """
        Synchronizes debug tab switch/slider settings to the running server instance.
        
        Args:
            val (Any): Ignored. Used for event callbacks.
        """
        d_val = int(self.delay_slider.get())
        self.delay_label.configure(text=f"Response Delay (ms): {d_val}")

        if not self.server: 
            return
            
        self.server.drop_all = self.silent_mode.get()
        self.server.ignore_renewals = self.ignore_renew.get()
        self.server.nak_mode = self.nak_mode.get()
        self.server.ignored_types = {k for k, v in self.filter_vars.items() if v.get()}
        self.server.delay_ms = d_val
        self.add_log(f"Debug settings updated (Delay: {d_val}ms)")

    def apply_mac_filter(self) -> None:
        """Parses the MAC filter textbox and applies the resulting list to the server."""
        raw_text = self.mac_filter_text.get("1.0", "end").strip()
        mac_list: List[str] = []
        for line in raw_text.split("\n"):
            # Standardize MAC format to lower case with colon separators.
            m = line.strip().lower().replace("-", ":")
            if m: 
                mac_list.append(m)
        self.saved_mac_filters = set(mac_list)
        
        if self.server:
            self.server.mac_filters = self.saved_mac_filters
            self.add_log(f"MAC filter applied ({len(self.saved_mac_filters)} entries)")
        else:
            self.add_log(f"MAC filter saved (will apply on server start)")

if __name__ == "__main__":
    app = App()
    app.mainloop()
