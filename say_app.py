"""Project S.A.Y. (Safely Attack Yourself) - IDS Traffic Testbench.

A standalone educational network traffic generator and IDS evaluation tool.
Crafts and transmits controlled, synthetic packet sequences (TCP SYN bursts,
ICMP ping floods, UDP port sweeps, and custom probes) to validate intrusion
detection rules safely on local interfaces.
"""

from __future__ import annotations

import ctypes
import datetime
import ipaddress
import os
import queue
import random
import socket
import sys
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import customtkinter as ctk
from scapy.all import ICMP, IP, TCP, UDP, Ether, conf, sendp

# ----------------------------------------------------------------------
# Configuration & Constants
# ----------------------------------------------------------------------
APP_TITLE = "Project S.A.Y."
APP_SUBTITLE = "Safely Attack Yourself | IDS Testbench"
WINDOW_GEOMETRY = "980x640"
MIN_WINDOW_SIZE = (920, 600)

COLOR_PRIMARY = "#3498db"
COLOR_PRIMARY_HOVER = "#2980b9"
COLOR_DANGER = "#e74c3c"
COLOR_DANGER_HOVER = "#c0392b"
COLOR_SUCCESS = "#2ecc71"
COLOR_WARNING = "#f39c12"
COLOR_MUTED = "#8c92a4"
COLOR_BG_DARK = "#12141a"
COLOR_CARD_DARK = "#1a1d26"
COLOR_CARD_BORDER = "#2a2e3d"
COLOR_CONSOLE_BG = "#0d0f14"

# Attack Presets Definition
ATTACK_PRESETS: Dict[str, Dict[str, Any]] = {
    "TCP SYN Burst (8 pkts -> Tests Rule 1)": {
        "protocol": "TCP",
        "count": 8,
        "delay": 0.05,
        "port": 80,
        "is_sweep": False,
        "customizable": False,
        "description": "Bursts 8 rapid TCP SYN packets to port 80 with sequential sequences to test SYN flood detection.",
    },
    "ICMP Ping Flood (12 pkts -> Tests Rule 2)": {
        "protocol": "ICMP",
        "count": 12,
        "delay": 0.05,
        "port": 0,
        "is_sweep": False,
        "customizable": False,
        "description": "Transmits 12 rapid ICMP Echo Requests with sequential identifiers to test ICMP rate thresholds.",
    },
    "UDP Port Sweep (18 pkts -> Tests Rule 3)": {
        "protocol": "UDP",
        "count": 18,
        "delay": 0.05,
        "port": 5000,
        "is_sweep": True,
        "customizable": False,
        "description": "Sweeps 18 UDP datagrams across sequential destination ports 5000-5017 to trigger port scan rules.",
    },
    "Stealth Baseline (2 pkts, slow -> Benign Test)": {
        "protocol": "TCP",
        "count": 2,
        "delay": 0.75,
        "port": 443,
        "is_sweep": False,
        "customizable": False,
        "description": "Transmits 2 low-frequency TCP packets spaced 0.75s apart as a baseline benign reference test.",
    },
    "Custom Attack Configuration": {
        "protocol": "TCP",
        "count": 10,
        "delay": 0.10,
        "port": 80,
        "is_sweep": False,
        "customizable": True,
        "description": "User-defined attack parameters with custom packet volume, delay, protocol, and port settings.",
    },
}


# ----------------------------------------------------------------------
# Helper Utilities
# ----------------------------------------------------------------------
def check_admin_privileges() -> bool:
    """Check if the current process is running with administrative privileges."""
    try:
        if sys.platform.startswith("win"):
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        else:
            return os.geteuid() == 0  # type: ignore[attr-defined]
    except Exception:
        return False


def get_local_ipv4() -> str:
    """Discover the active local IPv4 interface using a non-sending UDP socket."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Does not actually transmit packets over the wire, but causes the OS
        # routing table to select the preferred outgoing interface.
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        if ip and not ip.startswith("127."):
            return ip
    except Exception:
        pass
    finally:
        s.close()

    # Fallback to local hostname resolution
    try:
        host_ip = socket.gethostbyname(socket.gethostname())
        if host_ip and not host_ip.startswith("127."):
            return host_ip
    except Exception:
        pass

    return "127.0.0.1"


def validate_ipv4(ip_str: str) -> Tuple[bool, str]:
    """Validate that the given string is a legitimate IPv4 address.

    Returns (is_valid, error_message).
    """
    clean_ip = ip_str.strip()
    if not clean_ip:
        return False, "Target IP address cannot be empty."
    try:
        ipaddress.IPv4Address(clean_ip)
        return True, ""
    except ipaddress.AddressValueError:
        return False, f"'{clean_ip}' is not a valid IPv4 address."


# ----------------------------------------------------------------------
# Background Attack Generator Engine
# ----------------------------------------------------------------------
@dataclass
class AttackConfig:
    attacker_ip: str
    target_ip: str
    protocol: str  # "TCP", "ICMP", "UDP"
    count: int
    delay: float
    port: int
    is_sweep: bool
    preset_name: str


class AttackWorker(threading.Thread):
    """Background daemon thread executing Scapy Layer 2 frame crafting and injection."""

    def __init__(
        self,
        config: AttackConfig,
        msg_queue: queue.Queue,
        abort_event: threading.Event,
    ) -> None:
        super().__init__(daemon=True)
        self.config = config
        self.msg_queue = msg_queue
        self.abort_event = abort_event

    def run(self) -> None:
        cfg = self.config
        total = cfg.count
        start_time = time.time()

        self._emit_log(
            f"--- STARTING SIMULATION: {cfg.preset_name} ---",
            level="HEADER",
        )
        self._emit_log(
            f"Attacker: {cfg.attacker_ip} -> Target: {cfg.target_ip} | "
            f"Protocol: {cfg.protocol} | Count: {total} | Delay: {cfg.delay:.2f}s | "
            f"Base Port: {cfg.port} | Interface: {conf.iface}",
            level="INFO",
        )

        injected_count = 0
        seq_base = random.randint(1000, 50000)
        icmp_id = random.randint(1, 65535)

        for i in range(total):
            if self.abort_event.is_set():
                elapsed = time.time() - start_time
                self._emit_log(
                    f"[{datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]}] "
                    f"ABORTED by user after {injected_count} packets.",
                    level="WARN",
                )
                self.msg_queue.put(
                    (
                        "ABORTED",
                        injected_count,
                        total,
                        elapsed,
                        f"Aborted after {injected_count}/{total} packets.",
                    )
                )
                return

            timestamp_str = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
            log_line = ""

            try:
                ip_layer = IP(src=cfg.attacker_ip, dst=cfg.target_ip)

                if cfg.protocol == "TCP":
                    current_port = cfg.port + (i if cfg.is_sweep else 0)
                    seq_num = seq_base + (i * 100)
                    tcp_layer = TCP(
                        sport=random.randint(49152, 65530),
                        dport=current_port,
                        flags="S",
                        seq=seq_num,
                    )
                    frame = Ether() / ip_layer / tcp_layer
                    sendp(frame, iface=conf.iface, verbose=False)
                    log_line = (
                        f"[{timestamp_str}] INJECTED: TCP SYN -> "
                        f"{cfg.target_ip}:{current_port} | Seq={seq_num}"
                    )

                elif cfg.protocol == "ICMP":
                    seq_num = i + 1
                    icmp_layer = ICMP(
                        type=8,
                        code=0,
                        id=icmp_id,
                        seq=seq_num,
                    )
                    frame = Ether() / ip_layer / icmp_layer
                    sendp(frame, iface=conf.iface, verbose=False)
                    log_line = (
                        f"[{timestamp_str}] INJECTED: ICMP Echo -> "
                        f"{cfg.target_ip} | ID={icmp_id}, Seq={seq_num}"
                    )

                elif cfg.protocol == "UDP":
                    current_port = cfg.port + (i if cfg.is_sweep else 0)
                    payload = f"SAY_PROBE_PKT_{i+1}".encode("utf-8")
                    udp_layer = UDP(
                        sport=random.randint(49152, 65530),
                        dport=current_port,
                    )
                    frame = Ether() / ip_layer / udp_layer / payload
                    sendp(frame, iface=conf.iface, verbose=False)
                    log_line = (
                        f"[{timestamp_str}] INJECTED: UDP Datagram -> "
                        f"{cfg.target_ip}:{current_port}"
                    )

                injected_count += 1
                elapsed = time.time() - start_time
                self._emit_log(log_line, level="PKT")
                self.msg_queue.put(
                    ("PROGRESS", injected_count, total, elapsed, None)
                )

            except PermissionError as pe:
                self._emit_log(
                    f"[{timestamp_str}] PERMISSION ERROR: Raw sockets require Administrator privileges ({pe})",
                    level="ERROR",
                )
                self.msg_queue.put(
                    ("ERROR", injected_count, total, time.time() - start_time, str(pe))
                )
                return
            except OSError as oe:
                self._emit_log(
                    f"[{timestamp_str}] NETWORK/OS ERROR: {oe}",
                    level="ERROR",
                )
                self.msg_queue.put(
                    ("ERROR", injected_count, total, time.time() - start_time, str(oe))
                )
                return
            except Exception as ex:
                self._emit_log(
                    f"[{timestamp_str}] UNEXPECTED EXCEPTION: {ex}",
                    level="ERROR",
                )
                self.msg_queue.put(
                    ("ERROR", injected_count, total, time.time() - start_time, str(ex))
                )
                return

            # Inter-packet delay with granular polling for prompt abort response
            if i < total - 1:
                sleep_needed = cfg.delay
                step = 0.02
                while sleep_needed > 0:
                    if self.abort_event.is_set():
                        break
                    time_to_sleep = min(step, sleep_needed)
                    time.sleep(time_to_sleep)
                    sleep_needed -= time_to_sleep

        elapsed = time.time() - start_time
        self._emit_log(
            f"--- SIMULATION FINISHED: {injected_count}/{total} packets transmitted in {elapsed:.2f}s ---",
            level="SUCCESS",
        )
        self.msg_queue.put(
            (
                "COMPLETED",
                injected_count,
                total,
                elapsed,
                f"Successfully injected {injected_count} packets.",
            )
        )

    def _emit_log(self, text: str, level: str = "INFO") -> None:
        self.msg_queue.put(("LOG", text, level))


# ----------------------------------------------------------------------
# Main Application GUI
# ----------------------------------------------------------------------
class SayApp(ctk.CTk):
    """Modern Dark-Theme CustomTkinter GUI for Project S.A.Y."""

    def __init__(self) -> None:
        super().__init__()

        # Appearance & Window Configuration
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")

        self.title(f"{APP_TITLE} - IDS Traffic Testbench")
        self.geometry(WINDOW_GEOMETRY)
        self.minsize(*MIN_WINDOW_SIZE)

        # Threading & State Control
        self.msg_queue: queue.Queue = queue.Queue()
        self.abort_event = threading.Event()
        self.worker_thread: Optional[AttackWorker] = None
        self.is_running = False
        self.is_admin = check_admin_privileges()
        self.detected_ip = get_local_ipv4()
        self._is_updating_preset = False

        # Build UI Components
        self._build_layout()
        self._apply_preset(list(ATTACK_PRESETS.keys())[0])

        # Start periodic queue processing
        self.after(50, self._process_queue)

    def _build_layout(self) -> None:
        """Construct the two-column responsive grid layout."""
        self.grid_columnconfigure(0, weight=0, minsize=340)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_telemetry_panel()

    # ------------------------------------------------------------------
    # Left Sidebar: Configuration Panel
    # ------------------------------------------------------------------
    def _build_sidebar(self) -> None:
        self.sidebar_frame = ctk.CTkFrame(
            self,
            width=340,
            corner_radius=0,
            fg_color=COLOR_CARD_DARK,
        )
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew", padx=0, pady=0)
        self.sidebar_frame.grid_propagate(False)

        # Scrollable container inside sidebar to guarantee fit on smaller screens
        self.sidebar_scroll = ctk.CTkScrollableFrame(
            self.sidebar_frame,
            fg_color="transparent",
            label_text="",
        )
        self.sidebar_scroll.pack(fill="both", expand=True, padx=16, pady=16)

        # 1. Header & Branding
        header_title = ctk.CTkLabel(
            self.sidebar_scroll,
            text=APP_TITLE,
            font=ctk.CTkFont(family="Segoe UI", size=22, weight="bold"),
            text_color="#ffffff",
            anchor="w",
        )
        header_title.pack(fill="x", pady=(0, 2))

        header_sub = ctk.CTkLabel(
            self.sidebar_scroll,
            text=APP_SUBTITLE,
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=COLOR_MUTED,
            anchor="w",
        )
        header_sub.pack(fill="x", pady=(0, 14))

        # 2. Privileges Badge
        admin_text = "Admin: Active" if self.is_admin else "Admin: Required for Raw Sockets"
        admin_color = COLOR_SUCCESS if self.is_admin else COLOR_DANGER
        self.admin_badge = ctk.CTkLabel(
            self.sidebar_scroll,
            text=admin_text,
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color=admin_color,
            fg_color="#12141a",
            corner_radius=6,
            height=26,
        )
        self.admin_badge.pack(fill="x", pady=(0, 16))

        # 3. Target IPv4 Entry with Auto-Detect
        target_lbl = ctk.CTkLabel(
            self.sidebar_scroll,
            text="Target IPv4 Address:",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color="#e0e0e0",
            anchor="w",
        )
        target_lbl.pack(fill="x", pady=(0, 4))

        ip_container = ctk.CTkFrame(self.sidebar_scroll, fg_color="transparent")
        ip_container.pack(fill="x", pady=(0, 4))

        self.target_entry = ctk.CTkEntry(
            ip_container,
            placeholder_text="e.g., 172.17.91.4",
            font=ctk.CTkFont(family="Consolas", size=12),
            height=34,
        )
        self.target_entry.insert(0, self.detected_ip)
        self.target_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))

        self.btn_refresh_ip = ctk.CTkButton(
            ip_container,
            text="↻",
            width=36,
            height=34,
            fg_color="#2b3140",
            hover_color="#3c4357",
            font=ctk.CTkFont(size=14, weight="bold"),
            command=self._refresh_detected_ip,
        )
        self.btn_refresh_ip.pack(side="right")

        self.ip_status_lbl = ctk.CTkLabel(
            self.sidebar_scroll,
            text=f"Auto-detected active host interface: {self.detected_ip}",
            font=ctk.CTkFont(family="Segoe UI", size=10),
            text_color=COLOR_MUTED,
            anchor="w",
        )
        self.ip_status_lbl.pack(fill="x", pady=(0, 12))

        # 4. Simulated Attacker IP Entry (Layer 2 frame source)
        attacker_lbl = ctk.CTkLabel(
            self.sidebar_scroll,
            text="Simulated Attacker IP:",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color="#e0e0e0",
            anchor="w",
        )
        attacker_lbl.pack(fill="x", pady=(0, 4))

        self.attacker_entry = ctk.CTkEntry(
            self.sidebar_scroll,
            placeholder_text="e.g., 10.0.0.99",
            font=ctk.CTkFont(family="Consolas", size=12),
            height=34,
        )
        self.attacker_entry.insert(0, "10.0.0.99")
        self.attacker_entry.pack(fill="x", pady=(0, 4))

        self.attacker_status_lbl = ctk.CTkLabel(
            self.sidebar_scroll,
            text="Spoofed source IP for Layer 2 frame (IDS alert source)",
            font=ctk.CTkFont(family="Segoe UI", size=10),
            text_color=COLOR_MUTED,
            anchor="w",
        )
        self.attacker_status_lbl.pack(fill="x", pady=(0, 16))

        # 5. Attack Preset Selector
        preset_lbl = ctk.CTkLabel(
            self.sidebar_scroll,
            text="Attack Preset:",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color="#e0e0e0",
            anchor="w",
        )
        preset_lbl.pack(fill="x", pady=(0, 4))

        self.preset_menu = ctk.CTkOptionMenu(
            self.sidebar_scroll,
            values=list(ATTACK_PRESETS.keys()),
            command=self._on_preset_selected,
            height=34,
            dynamic_resizing=False,
            font=ctk.CTkFont(size=11),
        )
        self.preset_menu.pack(fill="x", pady=(0, 6))

        self.preset_desc_lbl = ctk.CTkLabel(
            self.sidebar_scroll,
            text="",
            font=ctk.CTkFont(family="Segoe UI", size=10),
            text_color="#a0a8b9",
            wraplength=290,
            justify="left",
            anchor="w",
        )
        self.preset_desc_lbl.pack(fill="x", pady=(0, 14))

        # 5. Custom Parameters Frame (Collapsible/Conditional)
        self.custom_frame = ctk.CTkFrame(
            self.sidebar_scroll,
            fg_color="#141720",
            corner_radius=8,
            border_width=1,
            border_color=COLOR_CARD_BORDER,
        )
        self.custom_frame.pack(fill="x", pady=(0, 14), padx=2)

        custom_inner_padding = 10
        self.proto_lbl = ctk.CTkLabel(
            self.custom_frame,
            text="Protocol:",
            font=ctk.CTkFont(size=11, weight="bold"),
            anchor="w",
        )
        self.proto_lbl.pack(fill="x", padx=custom_inner_padding, pady=(8, 2))

        self.proto_segment = ctk.CTkSegmentedButton(
            self.custom_frame,
            values=["TCP", "ICMP", "UDP"],
            command=self._on_custom_param_changed,
            height=28,
        )
        self.proto_segment.set("TCP")
        self.proto_segment.pack(fill="x", padx=custom_inner_padding, pady=(0, 8))

        self.port_container = ctk.CTkFrame(self.custom_frame, fg_color="transparent")
        self.port_container.pack(fill="x", padx=custom_inner_padding, pady=(0, 8))

        self.port_lbl = ctk.CTkLabel(
            self.port_container,
            text="Port:",
            font=ctk.CTkFont(size=11, weight="bold"),
            anchor="w",
        )
        self.port_lbl.pack(side="left", padx=(0, 8))

        self.port_entry = ctk.CTkEntry(
            self.port_container,
            width=80,
            height=28,
            font=ctk.CTkFont(family="Consolas", size=11),
        )
        self.port_entry.insert(0, "80")
        self.port_entry.pack(side="left")

        # 6. Sliders (Packet Count & Inter-Packet Delay)
        # Packet Count Slider
        self.count_title_lbl = ctk.CTkLabel(
            self.sidebar_scroll,
            text="Packet Count: 8",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color="#e0e0e0",
            anchor="w",
        )
        self.count_title_lbl.pack(fill="x", pady=(4, 2))

        self.count_slider = ctk.CTkSlider(
            self.sidebar_scroll,
            from_=1,
            to=50,
            number_of_steps=49,
            command=self._on_count_slider_moved,
            height=16,
        )
        self.count_slider.set(8)
        self.count_slider.pack(fill="x", pady=(0, 12))

        # Inter-Packet Delay Slider
        self.delay_title_lbl = ctk.CTkLabel(
            self.sidebar_scroll,
            text="Inter-Packet Delay: 0.05s",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color="#e0e0e0",
            anchor="w",
        )
        self.delay_title_lbl.pack(fill="x", pady=(0, 2))

        self.delay_slider = ctk.CTkSlider(
            self.sidebar_scroll,
            from_=0.01,
            to=1.00,
            number_of_steps=99,
            command=self._on_delay_slider_moved,
            height=16,
        )
        self.delay_slider.set(0.05)
        self.delay_slider.pack(fill="x", pady=(0, 20))

        # 7. Action Control Buttons
        self.btn_launch = ctk.CTkButton(
            self.sidebar_scroll,
            text="🚀 Launch Attack Simulation",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color=COLOR_DANGER,
            hover_color=COLOR_DANGER_HOVER,
            height=42,
            corner_radius=8,
            command=self.launch_attack,
        )
        self.btn_launch.pack(fill="x", pady=(0, 8))

        self.btn_abort = ctk.CTkButton(
            self.sidebar_scroll,
            text="⏹ Abort Attack",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            fg_color="#3c4357",
            hover_color="#4d556e",
            height=34,
            corner_radius=8,
            state="disabled",
            command=self.abort_attack,
        )
        self.btn_abort.pack(fill="x", pady=(0, 10))

    # ------------------------------------------------------------------
    # Right Main Panel: Telemetry, Progress & Console
    # ------------------------------------------------------------------
    def _build_telemetry_panel(self) -> None:
        self.telemetry_frame = ctk.CTkFrame(
            self,
            fg_color=COLOR_BG_DARK,
            corner_radius=0,
        )
        self.telemetry_frame.grid(row=0, column=1, sticky="nsew", padx=0, pady=0)
        self.telemetry_frame.grid_columnconfigure(0, weight=1)
        self.telemetry_frame.grid_rowconfigure(2, weight=1)  # Textbox expands

        # Top Bar: Header & Controls
        top_bar = ctk.CTkFrame(self.telemetry_frame, fg_color="transparent")
        top_bar.grid(row=0, column=0, sticky="ew", padx=20, pady=(18, 10))
        top_bar.grid_columnconfigure(0, weight=1)

        panel_title = ctk.CTkLabel(
            top_bar,
            text="📡 Transmission Telemetry & Packet Log",
            font=ctk.CTkFont(family="Segoe UI", size=16, weight="bold"),
            text_color="#ffffff",
            anchor="w",
        )
        panel_title.grid(row=0, column=0, sticky="w")

        self.btn_clear_log = ctk.CTkButton(
            top_bar,
            text="Clear Console",
            width=100,
            height=28,
            fg_color="#1f2430",
            hover_color="#2c3344",
            text_color=COLOR_MUTED,
            font=ctk.CTkFont(size=11),
            command=self.clear_logs,
        )
        self.btn_clear_log.grid(row=0, column=1, sticky="e")

        # Progress Bar Card
        progress_card = ctk.CTkFrame(
            self.telemetry_frame,
            fg_color=COLOR_CARD_DARK,
            corner_radius=8,
            border_width=1,
            border_color=COLOR_CARD_BORDER,
        )
        progress_card.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 12))
        progress_card.grid_columnconfigure(0, weight=1)

        prog_header = ctk.CTkFrame(progress_card, fg_color="transparent")
        prog_header.pack(fill="x", padx=14, pady=(10, 4))
        prog_header.grid_columnconfigure(0, weight=1)

        self.prog_status_lbl = ctk.CTkLabel(
            prog_header,
            text="Transmission Status: Idle",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color=COLOR_MUTED,
            anchor="w",
        )
        self.prog_status_lbl.grid(row=0, column=0, sticky="w")

        self.prog_pct_lbl = ctk.CTkLabel(
            prog_header,
            text="0% (0/0 pkts)",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color=COLOR_PRIMARY,
            anchor="e",
        )
        self.prog_pct_lbl.grid(row=0, column=1, sticky="e")

        self.progress_bar = ctk.CTkProgressBar(
            progress_card,
            orientation="horizontal",
            height=12,
            corner_radius=6,
            progress_color=COLOR_DANGER,
        )
        self.progress_bar.set(0.0)
        self.progress_bar.pack(fill="x", padx=14, pady=(0, 12))

        # Real-time Packet Console
        self.log_textbox = ctk.CTkTextbox(
            self.telemetry_frame,
            font=ctk.CTkFont(family="Consolas", size=11),
            fg_color=COLOR_CONSOLE_BG,
            border_width=1,
            border_color=COLOR_CARD_BORDER,
            corner_radius=8,
            text_color="#d6deeb",
            wrap="none",
        )
        self.log_textbox.grid(row=2, column=0, sticky="nsew", padx=20, pady=(0, 12))
        self._append_console(
            "=== Project S.A.Y. Telemetry Console Initialized ===\n"
            "Ready to generate test traffic for IDS rule evaluation.\n"
            "Configure attack parameters on the left and click 'Launch'.\n"
        )

        # Bottom Metrics Summary Card
        summary_card = ctk.CTkFrame(
            self.telemetry_frame,
            height=50,
            fg_color=COLOR_CARD_DARK,
            corner_radius=8,
            border_width=1,
            border_color=COLOR_CARD_BORDER,
        )
        summary_card.grid(row=3, column=0, sticky="ew", padx=20, pady=(0, 16))

        # Metrics Columns
        self.metric_pkts = ctk.CTkLabel(
            summary_card,
            text="Packets Injected: 0 / 0",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color="#ffffff",
        )
        self.metric_pkts.pack(side="left", padx=20, pady=12)

        self.metric_time = ctk.CTkLabel(
            summary_card,
            text="Elapsed Time: 0.00s",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color="#ffffff",
        )
        self.metric_time.pack(side="left", padx=20, pady=12)

        self.state_badge = ctk.CTkLabel(
            summary_card,
            text="State: IDLE",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color="#ffffff",
            fg_color="#3c4357",
            corner_radius=6,
            width=130,
            height=26,
        )
        self.state_badge.pack(side="right", padx=16, pady=12)

    # ------------------------------------------------------------------
    # Preset & Input Handlers
    # ------------------------------------------------------------------
    def _refresh_detected_ip(self) -> None:
        new_ip = get_local_ipv4()
        self.detected_ip = new_ip
        self.target_entry.delete(0, "end")
        self.target_entry.insert(0, new_ip)
        self.ip_status_lbl.configure(
            text=f"Refreshed host interface: {new_ip}",
            text_color=COLOR_PRIMARY,
        )

    def _on_preset_selected(self, choice: str) -> None:
        self._apply_preset(choice)

    def _apply_preset(self, preset_name: str) -> None:
        cfg = ATTACK_PRESETS.get(preset_name)
        if not cfg:
            return

        self._is_updating_preset = True
        try:
            self.preset_menu.set(preset_name)
            self.preset_desc_lbl.configure(text=cfg["description"])

            # Update controls
            self.count_slider.set(cfg["count"])
            self.count_title_lbl.configure(text=f"Packet Count: {int(cfg['count'])}")

            self.delay_slider.set(cfg["delay"])
            self.delay_title_lbl.configure(
                text=f"Inter-Packet Delay: {cfg['delay']:.2f}s"
            )

            # Sliders are ALWAYS active ("normal") and never disabled
            self.count_slider.configure(state="normal")
            self.delay_slider.configure(state="normal")

            is_custom = cfg.get("customizable", False)
            if is_custom:
                self.custom_frame.pack(
                    fill="x", pady=(0, 14), padx=2, after=self.preset_desc_lbl
                )
            else:
                self.custom_frame.pack_forget()

            if "port" in cfg:
                self.port_entry.delete(0, "end")
                self.port_entry.insert(0, str(cfg["port"]))
            if "protocol" in cfg:
                self.proto_segment.set(cfg["protocol"])
        finally:
            self._is_updating_preset = False

    def _on_custom_param_changed(self, value: str) -> None:
        if value == "ICMP":
            self.port_container.pack_forget()
        else:
            self.port_container.pack(fill="x", padx=10, pady=(0, 8))

    def _on_count_slider_moved(self, value: float) -> None:
        self.count_title_lbl.configure(text=f"Packet Count: {int(value)}")
        if not self._is_updating_preset:
            self._switch_to_custom_on_slider_interaction()

    def _on_delay_slider_moved(self, value: float) -> None:
        self.delay_title_lbl.configure(text=f"Inter-Packet Delay: {value:.2f}s")
        if not self._is_updating_preset:
            self._switch_to_custom_on_slider_interaction()

    def _switch_to_custom_on_slider_interaction(self) -> None:
        current_preset = self.preset_menu.get()
        if current_preset != "Custom Attack Configuration":
            self.preset_menu.set("Custom Attack Configuration")
            self.preset_desc_lbl.configure(
                text="Switched to Custom Attack Configuration (modified from preset)."
            )
            self.custom_frame.pack(
                fill="x", pady=(0, 14), padx=2, after=self.preset_desc_lbl
            )

    # ------------------------------------------------------------------
    # Simulation Execution & Control
    # ------------------------------------------------------------------
    def launch_attack(self) -> None:
        if self.is_running:
            return

        target_ip = self.target_entry.get().strip()
        is_valid_tgt, err_msg_tgt = validate_ipv4(target_ip)
        if not is_valid_tgt:
            self.ip_status_lbl.configure(
                text=f"Error: {err_msg_tgt}", text_color=COLOR_DANGER
            )
            self._append_console(f"[INPUT ERROR] Target IP: {err_msg_tgt}\n")
            return

        attacker_ip = self.attacker_entry.get().strip()
        is_valid_att, err_msg_att = validate_ipv4(attacker_ip)
        if not is_valid_att:
            self.attacker_status_lbl.configure(
                text=f"Error: {err_msg_att}", text_color=COLOR_DANGER
            )
            self._append_console(f"[INPUT ERROR] Attacker IP: {err_msg_att}\n")
            return

        preset_name = self.preset_menu.get()
        preset_cfg = ATTACK_PRESETS.get(preset_name, {})

        if preset_cfg.get("customizable", False):
            protocol = self.proto_segment.get()
            count = int(self.count_slider.get())
            delay = round(self.delay_slider.get(), 2)
            try:
                port = int(self.port_entry.get().strip())
                if not (1 <= port <= 65535):
                    raise ValueError("Port out of range 1-65535")
            except ValueError:
                self._append_console("[INPUT ERROR] Port must be an integer between 1 and 65535.\n")
                return
            is_sweep = False
        else:
            protocol = preset_cfg.get("protocol", "TCP")
            count = int(preset_cfg.get("count", 8))
            delay = float(preset_cfg.get("delay", 0.05))
            port = int(preset_cfg.get("port", 80))
            is_sweep = bool(preset_cfg.get("is_sweep", False))

        # Check raw socket admin privilege advisory
        if not self.is_admin:
            self._append_console(
                "[WARNING] Administrator privileges not detected. "
                "Raw packet generation may fail if WinPcap/Npcap driver restricts unprivileged sockets.\n"
            )

        # Configure Attack Engine
        attack_cfg = AttackConfig(
            attacker_ip=attacker_ip,
            target_ip=target_ip,
            protocol=protocol,
            count=count,
            delay=delay,
            port=port,
            is_sweep=is_sweep,
            preset_name=preset_name,
        )

        # UI State Transition -> FIRING
        self.is_running = True
        self.abort_event.clear()

        self.btn_launch.configure(state="disabled", text="⚡ Simulating Attack...")
        self.btn_abort.configure(state="normal", fg_color=COLOR_DANGER, hover_color=COLOR_DANGER_HOVER)
        self.preset_menu.configure(state="disabled")
        self.target_entry.configure(state="disabled")
        self.attacker_entry.configure(state="disabled")

        self.progress_bar.set(0.0)
        self.prog_status_lbl.configure(
            text=f"Active Simulation: {preset_name}",
            text_color="#ffffff",
        )
        self.prog_pct_lbl.configure(text=f"0% (0/{count} pkts)", text_color=COLOR_DANGER)

        self.state_badge.configure(text="State: FIRING", fg_color=COLOR_DANGER)
        self.metric_pkts.configure(text=f"Packets Injected: 0 / {count}")
        self.metric_time.configure(text="Elapsed Time: 0.00s")

        # Spawn Worker Daemon Thread
        self.worker_thread = AttackWorker(
            config=attack_cfg,
            msg_queue=self.msg_queue,
            abort_event=self.abort_event,
        )
        self.worker_thread.start()

    def abort_attack(self) -> None:
        if not self.is_running:
            return
        self.abort_event.set()
        self.btn_abort.configure(state="disabled", text="Aborting...")
        self._append_console("\n[SYSTEM] Abort signal sent to worker thread...\n")

    def _reset_controls(self) -> None:
        self.is_running = False
        self.btn_launch.configure(
            state="normal",
            text="🚀 Launch Attack Simulation",
            fg_color=COLOR_DANGER,
            hover_color=COLOR_DANGER_HOVER,
        )
        self.btn_abort.configure(
            state="disabled",
            text="⏹ Abort Attack",
            fg_color="#3c4357",
            hover_color="#4d556e",
        )
        self.preset_menu.configure(state="normal")
        self.target_entry.configure(state="normal")
        self.attacker_entry.configure(state="normal")

    # ------------------------------------------------------------------
    # Safe Event Loop Queue Processing
    # ------------------------------------------------------------------
    def _process_queue(self) -> None:
        """Poll the thread-safe queue and apply updates to Tkinter UI elements."""
        try:
            while True:
                msg = self.msg_queue.get_nowait()
                msg_type = msg[0]

                if msg_type == "LOG":
                    _, text, level = msg
                    self._append_console(f"{text}\n")

                elif msg_type == "PROGRESS":
                    _, count, total, elapsed, _ = msg
                    pct = (count / total) if total > 0 else 1.0
                    self.progress_bar.set(pct)
                    self.prog_pct_lbl.configure(
                        text=f"{int(pct * 100)}% ({count}/{total} pkts)"
                    )
                    self.metric_pkts.configure(text=f"Packets Injected: {count} / {total}")
                    self.metric_time.configure(text=f"Elapsed Time: {elapsed:.2f}s")

                elif msg_type == "COMPLETED":
                    _, count, total, elapsed, summary = msg
                    self.progress_bar.set(1.0)
                    self.prog_pct_lbl.configure(text=f"100% ({count}/{total} pkts)", text_color=COLOR_SUCCESS)
                    self.prog_status_lbl.configure(text="Simulation Finished Successfully", text_color=COLOR_SUCCESS)
                    self.state_badge.configure(text="State: COMPLETED", fg_color=COLOR_SUCCESS)
                    self.metric_pkts.configure(text=f"Packets Injected: {count} / {total}")
                    self.metric_time.configure(text=f"Elapsed Time: {elapsed:.2f}s")
                    self._reset_controls()

                elif msg_type == "ABORTED":
                    _, count, total, elapsed, summary = msg
                    pct = (count / total) if total > 0 else 0.0
                    self.progress_bar.set(pct)
                    self.prog_pct_lbl.configure(text=f"Stopped ({count}/{total} pkts)", text_color=COLOR_WARNING)
                    self.prog_status_lbl.configure(text="Simulation Aborted by User", text_color=COLOR_WARNING)
                    self.state_badge.configure(text="State: ABORTED", fg_color=COLOR_WARNING)
                    self.metric_pkts.configure(text=f"Packets Injected: {count} / {total}")
                    self.metric_time.configure(text=f"Elapsed Time: {elapsed:.2f}s")
                    self._reset_controls()

                elif msg_type == "ERROR":
                    _, count, total, elapsed, err_str = msg
                    self.prog_status_lbl.configure(text="Simulation Failed", text_color=COLOR_DANGER)
                    self.state_badge.configure(text="State: ERROR", fg_color=COLOR_DANGER)
                    self.metric_pkts.configure(text=f"Packets Injected: {count} / {total}")
                    self.metric_time.configure(text=f"Elapsed Time: {elapsed:.2f}s")
                    self._reset_controls()

                self.msg_queue.task_done()
        except queue.Empty:
            pass
        finally:
            self.after(40, self._process_queue)

    def _append_console(self, text: str) -> None:
        self.log_textbox.configure(state="normal")
        self.log_textbox.insert("end", text)
        self.log_textbox.see("end")
        self.log_textbox.configure(state="disabled")

    def clear_logs(self) -> None:
        self.log_textbox.configure(state="normal")
        self.log_textbox.delete("1.0", "end")
        self.log_textbox.configure(state="disabled")
        self._append_console("=== Console Log Cleared ===\n")


# ----------------------------------------------------------------------
# Application Entry Point
# ----------------------------------------------------------------------
def main() -> None:
    app = SayApp()
    app.mainloop()


if __name__ == "__main__":
    main()
