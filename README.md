# 🚀 Project S.A.Y. (Safely Attack Yourself) — Layer 2 IDS Traffic Testbench

![Python](https://img.shields.io/badge/Python-3.14-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-Layer_2_Injection-e74c3c?style=for-the-badge)
![CustomTkinter](https://img.shields.io/badge/GUI-CustomTkinter-1f6aa5?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Windows_11-0078D6?style=for-the-badge&logo=windows&logoColor=white)

**Project S.A.Y. (Safely Attack Yourself)** is a standalone, native Windows traffic generator and synthetic attack testbench engineered to audit Intrusion Detection Systems (IDS) such as [**Glass-Box IDS**](https://github.com/WisterWist/GlassBoxIDS) without spinning up external attacker virtual machines.

---

## 📸 Interface Preview

<img width="977" height="640" alt="image" src="https://github.com/user-attachments/assets/6019d127-18df-4fdf-88a7-dc2819dcba23" />



---

## 🧠 Core Engineering Solution: Bypassing Windows Kernel Loopback

When auditing an IDS on a single Windows host, standard Layer 3 socket injections (`send()`) targeting the local IPv4 address are short-circuited by the Windows TCP/IP kernel stack into internal loopback memory—never reaching the physical Network Interface Card (NIC) or Npcap capture queues.

**Project S.A.Y.** solves this by:
1. **Layer 2 Ethernet Frame Construction:** Encapsulating synthetic transport payloads inside full Ethernet frames (`Ether() / IP(src=attacker_ip, dst=target_ip) / transport_layer`).
2. **Direct Adapter Injection (`sendp`):** Pushing frames directly onto the active physical interface via `sendp(frame, iface=conf.iface, verbose=False)` so local Npcap sniffers intercept the traffic accurately.
3. **Spoofed External Threat Actor (`10.0.0.99`):** Simulating realistic external adversary telemetry (`10.0.0.99 -> Host IP`) to test IDS alert logging and IPv4 whitelisting workflows.

---

## ⚡ Features & Attack Presets

* **Automatic Host IPv4 Discovery:** Uses a non-transmitting UDP routing query to auto-detect the primary active network interface on startup.
* **Admin Privilege Verification:** Queries `ctypes.windll.shell32.IsUserAnAdmin()` to verify raw socket execution permissions.
* **5 Built-In Simulation Profiles:**
  1. **`TCP SYN Burst (8 pkts -> Tests Rule 1)`:** Rapid half-open TCP `SYN` probes to port `80` with sequential sequence numbers.
  2. **`ICMP Ping Flood (12 pkts -> Tests Rule 2)`:** High-frequency ICMP Echo Request burst (`Type 8`).
  3. **`UDP Port Sweep (18 pkts -> Tests Rule 3)`:** Sequential UDP datagram sweep across destination ports `5000–5017`.
  4. **`Stealth Baseline (2 pkts, slow -> Benign Test)`:** Low-frequency TCP packets spaced `0.75s` apart to verify false-positive resistance.
  5. **`Custom Attack Configuration`:** Unlocks manual protocol selection (`TCP` / `ICMP` / `UDP`), custom port targeting, packet volume slider (`1–50`), and inter-packet delay slider (`0.01s–1.00s`).
* **Granular 20ms Abort Control:** Polls a thread-safe `threading.Event` across `20ms` sleep slices for instantaneous halt when clicking **⏹ Abort Attack**.

---

## 🗂️ Project Structure

* `say_app.py` — Standalone CustomTkinter GUI & Scapy Layer 2 packet injection engine
* `README.md` — Technical documentation & usage guide

---

## ⚙️ Prerequisites & Usage

* **OS:** Windows 10 / 11
* **Driver:** Install [**Npcap**](https://npcap.com/) *(Check **"Install Npcap in WinPcap API-compatible Mode"** during installation)*.
* **Install Dependencies:** `pip install scapy customtkinter`
* **Launch Testbench (Run PowerShell as Administrator):** `python say_app.py`

---

## ⚠️ Ethical Disclaimer

Project S.A.Y. is strictly an educational traffic generator built for local interface auditing and university cybersecurity coursework. Only inject traffic against local interfaces or lab environments you own and have explicit authorization to test.

---

## 👨‍💻 Author

**Muhammad Arif Bin Azman**  
Bachelor of Computer Science (Cyber Security) (Hons.)  
Universiti Tenaga Nasional (UNITEN)
