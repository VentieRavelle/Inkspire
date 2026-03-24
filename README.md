# 🕵️‍♂️ Inkspire — OSINT & Port Scanner

![inkspire (1)](https://github.com/user-attachments/assets/864f83a9-04c4-40c1-b659-b7bce2d91b61)

**Inkspire** is a high-performance network reconnaissance tool written in Go. It combines multi-threaded port scanning with deep OSINT gathering, providing a comprehensive snapshot of any target's infrastructure.

🌐 **Project Website:** [inkspire.ventie.dev](https://inkspire.ventie.dev)

---

### 🚀 Key Features

* **Lightning Fast Scanning**: Utilizes Go's concurrency (goroutines) for high-speed port analysis.
* **Dual Protocol Support**: Accurately detects **TCP** (Open/Closed) and **UDP** (Open/Filtered) states.
* **Deep OSINT Gathering**: 
    * **Geolocation**: Real-time lookup of Country, City, and ISP.
    * **WHOIS Data**: Retrieves Registrar and Organization details.
    * **Reverse DNS**: Automatically resolves IP addresses to hostnames.
* **Vulnerability Detection**: Cross-references discovered service banners with a built-in **CVE database**.
* **Smart Reporting**: Automatically saves detailed scan results to your `Downloads` folder in JSON format.
* **Cross-Platform**: Native binaries for Windows, Linux, and macOS.

---

### ⚙️ Command Line Arguments

| Flag | Description | Default |
| :--- | :--- | :--- |
| `-ip` | **(Required)** Target IP address or CIDR range | `""` |
| `-ports` | Port range or comma-separated list (e.g., `80,443,1-1024`) | `1-1024` |
| `-w` | Number of concurrent workers (goroutines) | `100` |
| `-force` | Scan even if the host does not respond to ICMP (Ping) | `false` |

---

### 📦 Installation & Usage

#### 1. Quick Start (Binary)
Download the latest binary for your OS from the [Releases](https://github.com/VentieRavelle/Inkspire/releases) page. Ensure the `data/known_ports.json` file is present in the project directory.

#### 2. Build from Source
```bash
git clone [https://github.com/VentieRavelle/Inkspire.git](https://github.com/VentieRavelle/Inkspire.git)
cd Inkspire/cmd
go build -o inkspire main.go
