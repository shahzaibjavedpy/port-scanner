# 🛡️ Advanced Python Port Scanner & Network Security Toolkit

A high-performance, multi-threaded port scanner and network auditing utility written in pure Python. Designed for developers, network administrators, and cybersecurity students to perform quick network reconnaissance, service banner grabbing, subnet scanning, and basic OS fingerprinting.

---

## 🚀 Key Features

* **⚡ Fast Multithreading:** Utilizes Python's `ThreadPoolExecutor` to scan large port ranges in seconds.
* **🔍 Service & Banner Detection:** Identifies running services (e.g., MSRPC, SMB, HTTP, SSH) on open ports.
* **🌐 Subnet / Network Scanning:** Scan entire IP ranges/subnets (e.g., `192.168.1.0/24`) automatically.
* **💻 Basic OS Fingerprinting:** Estimates the target operating system based on socket connection heuristics.
* **📄 Automated Reporting:** Exports professional scan summaries into both **Text (`.txt`)** and **JSON (`.json`)** formats.

---

## 🛠️ Tech Stack & Modules
* **Language:** Python 3.x
* **Core Modules:** `socket`, `concurrent.futures`, `ipaddress`, `json`, `datetime`

---

## ⚙️ Installation & Usage

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/shahzaibjavedpy/port-scanner.git](https://github.com/shahzaibjavedpy/port-scanner.git)
   cd port-scanner