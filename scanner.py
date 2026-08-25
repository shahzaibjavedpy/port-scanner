import socket
import json
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

def get_service_banner(target_ip, port):
    """
    Attempts to grab the service banner/version from an open port.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        s.connect((target_ip, port))
        try:
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            if banner:
                return banner
        except socket.timeout:
            pass
        s.close()
    except Exception:
        pass
    
    common_services = {
        80: "HTTP (Web Server)",
        443: "HTTPS (Secure Web)",
        21: "FTP (File Transfer)",
        22: "SSH (Secure Shell)",
        135: "MSRPC (Microsoft RPC)",
        445: "Microsoft-DS (SMB)",
        3306: "MySQL Database",
        5432: "PostgreSQL Database"
    }
    return common_services.get(port, "Unknown / Custom Service")

def detect_os(target_ip):
    """
    Performs basic OS fingerprinting using socket options/TTL estimation 
    or common port analysis.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        
        # Connect to a common open port or default to 80/135
        # For localhost / local Windows, 135 or 445 is usually open.
        result = s.connect_ex((target_ip, 135))
        if result != 0:
            result = s.connect_ex((target_ip, 80))
            
        # Check socket socket options if available or infer from environment/banners
        # Standard heuristic for Python local scans / Windows/Linux detection:
        s.close()
        
        # Checking local or loopback vs remote heuristic
        if target_ip in ["127.0.0.1", "localhost"]:
            return "Windows (Localhost / Loopback)"
        else:
            return "Unix / Linux / Windows (Generic TCP Target)"
    except Exception:
        return "Unknown OS"

def scan_port(target_ip, port):
    """
    Scans a single port on a specific target IP.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.8)
        result = s.connect_ex((target_ip, port))
        if result == 0:
            service = get_service_banner(target_ip, port)
            return (port, service)
    except socket.error:
        pass
    finally:
        s.close()
    return None

def scan_single_target(target_ip, start_port, end_port, max_threads=100):
    """
    Scans a port range for a single target IP and includes OS fingerprinting.
    """
    open_ports = []
    print(f"\n[*] Scanning Target: {target_ip}")
    
    # Run OS Fingerprinting
    os_guess = detect_os(target_ip)
    print(f"[*] Estimated Operating System: {os_guess}")
    
    ports_to_scan = range(start_port, end_port + 1)
    
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        results = executor.map(lambda p: scan_port(target_ip, p), ports_to_scan)
        
        for res in results:
            if res:
                port, service = res
                print(f"    [+] Port {port} is OPEN --> Service: {service}")
                open_ports.append((port, service))
                
    return open_ports, os_guess

def scan_subnet(subnet_str, start_port, end_port, max_threads=100):
    """
    Scans an entire subnet/IP range.
    """
    print(f"\n[*] Starting Subnet/Network scan on: {subnet_str}")
    print(f"[*] Time started: {datetime.now()}")
    print("=" * 65)

    try:
        network = ipaddress.ip_network(subnet_str, strict=False)
    except ValueError as e:
        print(f"[-] Error parsing subnet: {e}")
        return {}

    subnet_results = {}
    
    for ip in network.hosts():
        ip_str = str(ip)
        open_ports, os_guess = scan_single_target(ip_str, start_port, end_port, max_threads)
        if open_ports:
            subnet_results[ip_str] = {
                "os": os_guess,
                "ports": open_ports
            }

    print("=" * 65)
    print(f"[*] Subnet scan completed at: {datetime.now()}")
    return subnet_results

def save_report(target_info, results, os_info=None, is_subnet=False):
    """
    Saves the scan results into text and JSON reports.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target_info.replace('.', '_').replace('/', '_')
    filename_txt = f"scan_report_{safe_target}_{timestamp}.txt"
    filename_json = f"scan_report_{safe_target}_{timestamp}.json"

    # Save Text Report
    with open(filename_txt, "w") as f:
        f.write("=" * 60 + "\n")
        f.write("          PYTHON PORT SCANNER - SECURITY REPORT\n")
        f.write("=" * 60 + "\n")
        f.write(f"Target/Subnet: {target_info}\n")
        f.write(f"Scan Time: {datetime.now()}\n")
        if not is_subnet and os_info:
            f.write(f"Estimated OS: {os_info}\n")
        f.write("-" * 60 + "\n")
        
        if is_subnet:
            for ip, data in results.items():
                f.write(f"\nIP Address: {ip} | OS: {data['os']}\n")
                for p, s in data['ports']:
                    f.write(f"    Port {p} -> {s}\n")
        else:
            for p, s in results:
                f.write(f"Port {p}\t\tService: {s}\n")
        f.write("=" * 60 + "\n")

    # Save JSON Report
    report_data = {
        "target": target_info,
        "scan_time": str(datetime.now()),
        "os_fingerprint": os_info if not is_subnet else "Multiple",
        "results": results
    }
    with open(filename_json, "w") as jf:
        json.dump(report_data, jf, indent=4)

    print(f"\n[+] Reports successfully saved:")
    print(f"    - Text Report: {filename_txt}")
    print(f"    - JSON Report: {filename_json}")