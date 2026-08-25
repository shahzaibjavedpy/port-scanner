from scanner import scan_single_target, scan_subnet, save_report

def main():
    print("=" * 60)
    print("       PYTHON PORT SCANNER - ADVANCED TOOLKIT       ")
    print("=" * 60)
    
    print("\nSelect Scan Type:")
    print("1. Single IP / Hostname Scan")
    print("2. Subnet / Network Range Scan (e.g., 192.168.1.0/24)")
    
    choice = input("\n[?] Enter your choice (1 or 2): ").strip()
    
    if choice == '1':
        target = input("[?] Enter target IP address (e.g., 127.0.0.1): ").strip()
        if not target:
            print("[-] Error: Target cannot be empty!")
            return

        # Clean up URL prefixes if accidentally entered
        target = target.replace("http://", "").replace("https://", "").strip()

        try:
            start_port = int(input("[?] Enter start port (e.g., 1): "))
            end_port = int(input("[?] Enter end port (e.g., 1024): "))
        except ValueError:
            print("[-] Error: Ports must be valid integers!")
            return

        if start_port > end_port or start_port < 1 or end_port > 65535:
            print("[-] Error: Invalid port range.")
            return

        print(f"\n[*] Starting scan on {target}...")
        open_ports, os_info = scan_single_target(target, start_port, end_port)
        
        print("\n" + "=" * 60)
        print(f" SCAN SUMMARY FOR: {target}")
        print("=" * 60)
        print(f"[+] Estimated OS: {os_info}")
        if open_ports:
            print(f"[+] Total Open Ports Found: {len(open_ports)}")
            for port, service in open_ports:
                print(f"    - Port {port}: {service}")
                
            if input("\n[?] Save report? (y/n): ").strip().lower() == 'y':
                save_report(target, open_ports, os_info=os_info, is_subnet=False)
        else:
            print("[-] No open ports found.")
        print("=" * 60)

    elif choice == '2':
        subnet = input("[?] Enter network subnet (e.g., 192.168.1.0/24): ").strip()
        if not subnet:
            print("[-] Error: Subnet cannot be empty!")
            return

        try:
            start_port = int(input("[?] Enter start port (e.g., 1): "))
            end_port = int(input("[?] Enter end port (e.g., 1024): "))
        except ValueError:
            print("[-] Error: Ports must be valid integers!")
            return

        subnet_results = scan_subnet(subnet, start_port, end_port)
        
        print("\n" + "=" * 60)
        print(f" SUBNET SCAN SUMMARY FOR: {subnet}")
        print("=" * 60)
        if subnet_results:
            print(f"[+] Active Hosts with Open Ports Found: {len(subnet_results)}")
            for ip, data in subnet_results.items():
                print(f"    - IP: {ip} | OS: {data['os']} ({len(data['ports'])} open ports)")
                
            if input("\n[?] Save subnet report? (y/n): ").strip().lower() == 'y':
                save_report(subnet, subnet_results, is_subnet=True)
        else:
            print("[-] No active hosts/open ports found in the subnet.")
        print("=" * 60)
    else:
        print("[-] Invalid choice!")

if __name__ == "__main__":
    main()