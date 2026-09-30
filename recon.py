import subprocess
import os
import socket
import json
from datetime import datetime


def choose_scan_mode():
    print("\nSELECT SCAN MODE")
    print("=" * 30)
    print("1. Basic scan")
    print("2. Service/version scan")
    print("3. OS detection")

    choice = input("\nEnter your choice (1-3): ")

    if choice == "1":
        return ["nmap"], "Basic scan"

    elif choice == "2":
        return ["nmap", "-sV"], "Service/version scan"

    elif choice == "3":
        return ["nmap", "-O", "-sV"], "OS detection"

    else:
        print("[!] Invalid choice.")
        return None, None


def choose_port_scan():
    print("\nPORT SCAN OPTIONS")
    print("=" * 30)
    print("1. Default ports")
    print("2. Common ports")
    print("3. Custom port")
    print("4. Port range")

    choice = input("\nEnter your choice (1-4): ")

    if choice == "1":
        return [], "Default ports"

    elif choice == "2":
        return ["--top-ports", "20"], "Top 20 ports"

    elif choice == "3":

        port = input("\nEnter port number (example: 443): ")

        if not port.isdigit():
            print("[!] Port must be a number.")
            return None, None

        port_number = int(port)

        if port_number < 1 or port_number > 65535:
            print("[!] Port must be between 1 and 65535.")
            return None, None

        return ["-p", port], f"Port {port}"

    elif choice == "4":

        port_range = input(
            "\nEnter port range (example: 1-100): "
        )

        if "-" not in port_range:
            print("[!] Range must use the format: start-end")
            return None, None

        parts = port_range.split("-")

        if len(parts) != 2:
            print("[!] Invalid port range.")
            return None, None

        start = parts[0]
        end = parts[1]

        if not start.isdigit() or not end.isdigit():
            print("[!] Ports must be numbers.")
            return None, None

        start_port = int(start)
        end_port = int(end)

        if start_port < 1 or end_port > 65535:
            print("[!] Ports must be between 1 and 65535.")
            return None, None

        if start_port > end_port:
            print("[!] Starting port cannot be greater than ending port.")
            return None, None

        return ["-p", port_range], f"Ports {port_range}"

    else:
        print("[!] Invalid choice.")
        return None, None


def scan_target(
    target,
    scan_command,
    scan_mode,
    port_command,
    port_scan_mode
):

    print("\n[+] Starting reconnaissance...")

    if scan_mode == "Basic scan":
        print("[+] Basic port scan enabled")

    elif scan_mode == "Service/version scan":
        print("[+] Service and version detection enabled")

    elif scan_mode == "OS detection":
        print("[+] Operating system detection enabled")
        print("[+] Service and version detection enabled")

    print(f"[+] Port selection: {port_scan_mode}")
    print("[+] Running Nmap scan...\n")

    # Resolve the target to an IP address
    try:
        ip_address = socket.gethostbyname(target)
        print(f"[+] IP address: {ip_address}\n")

    except socket.gaierror:
        print("[!] Could not resolve target.")
        return

    # Build the Nmap command
    command = scan_command + port_command + [target]

    # Run Nmap
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )

    except FileNotFoundError:
        print("[!] Nmap was not found.")
        print("[!] Make sure Nmap is installed and available in PATH.")
        return

    # Check if Nmap returned an error
    if result.returncode != 0:
        print("[!] Scan failed.")
        print(result.stderr)
        return

    open_ports = []
    operating_system = "Unknown"

    # Read Nmap output
    for line in result.stdout.splitlines():

        # Remove unnecessary spaces
        line = line.strip()

        # Find open TCP ports
        if "/tcp" in line and "open" in line:

            parts = line.split()

            port = parts[0]
            state = parts[1]
            service = parts[2]

            if len(parts) > 3:
                version = " ".join(parts[3:])
            else:
                version = "Unknown"

            open_ports.append({
                "port": port,
                "state": state,
                "service": service,
                "version": version
            })

        # Find OS details from Nmap
        if line.startswith("OS details:"):

            operating_system = line.split(
                "OS details:", 1
            )[1].strip()

        # Find the OS from the Running line
        elif line.startswith("Running:"):

            running_os = line.split(
                "Running:", 1
            )[1].strip()

            if operating_system == "Unknown":
                operating_system = running_os

        # Find OS information from Service Info
        if line.startswith("Service Info:"):

            if "OS:" in line:

                os_part = line.split(
                    "OS:", 1
                )[1]

                # Remove CPE and other information
                if ";" in os_part:
                    os_part = os_part.split(";", 1)[0]

                if "," in os_part:
                    os_part = os_part.split(",", 1)[0]

                operating_system = os_part.strip()

    display_results(
        target,
        ip_address,
        open_ports,
        operating_system,
        scan_mode,
        port_scan_mode
    )

    save_report(
        target,
        ip_address,
        operating_system,
        open_ports,
        scan_mode,
        port_scan_mode
    )

    save_scan_history(
        target,
        ip_address,
        operating_system,
        open_ports,
        scan_mode,
        port_scan_mode
    )


def display_results(
    target,
    ip_address,
    open_ports,
    operating_system,
    scan_mode,
    port_scan_mode
):

    print("\n")
    print("=" * 60)
    print("                 SCAN RESULTS")
    print("=" * 60)

    print(f"Target:             {target}")
    print(f"IP Address:         {ip_address}")
    print(f"Operating System:   {operating_system}")
    print(f"Scan Mode:          {scan_mode}")
    print(f"Port Selection:     {port_scan_mode}")
    print(f"Open TCP Ports:     {len(open_ports)}")

    print("\nOPEN PORTS")
    print("=" * 60)

    if len(open_ports) == 0:
        print("No open TCP ports found.")
        print("=" * 60)
        return

    for item in open_ports:

        print(
            f"{item['port']:<10}"
            f"{item['state']:<8}"
            f"{item['service']:<18}"
            f"{item['version']}"
        )

    print("=" * 60)


def save_report(
    target,
    ip_address,
    operating_system,
    open_ports,
    scan_mode,
    port_scan_mode
):

    # Create reports folder if it does not exist
    os.makedirs("reports", exist_ok=True)

    current_time = datetime.now()

    timestamp = current_time.strftime(
        "%Y-%m-%d_%H-%M-%S"
    )

    # Create TXT report
    txt_filename = f"recon_{target}_{timestamp}.txt"

    txt_filepath = os.path.join(
        "reports",
        txt_filename
    )

    with open(txt_filepath, "w") as report:

        report.write(
            "NETWORK RECONNAISSANCE REPORT\n"
        )

        report.write(
            "=" * 40 + "\n\n"
        )

        report.write(
            f"Target: {target}\n"
        )

        report.write(
            f"IP Address: {ip_address}\n"
        )

        report.write(
            f"Scan Mode: {scan_mode}\n"
        )

        report.write(
            f"Port Selection: {port_scan_mode}\n"
        )

        report.write(
            f"Operating System: {operating_system}\n"
        )

        report.write(
            f"Date: {current_time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        )

        report.write(
            "SCAN SUMMARY\n"
        )

        report.write(
            "-" * 40 + "\n"
        )

        report.write(
            f"Open TCP ports: {len(open_ports)}\n\n"
        )

        report.write(
            "OPEN PORTS\n"
        )

        report.write(
            "-" * 40 + "\n\n"
        )

        if len(open_ports) == 0:

            report.write(
                "No open TCP ports found.\n"
            )

        else:

            for item in open_ports:

                report.write(
                    f"Port:    {item['port']}\n"
                )

                report.write(
                    f"State:   {item['state']}\n"
                )

                report.write(
                    f"Service: {item['service']}\n"
                )

                report.write(
                    f"Version: {item['version']}\n"
                )

                report.write(
                    "-" * 40 + "\n"
                )

    # Create JSON report
    json_filename = f"recon_{target}_{timestamp}.json"

    json_filepath = os.path.join(
        "reports",
        json_filename
    )

    report_data = {
        "target": target,
        "ip_address": ip_address,
        "scan_mode": scan_mode,
        "port_selection": port_scan_mode,
        "operating_system": operating_system,
        "date": current_time.strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "open_port_count": len(open_ports),
        "open_ports": open_ports
    }

    with open(json_filepath, "w") as report:

        json.dump(
            report_data,
            report,
            indent=4
        )

    print(f"\n[✓] TXT report saved to: {txt_filepath}")
    print(f"[✓] JSON report saved to: {json_filepath}")


def save_scan_history(
    target,
    ip_address,
    operating_system,
    open_ports,
    scan_mode,
    port_scan_mode
):

    history_file = "scan_history.json"

    current_time = datetime.now()

    history_entry = {
        "target": target,
        "ip_address": ip_address,
        "scan_mode": scan_mode,
        "port_selection": port_scan_mode,
        "operating_system": operating_system,
        "date": current_time.strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "open_port_count": len(open_ports)
    }

    # Load existing history
    if os.path.exists(history_file):

        try:

            with open(history_file, "r") as file:
                history = json.load(file)

        except json.JSONDecodeError:

            history = []

    else:

        history = []

    # Add the newest scan
    history.append(history_entry)

    # Save updated history
    with open(history_file, "w") as file:

        json.dump(
            history,
            file,
            indent=4
        )

    print(f"[✓] Scan added to history: {history_file}")


def view_scan_history():

    history_file = "scan_history.json"

    print("\n")
    print("=" * 60)
    print("                    SCAN HISTORY")
    print("=" * 60)

    # Check if history exists
    if not os.path.exists(history_file):

        print("No scan history found.")
        print("=" * 60)
        return

    try:

        with open(history_file, "r") as file:
            history = json.load(file)

    except json.JSONDecodeError:

        print("[!] Scan history file is invalid.")
        print("=" * 60)
        return

    if len(history) == 0:

        print("No scan history found.")
        print("=" * 60)
        return

    # Display scans
    for number, scan in enumerate(history, start=1):

        print(f"\nScan #{number}")
        print("-" * 60)

        print(f"Target:             {scan['target']}")
        print(f"IP Address:         {scan['ip_address']}")
        print(f"Scan Mode:          {scan['scan_mode']}")
        print(f"Port Selection:     {scan['port_selection']}")
        print(f"Operating System:   {scan['operating_system']}")
        print(f"Date:               {scan['date']}")
        print(f"Open TCP Ports:     {scan['open_port_count']}")

    print("\n" + "=" * 60)


def main():

    print("================================")
    print("      NETWORK RECON TOOL")
    print("================================")

    print("\nMAIN MENU")
    print("=" * 30)
    print("1. Start new scan")
    print("2. View scan history")

    choice = input("\nEnter your choice (1-2): ")

    if choice == "2":

        view_scan_history()
        return

    if choice != "1":

        print("[!] Invalid choice.")
        return

    target = input(
        "\nEnter target IP or hostname: "
    )

    if target == "":
        print("[!] Target cannot be empty.")
        return

    print(f"\n[+] Target: {target}")

    scan_command, scan_mode = choose_scan_mode()

    if scan_command is None:
        return

    port_command, port_scan_mode = choose_port_scan()

    if port_command is None:
        return

    scan_target(
        target,
        scan_command,
        scan_mode,
        port_command,
        port_scan_mode
    )


if __name__ == "__main__":
    main()