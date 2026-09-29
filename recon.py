import subprocess
import os
import socket
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


def scan_target(target, scan_command, scan_mode):
    print("\n[+] Starting reconnaissance...")

    if scan_mode == "Basic scan":
        print("[+] Basic port scan enabled")

    elif scan_mode == "Service/version scan":
        print("[+] Service and version detection enabled")

    elif scan_mode == "OS detection":
        print("[+] Operating system detection enabled")
        print("[+] Service and version detection enabled")

    print("[+] Running Nmap scan...\n")

    # Resolve the target to an IP address
    try:
        ip_address = socket.gethostbyname(target)
        print(f"[+] IP address: {ip_address}\n")

    except socket.gaierror:
        print("[!] Could not resolve target.")
        return

    # Add the target to the Nmap command
    command = scan_command + [target]

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

            # Only use this if OS details was not already found
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
        open_ports,
        operating_system,
        scan_mode
    )

    save_report(
        target,
        ip_address,
        operating_system,
        open_ports,
        scan_mode
    )


def display_results(
    open_ports,
    operating_system,
    scan_mode
):

    print("SCAN RESULTS")
    print("=" * 50)

    print(f"Scan Mode: {scan_mode}")
    print(f"Operating System: {operating_system}")

    print("\nOpen Ports:")
    print("-" * 50)

    if len(open_ports) == 0:
        print("No open TCP ports found.")
        return

    for item in open_ports:

        print(f"Port:    {item['port']}")
        print(f"State:   {item['state']}")
        print(f"Service: {item['service']}")
        print(f"Version: {item['version']}")
        print("-" * 50)


def save_report(
    target,
    ip_address,
    operating_system,
    open_ports,
    scan_mode
):

    # Create reports folder if it does not exist
    os.makedirs("reports", exist_ok=True)

    current_time = datetime.now()

    timestamp = current_time.strftime(
        "%Y-%m-%d_%H-%M-%S"
    )

    filename = f"recon_{target}_{timestamp}.txt"

    filepath = os.path.join(
        "reports",
        filename
    )

    with open(filepath, "w") as report:

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

    print(f"\n[✓] Report saved to: {filepath}")


def main():

    print("================================")
    print("      NETWORK RECON TOOL")
    print("================================")

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

    scan_target(
        target,
        scan_command,
        scan_mode
    )


if __name__ == "__main__":
    main()