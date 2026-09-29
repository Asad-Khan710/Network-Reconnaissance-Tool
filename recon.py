import subprocess
import os
from datetime import datetime


def scan_target(target):
    print("\n[+] Starting reconnaissance...")
    print("[+] Service detection enabled")
    print("[+] Running Nmap scan...\n")

    try:
        result = subprocess.run(
            ["nmap", "-sV", target],
            capture_output=True,
            text=True
        )

    except FileNotFoundError:
        print("[!] Nmap was not found.")
        print("[!] Make sure Nmap is installed and available in PATH.")
        return

    if result.returncode != 0:
        print("[!] Scan failed.")
        print(result.stderr)
        return

    open_ports = []

    for line in result.stdout.splitlines():

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

    display_results(open_ports)
    save_report(target, open_ports)


def display_results(open_ports):

    print("Open Ports:")
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


def save_report(target, open_ports):

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

    target = input("\nEnter target IP or hostname: ")

    if target == "":
        print("[!] Target cannot be empty.")
        return

    print(f"\n[+] Target: {target}")

    scan_target(target)


if __name__ == "__main__":
    main()

