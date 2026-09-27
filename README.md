# Network Reconnaissance Tool

A Python-based network reconnaissance tool that uses Nmap to discover hosts, open ports, running services, and service information on authorized networks and systems.

## Project Goal

The goal of this project is to build a practical cybersecurity reconnaissance tool that automates common network discovery tasks using Python and Nmap.

The tool will progressively be developed to:

* Discover live hosts on a network
* Identify open ports
* Detect running services
* Identify service versions
* Organize discovered information into structured results
* Generate a readable reconnaissance report
* Provide a simple command-line interface

## Planned Features

### Host Discovery

Identify active hosts within a specified IP address or network range.

### Port Scanning

Scan hosts for open TCP ports and identify the services listening on those ports.

### Service Detection

Use Nmap to determine the services and, where available, versions associated with discovered ports.

### Python Automation

Use Python to automate Nmap scans and process the resulting information instead of manually running individual Nmap commands.

### Report Generation

Generate a structured report containing information such as:

```text
Host: 192.168.1.10

Port     State     Service     Version
22       open      ssh         OpenSSH
80       open      http        Apache
443      open      https       nginx
```

## Technologies

* Python
* Nmap
* Networking
* TCP/IP
* Linux
* Git/GitHub

## Project Structure

```text
Network-Reconnaissance-Tool/
│
├── README.md
└── recon.py
```

The project structure will expand as additional functionality is implemented.

## Development Roadmap

* [ ] Set up project and Nmap environment
* [ ] Perform a basic Nmap scan
* [ ] Run Nmap scans through Python
* [ ] Discover open ports
* [ ] Detect services
* [ ] Detect service versions
* [ ] Discover multiple hosts
* [ ] Parse scan results
* [ ] Store results in structured data
* [ ] Generate reconnaissance reports
* [ ] Add command-line arguments
* [ ] Add error handling
* [ ] Improve documentation

## Security Context

Network reconnaissance is commonly used during security assessments to understand what systems and services are exposed on a network.

This project is intended for use against systems and networks where the user has authorization to perform security testing.

## Skills Demonstrated

This project will demonstrate practical experience with:

* Python scripting
* Network reconnaissance
* Nmap
* TCP/IP networking
* Port scanning
* Service enumeration
* Data parsing
* Automation
* Security reporting
* Command-line tools

## Purpose

This project is part of a cybersecurity portfolio focused on building practical security tools rather than only completing theoretical exercises.

The project combines Python programming with networking and reconnaissance concepts to create a tool that can be expanded toward more advanced security automation.
