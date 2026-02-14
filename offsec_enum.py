#!/usr/bin/env python3
"""
OSCP Automated Enumeration Script
Author: Custom OSCP Tool
Description: Comprehensive enumeration automation for penetration testing
"""

import subprocess
import os
import sys
import argparse
import json
from datetime import datetime
from pathlib import Path
import threading
import queue

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class EnumerationEngine:
    def __init__(self, target, output_dir, ports=None, quick=False):
        self.target = target
        self.output_dir = Path(output_dir)
        self.ports = ports
        self.quick = quick
        self.open_ports = {}
        self.results = {}
        
        # Create output directory structure
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / "nmap").mkdir(exist_ok=True)
        (self.output_dir / "web").mkdir(exist_ok=True)
        (self.output_dir / "smb").mkdir(exist_ok=True)
        (self.output_dir / "ftp").mkdir(exist_ok=True)
        (self.output_dir / "misc").mkdir(exist_ok=True)
        
        self.log_file = self.output_dir / f"enum_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        
    def log(self, message, level="INFO"):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] [{level}] {message}"
        
        # Color output based on level
        if level == "INFO":
            print(f"{Colors.OKBLUE}[*]{Colors.ENDC} {message}")
        elif level == "SUCCESS":
            print(f"{Colors.OKGREEN}[+]{Colors.ENDC} {message}")
        elif level == "WARNING":
            print(f"{Colors.WARNING}[!]{Colors.ENDC} {message}")
        elif level == "ERROR":
            print(f"{Colors.FAIL}[-]{Colors.ENDC} {message}")
        
        # Write to log file
        with open(self.log_file, 'a') as f:
            f.write(log_entry + '\n')
    
    def run_command(self, command, output_file=None, timeout=None):
        """Execute shell command and optionally save output"""
        try:
            self.log(f"Running: {command}", "INFO")
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if output_file:
                with open(output_file, 'w') as f:
                    f.write(result.stdout)
                    if result.stderr:
                        f.write("\n=== STDERR ===\n")
                        f.write(result.stderr)
            
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            self.log(f"Command timed out: {command}", "WARNING")
            return False, "", "Timeout"
        except Exception as e:
            self.log(f"Error running command: {e}", "ERROR")
            return False, "", str(e)
    
    def initial_nmap_scan(self):
        """Quick initial port scan to identify open ports"""
        self.log("Starting initial port discovery...", "INFO")
        
        if self.ports:
            port_range = self.ports
        else:
            port_range = "-p-" if not self.quick else "-p 1-10000"
        
        output_file = self.output_dir / "nmap" / "initial_scan.nmap"
        
        command = f"nmap -sV -sC {port_range} -oA {output_file.with_suffix('')} --open -T4 {self.target}"
        
        success, stdout, stderr = self.run_command(command, timeout=3600)
        
        if success:
            self.log("Initial scan complete", "SUCCESS")
            self.parse_nmap_output(stdout)
        else:
            self.log("Initial scan failed", "ERROR")
    
    def parse_nmap_output(self, nmap_output):
        """Parse nmap output to extract open ports and services"""
        for line in nmap_output.split('\n'):
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                port_info = parts[0].split('/')[0]
                try:
                    port = int(port_info)
                    service = parts[2] if len(parts) > 2 else "unknown"
                    self.open_ports[port] = service
                    self.log(f"Found open port: {port}/{service}", "SUCCESS")
                except ValueError:
                    continue
    
    def detailed_nmap_scans(self):
        """Run detailed nmap scans on discovered ports"""
        if not self.open_ports:
            self.log("No open ports found, skipping detailed scans", "WARNING")
            return
        
        ports_str = ','.join(map(str, self.open_ports.keys()))
        
        # Vulnerability scan
        self.log("Running NSE vulnerability scripts...", "INFO")
        vuln_output = self.output_dir / "nmap" / "vuln_scan.nmap"
        vuln_cmd = f"nmap -sV --script=vuln -p {ports_str} -oA {vuln_output.with_suffix('')} {self.target}"
        self.run_command(vuln_cmd, timeout=1800)
        
        # UDP scan (top 100 ports)
        if not self.quick:
            self.log("Running UDP scan (top 100 ports)...", "INFO")
            udp_output = self.output_dir / "nmap" / "udp_scan.nmap"
            udp_cmd = f"sudo nmap -sU --top-ports 100 -oA {udp_output.with_suffix('')} {self.target}"
            self.run_command(udp_cmd, timeout=1800)
    
    def enumerate_http(self, port):
        """Enumerate HTTP/HTTPS services"""
        self.log(f"Enumerating HTTP on port {port}...", "INFO")
        
        protocol = "https" if port == 443 or "https" in self.open_ports.get(port, "").lower() else "http"
        url = f"{protocol}://{self.target}:{port}"
        
        # Nikto scan
        nikto_output = self.output_dir / "web" / f"nikto_{port}.txt"
        nikto_cmd = f"nikto -h {url} -output {nikto_output}"
        self.run_command(nikto_cmd, timeout=600)
        
        # Gobuster directory enumeration
        gobuster_output = self.output_dir / "web" / f"gobuster_{port}.txt"
        wordlist = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
        
        if os.path.exists(wordlist):
            gobuster_cmd = f"gobuster dir -u {url} -w {wordlist} -o {gobuster_output} -t 50 -x php,txt,html,jsp,asp,aspx"
            self.run_command(gobuster_cmd, timeout=1800)
        else:
            self.log(f"Wordlist not found: {wordlist}", "WARNING")
        
        # WhatWeb
        whatweb_output = self.output_dir / "web" / f"whatweb_{port}.txt"
        whatweb_cmd = f"whatweb {url} -a 3 --log-verbose={whatweb_output}"
        self.run_command(whatweb_cmd, timeout=300)
    
    def enumerate_smb(self, port):
        """Enumerate SMB services"""
        self.log(f"Enumerating SMB on port {port}...", "INFO")
        
        # Enum4linux
        enum4linux_output = self.output_dir / "smb" / "enum4linux.txt"
        enum4linux_cmd = f"enum4linux -a {self.target}"
        self.run_command(enum4linux_cmd, enum4linux_output, timeout=600)
        
        # SMBMap
        smbmap_output = self.output_dir / "smb" / "smbmap.txt"
        smbmap_cmd = f"smbmap -H {self.target}"
        self.run_command(smbmap_cmd, smbmap_output, timeout=300)
        
        # SMBClient list shares
        smbclient_output = self.output_dir / "smb" / "smbclient.txt"
        smbclient_cmd = f"smbclient -L //{self.target} -N"
        self.run_command(smbclient_cmd, smbclient_output, timeout=300)
        
        # NSE SMB scripts
        nmap_smb_output = self.output_dir / "smb" / "nmap_smb.txt"
        nmap_smb_cmd = f"nmap -p {port} --script=smb-enum-shares,smb-enum-users,smb-os-discovery {self.target}"
        self.run_command(nmap_smb_cmd, nmap_smb_output, timeout=300)
    
    def enumerate_ftp(self, port):
        """Enumerate FTP services"""
        self.log(f"Enumerating FTP on port {port}...", "INFO")
        
        # Anonymous FTP check
        ftp_output = self.output_dir / "ftp" / "ftp_enum.txt"
        nmap_ftp_cmd = f"nmap -p {port} --script=ftp-anon,ftp-bounce,ftp-syst {self.target}"
        self.run_command(nmap_ftp_cmd, ftp_output, timeout=300)
    
    def enumerate_ssh(self, port):
        """Enumerate SSH services"""
        self.log(f"Enumerating SSH on port {port}...", "INFO")
        
        ssh_output = self.output_dir / "misc" / "ssh_enum.txt"
        nmap_ssh_cmd = f"nmap -p {port} --script=ssh-auth-methods,ssh-hostkey {self.target}"
        self.run_command(nmap_ssh_cmd, ssh_output, timeout=300)
    
    def enumerate_mysql(self, port):
        """Enumerate MySQL services"""
        self.log(f"Enumerating MySQL on port {port}...", "INFO")
        
        mysql_output = self.output_dir / "misc" / "mysql_enum.txt"
        nmap_mysql_cmd = f"nmap -p {port} --script=mysql-info,mysql-databases,mysql-empty-password {self.target}"
        self.run_command(nmap_mysql_cmd, mysql_output, timeout=300)
    
    def enumerate_mssql(self, port):
        """Enumerate MSSQL services"""
        self.log(f"Enumerating MSSQL on port {port}...", "INFO")
        
        mssql_output = self.output_dir / "misc" / "mssql_enum.txt"
        nmap_mssql_cmd = f"nmap -p {port} --script=ms-sql-info,ms-sql-empty-password,ms-sql-config {self.target}"
        self.run_command(nmap_mssql_cmd, mssql_output, timeout=300)
    
    def enumerate_services(self):
        """Enumerate all discovered services"""
        service_mapping = {
            'http': [80, 8080, 8000, 8888, 3000],
            'https': [443, 8443],
            'smb': [139, 445],
            'ftp': [21],
            'ssh': [22],
            'mysql': [3306],
            'mssql': [1433]
        }
        
        for port, service in self.open_ports.items():
            service_lower = service.lower()
            
            # HTTP/HTTPS enumeration
            if 'http' in service_lower or port in service_mapping['http'] + service_mapping['https']:
                self.enumerate_http(port)
            
            # SMB enumeration
            elif 'smb' in service_lower or 'microsoft-ds' in service_lower or 'netbios' in service_lower or port in service_mapping['smb']:
                self.enumerate_smb(port)
            
            # FTP enumeration
            elif 'ftp' in service_lower or port in service_mapping['ftp']:
                self.enumerate_ftp(port)
            
            # SSH enumeration
            elif 'ssh' in service_lower or port in service_mapping['ssh']:
                self.enumerate_ssh(port)
            
            # MySQL enumeration
            elif 'mysql' in service_lower or port in service_mapping['mysql']:
                self.enumerate_mysql(port)
            
            # MSSQL enumeration
            elif 'mssql' in service_lower or 'ms-sql' in service_lower or port in service_mapping['mssql']:
                self.enumerate_mssql(port)
    
    def generate_report(self):
        """Generate a summary report"""
        self.log("Generating enumeration report...", "INFO")
        
        report_file = self.output_dir / "REPORT.md"
        
        with open(report_file, 'w') as f:
            f.write(f"# Enumeration Report for {self.target}\n\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("## Open Ports\n\n")
            if self.open_ports:
                for port, service in sorted(self.open_ports.items()):
                    f.write(f"- **{port}/tcp** - {service}\n")
            else:
                f.write("No open ports discovered\n")
            
            f.write("\n## Enumeration Files\n\n")
            f.write("Results have been saved in the following directories:\n\n")
            f.write("- `nmap/` - All nmap scan results\n")
            f.write("- `web/` - Web enumeration (nikto, gobuster, whatweb)\n")
            f.write("- `smb/` - SMB enumeration results\n")
            f.write("- `ftp/` - FTP enumeration results\n")
            f.write("- `misc/` - Other service enumeration\n")
            
            f.write("\n## Next Steps\n\n")
            f.write("1. Review all enumeration results\n")
            f.write("2. Identify potential vulnerabilities\n")
            f.write("3. Check web directories for sensitive files\n")
            f.write("4. Test for default credentials\n")
            f.write("5. Research service versions for known exploits\n")
        
        self.log(f"Report saved to {report_file}", "SUCCESS")
    
    def run(self):
        """Execute full enumeration workflow"""
        self.log(f"Starting enumeration of {self.target}", "INFO")
        self.log(f"Output directory: {self.output_dir}", "INFO")
        
        # Phase 1: Initial port scan
        self.initial_nmap_scan()
        
        # Phase 2: Detailed nmap scans
        if self.open_ports:
            self.detailed_nmap_scans()
            
            # Phase 3: Service-specific enumeration
            self.enumerate_services()
        
        # Phase 4: Generate report
        self.generate_report()
        
        self.log("Enumeration complete!", "SUCCESS")
        self.log(f"Check {self.output_dir} for all results", "INFO")

def main():
    banner = f"""
{Colors.OKGREEN}
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║        OSCP Automated Enumeration Tool v1.0              ║
║        Comprehensive Network & Service Enumeration        ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
{Colors.ENDC}
    """
    print(banner)
    
    parser = argparse.ArgumentParser(
        description="Automated enumeration tool for OSCP",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-o', '--output', default='./enum_results', 
                       help='Output directory (default: ./enum_results)')
    parser.add_argument('-p', '--ports', help='Port range (e.g., 1-1000 or 80,443,8080)')
    parser.add_argument('-q', '--quick', action='store_true',
                       help='Quick mode (scan top 10000 ports only)')
    
    args = parser.parse_args()
    
    # Create unique output directory with timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_dir = f"{args.output}_{args.target}_{timestamp}"
    
    # Initialize and run enumeration
    engine = EnumerationEngine(
        target=args.target,
        output_dir=output_dir,
        ports=args.ports,
        quick=args.quick
    )
    
    try:
        engine.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Enumeration interrupted by user{Colors.ENDC}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.FAIL}[!] Error: {e}{Colors.ENDC}")
        sys.exit(1)

if __name__ == "__main__":
    main()
