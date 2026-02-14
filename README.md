# OSCP Automated Enumeration Tool

A comprehensive automated enumeration script designed for OSCP exam efficiency. This tool automates the tedious enumeration process, allowing you to focus on exploitation.

## Features

- **Automated Port Scanning**: Initial discovery and detailed nmap scans
- **Service-Specific Enumeration**:
  - HTTP/HTTPS: nikto, gobuster, whatweb
  - SMB: enum4linux, smbmap, smbclient
  - FTP: Anonymous access checks
  - SSH: Auth methods, host keys
  - MySQL/MSSQL: Database enumeration
- **Vulnerability Scanning**: NSE vuln scripts
- **Organized Output**: Structured directories for easy review
- **Automatic Reporting**: Markdown summary of findings

## Prerequisites

### Required Tools

Install these tools on your Kali Linux system:

```bash
# Update system
sudo apt update

# Install required tools
sudo apt install -y nmap nikto gobuster enum4linux smbmap smbclient whatweb python3

# Verify installations
which nmap nikto gobuster enum4linux smbmap whatweb
```

### Wordlists

The script uses common Kali wordlists. Ensure they're installed:

```bash
# Install wordlists
sudo apt install -y wordlists

# Extract dirb wordlists
sudo gunzip /usr/share/wordlists/dirb/* 2>/dev/null
```

## Installation

```bash
# Download the script
chmod +x oscp_auto_enum.py

# Make it executable
sudo ln -s $(pwd)/oscp_auto_enum.py /usr/local/bin/oscp-enum
```

## Usage

### Basic Usage

```bash
# Simple enumeration
sudo python3 oscp_auto_enum.py 10.10.10.10

# With custom output directory
sudo python3 oscp_auto_enum.py 10.10.10.10 -o /root/oscp/target1
```

### Advanced Options

```bash
# Quick mode (top 10000 ports only)
sudo python3 oscp_auto_enum.py 10.10.10.10 -q

# Specific ports
sudo python3 oscp_auto_enum.py 10.10.10.10 -p 80,443,8080

# Port range
sudo python3 oscp_auto_enum.py 10.10.10.10 -p 1-1000
```

### Full Command Reference

```
usage: oscp_auto_enum.py [-h] [-o OUTPUT] [-p PORTS] [-q] target

Arguments:
  target                Target IP address or hostname
  
Options:
  -h, --help            Show help message
  -o, --output OUTPUT   Output directory (default: ./enum_results)
  -p, --ports PORTS     Port range (e.g., 1-1000 or 80,443,8080)
  -q, --quick           Quick mode (scan top 10000 ports only)
```

## Output Structure

```
enum_results_<target>_<timestamp>/
├── REPORT.md                 # Summary report
├── enum_<timestamp>.log      # Detailed log file
├── nmap/                     # All nmap scans
│   ├── initial_scan.nmap
│   ├── vuln_scan.nmap
│   └── udp_scan.nmap
├── web/                      # Web enumeration
│   ├── nikto_80.txt
│   ├── gobuster_80.txt
│   └── whatweb_80.txt
├── smb/                      # SMB enumeration
│   ├── enum4linux.txt
│   ├── smbmap.txt
│   └── smbclient.txt
├── ftp/                      # FTP enumeration
│   └── ftp_enum.txt
└── misc/                     # Other services
    ├── ssh_enum.txt
    └── mysql_enum.txt
```

## OSCP Exam Workflow

### Before the Exam

1. **Test the script** on HTB/PG machines
2. **Customize** service enumeration based on your preferences
3. **Verify** all tools are installed and working
4. **Create aliases** for quick access

### During the Exam

1. **Start enumeration immediately** on all targets:
   ```bash
   sudo python3 oscp_auto_enum.py 192.168.x.10 -o target1 &
   sudo python3 oscp_auto_enum.py 192.168.x.11 -o target2 &
   sudo python3 oscp_auto_enum.py 192.168.x.12 -o target3 &
   ```

2. **Review results** as they complete
3. **Focus on exploitation** while scans run in background
4. **Check REPORT.md** for quick overview

### Time-Saving Tips

- Run enumeration on all targets simultaneously
- Start with quick mode (-q) if time-limited
- Review web/smb directories first (common vectors)
- Keep the script running while you manually exploit

## Customization

### Add Custom Enumeration

Edit the `enumerate_services()` method to add your own tools:

```python
def enumerate_custom(self, port):
    """Your custom enumeration"""
    self.log(f"Running custom enum on port {port}...", "INFO")
    output = self.output_dir / "custom" / f"custom_{port}.txt"
    cmd = f"your-tool -target {self.target} -port {port}"
    self.run_command(cmd, output, timeout=300)
```

### Modify Wordlists

Change the wordlist path in `enumerate_http()`:

```python
wordlist = "/usr/share/wordlists/your-custom-list.txt"
```

### Adjust Timeouts

Modify timeout values for longer/shorter scans:

```python
self.run_command(command, timeout=600)  # 10 minutes
```

## Troubleshooting

### Permission Errors

Some scans require root:
```bash
sudo python3 oscp_auto_enum.py <target>
```

### Missing Tools

Install missing dependencies:
```bash
sudo apt install -y <tool-name>
```

### Slow Scans

Use quick mode or specify ports:
```bash
sudo python3 oscp_auto_enum.py 10.10.10.10 -q
sudo python3 oscp_auto_enum.py 10.10.10.10 -p 1-1000
```

## Exam-Specific Notes

- **Don't rely solely on automation**: Always do manual verification
- **Check results regularly**: Automated tools can miss things
- **Understand the tools**: Know what each command does
- **Document manually**: Screenshots and notes are still required
- **Test thoroughly**: Practice on HTB/PG before the exam

## Legal Disclaimer

This tool is for authorized penetration testing and educational purposes only (like OSCP exam). Never use against systems you don't have explicit permission to test.

## OSCP Exam Compliance

- No automated exploitation (enumeration only)
- No Metasploit auto-exploit modules
- Manual verification required
- Screenshots needed for report

## Credits

Created for OSCP exam preparation. Good luck on your certification!

## License

Free to use for OSCP preparation and ethical hacking education.
