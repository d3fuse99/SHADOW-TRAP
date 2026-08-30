import os
import sys
import ctypes
import subprocess
import ipaddress
from config import RED, GREEN, YELLOW, RESET

def is_admin():
    try:
        if sys.platform == "win32":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.geteuid() == 0
    except Exception:
        return False

def block_ip(ip):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        print(f"{RED}[-] Block aborted: Invalid IP format ({ip}){RESET}")
        return False

    print(f"{YELLOW}[*] Applying firewall rule for {ip}...{RESET}")
    
    try:
        if sys.platform == "win32":
            rule_name = f"SHADOW-TRAP-Block-{ip}"
            ps_command = (
                f'$ErrorActionPreference = "Stop"; '
                f'if (-not (Get-NetFirewallRule -DisplayName "{rule_name}" -ErrorAction SilentlyContinue)) {{ '
                f'New-NetFirewallRule -DisplayName "{rule_name}" -Direction Inbound -Action Block -RemoteAddress "{ip}" | Out-Null }}'
            )
            subprocess.run(["powershell", "-Command", ps_command], capture_output=True, text=True, check=True)
        else:
            check_cmd = subprocess.run(["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True)
            if check_cmd.returncode != 0:
                subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True, capture_output=True)
                
        print(f"{GREEN}[+] IP {ip} successfully blocked.{RESET}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"{RED}[-] Firewall execution error for {ip}: {e.stderr.strip() if e.stderr else e}{RESET}")
        return False
    except Exception as e:
        print(f"{RED}[-] Unexpected firewall error: {e}{RESET}")
        return False