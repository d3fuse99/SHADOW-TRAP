import socket
import threading
import time
import sys
from concurrent.futures import ThreadPoolExecutor
from config import BANNER, PORTS_CONFIG, WHITE, GREEN, RED, RESET, YELLOW
from firewall import is_admin
from threat_intel import init_db, assess_threat
from deception import emulate_ssh, emulate_ftp, emulate_http, emulate_generic

executor = ThreadPoolExecutor(max_workers=100)

def handle_attacker(client_socket, client_address, port, config):
    try:
        ip = client_address[0]
        service = config["service"]
        
        print(f"\n{RED}[!] INCOMING: {ip}:{client_address[1]} -> Port {port} ({service}){RESET}")
        
        if port == 22:
            payload, points, reason = emulate_ssh(client_socket, ip)
        elif port == 21:
            payload, points, reason = emulate_ftp(client_socket, ip)
        elif port == 80:
            payload, points, reason = emulate_http(client_socket, ip)
        else:
            payload, points, reason = emulate_generic(client_socket, ip, config)
            
        if payload:
            print(f"{WHITE}[🔬] Payload ({ip}): {payload}{RESET}")
            
        assess_threat(ip, points, reason, port, service, payload)
    finally:
        try:
            client_socket.close()
        except Exception:
            pass

def start_port_listener(port, config):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind(("0.0.0.0", port))
        server.listen(128)
        print(f"{GREEN}[+] Trap [{config['service']}] active on port {port}{RESET}")
    except Exception as e:
        print(f"{RED}[-] Error binding port {port} ({config['service']}): {e}{RESET}")
        return

    while True:
        try:
            client_socket, client_address = server.accept()
            executor.submit(handle_attacker, client_socket, client_address, port, config)
        except Exception:
            break

def main():
    print(BANNER)
    
    if not is_admin():
        print(f"{RED}[!] Error: Administrator/Root privileges required to manage firewall rules.{RESET}")
        sys.exit(1)
        
    init_db()
    threads = []
    
    for port, config in PORTS_CONFIG.items():
        t = threading.Thread(target=start_port_listener, args=(port, config), daemon=True)
        t.start()
        threads.append(t)
        
    print(f"\n{WHITE}[*] Honeytraps online. Waiting for traffic... (Press Ctrl+C to stop){RESET}\n")
    
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[*] Shutting down SHADOW-TRAP.{RESET}")
        executor.shutdown(wait=False)
        sys.exit(0)

if __name__ == "__main__":
    main()