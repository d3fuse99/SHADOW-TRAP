import socket
import urllib.parse
from config import YELLOW, RESET

def emulate_ssh(client_socket, ip):
    try:
        client_socket.sendall(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n")
        client_socket.settimeout(15.0)
        client_banner = client_socket.recv(1024)
        
        client_socket.sendall(b"login as: ")
        username = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()
        
        client_socket.sendall(f"{username}@ubuntu-server's password: ".encode('utf-8'))
        password = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()
        
        client_socket.sendall(b"\r\nAccess denied.\r\n")
        
        payload = f"SSH login attempt -> User: '{username}' | Pass: '{password}'"
        return payload, 10, "SSH brute-force attempt"
    except Exception:
        return "SSH connection dropped", 4, "Aborted SSH session"

def emulate_ftp(client_socket, ip):
    try:
        client_socket.sendall(b"220 (vsFTPd 3.0.3)\r\n")
        client_socket.settimeout(15.0)
        
        user_data = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()
        username = user_data.replace("USER", "").strip() if "USER" in user_data else user_data
        
        client_socket.sendall(b"331 Please specify the password.\r\n")
        
        pass_data = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()
        password = pass_data.replace("PASS", "").strip() if "PASS" in pass_data else pass_data
        
        client_socket.sendall(b"530 Login incorrect.\r\n")
        
        payload = f"FTP login attempt -> User: '{username}' | Pass: '{password}'"
        return payload, 10, "FTP brute-force attempt"
    except Exception:
        return "FTP connection dropped", 4, "Aborted FTP session"

def emulate_http(client_socket, ip):
    try:
        client_socket.settimeout(10.0)
        request_data = client_socket.recv(4096).decode('utf-8', errors='ignore')
        if not request_data:
            return "Empty HTTP request", 2, "TCP Port scan"
        
        first_line = request_data.split("\r\n")[0]
        
        if "POST" in first_line:
            parts = request_data.split("\r\n\r\n", 1)
            raw_body = parts[1] if len(parts) > 1 else ""
            decoded_body = urllib.parse.unquote_plus(raw_body).strip()
            payload = f"HTTP POST -> {first_line} | Body: {decoded_body}"
            
            response = (
                "HTTP/1.1 401 Unauthorized\r\n"
                "Content-Type: text/html\r\n"
                "Connection: close\r\n\r\n"
                "<html><body><h2>401 Unauthorized</h2><p>Access Denied.</p></body></html>"
            )
            client_socket.sendall(response.encode())
            return payload, 10, "HTTP POST authentication attempt"
        
        html = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            "Connection: close\r\n\r\n"
            "<!DOCTYPE html><html><head><title>Admin Login</title></head>"
            "<body style='font-family:sans-serif;text-align:center;padding:50px;background:#111;color:#eee;'>"
            "<h2>System Management Portal</h2>"
            "<form method='POST'><input type='text' name='username' placeholder='Username' required><br><br>"
            "<input type='password' name='password' placeholder='Password' required><br><br>"
            "<button type='submit'>Sign In</button></form></body></html>"
        )
        client_socket.sendall(html.encode())
        return f"HTTP GET -> {first_line}", 5, "HTTP web discovery"
    except Exception:
        return "HTTP connection dropped", 2, "Aborted HTTP connection"

def emulate_generic(client_socket, ip, config):
    try:
        if config["banner"]:
            client_socket.sendall(config["banner"])
        client_socket.settimeout(15.0)
        
        data = client_socket.recv(1024)
        payload = data.decode('utf-8', errors='ignore').strip() if data else ""
        
        points = 8 if payload else 2
        reason = "Data payload transmitted" if payload else "TCP Connect / Port scan"
        return payload, points, reason
    except socket.timeout:
        return "", 2, "Port scan (Timeout)"
    except Exception:
        return "Generic error", 1, "Connection error"