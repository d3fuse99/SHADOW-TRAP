import socket

s = socket.socket()
s.connect(('127.0.0.1', 22))

print(s.recv(1024).decode(errors='ignore'), end='')
s.sendall(b"SSH-2.0-MyTestClient\r\n")

print(s.recv(1024).decode(errors='ignore'), end='')
username = input()
s.sendall(username.encode() + b"\r\n")

print(s.recv(1024).decode(errors='ignore'), end='')
password = input()
s.sendall(password.encode() + b"\r\n")

print(s.recv(1024).decode(errors='ignore'))
s.close()