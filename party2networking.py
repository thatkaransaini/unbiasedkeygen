


import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
host = "127.0.0.1"
port = 10316
s.bind((host,port))
d = s.recvfrom(1024)
print d
reply = "potato"
s.sendto(reply.encode("ascii") , d[1])
d = s.recvfrom(1024)
print d
reply = "potato"
s.sendto(reply.encode("ascii") , d[1])