import socket
import sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
host = "127.0.0.1"                           
port = 10316   
data = "hello"
#data=data.encode('ascii')
try :
    s.sendto(data, (host, port))
    print "Hash sent to Party Two"
    d = s.recvfrom(1024)
    print "Hash Received from Party Two"
    print d
except socket.error:
    print('')