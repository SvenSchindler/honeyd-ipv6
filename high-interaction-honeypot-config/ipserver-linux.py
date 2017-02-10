import socket
import time
import subprocess
from uuid import getnode as get_mac

honeyd_ip = "2001:db8:10::1"
prefix = "2001:db8:10::"
pathToYourIpUpdateScript = '/path/to/your/update_ip.sh'

#generate mac and an ipv6 address based on the ethernet address
mac = open('/sys/class/net/eth0/address').read().strip() 
m = mac.split(":")
eui = m[0]+ m[1] + ":" + m[2] + "ff:fe" + m[3] + ":" + m[4] + m[5]
print "my mac is " + str(mac) + " and my eui is " + str(eui)

autogenerated_address = prefix + eui
subprocess.call(['/root/change_ip.sh',str(autogenerated_address)])

#send newly generated ip to honeyd
client_socket = socket.socket(socket.AF_INET6,socket.SOCK_STREAM)
client_socket.connect((honeyd_ip,4455))
client_socket.send(mac+";"+autogenerated_address)
client_socket.close()

time.sleep(2)

#wait for ip change messages
print "try to bind to " + str(autogenerated_address)
s= socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.bind((autogenerated_address,50000))
s.listen(1)

try:
  connection, addr = s.accept()
  addrToConfigure = connection.recv(1024).strip()
  if not addrToConfigure:
    connection.close()
  else:
    print "configure " + str(addrToConfigure)
    subprocess.call([pathToYourIpUpdateScript,str(addrToConfigure)," " + str(autogenerated_address)])
finally:
  s.close()
  
#you may want to clean up the files automatically after execution
