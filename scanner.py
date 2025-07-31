import ipaddress
network = ipaddress.ip_network("192.168.1.0/24",strict=False)
for ip in network.hosts():
    print(ip)