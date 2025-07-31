#Importing necessary libraries
import ipaddress
import socket

#Allows you to scan multiple devices at once (uses threads)
import concurrent.futures

#Function to check if an indicidual IP address is online
def is_host_online(ipaddress):
    try:
        #attempt to connect to port 80
        socket.setdefaulttimeout(1)#After 1 second, give up on connecting
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)#AF_INET specifies IPv4 socket and SOCK_STREAM sets the socket type to TCP
        result = s.connect_ex((str(ipaddress), 80))#Returns 0 if connection successful
        s.close()
        return result == 0 #if successful connection -  assume host is online
    except:
        return False
    
def scan_subnet(subnet):
    try:
        network = ipaddress.ip_network(subnet, strict = False)#Parse through the subnet
    except ValueError:
        print("invalid Subnet format")
        return
        
    print(f"Scanning the subnet {subnet}")
    hosts_online = []

    #use of threading to scan multiple IPs faster
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        future_to_ip = {}
        for ip in network.hosts():#iterates through IPs in given subnet
            future = executor.submit(is_host_online, ip)
            future_to_ip[future] = ip

        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                if future.result():
                    print(f"Host {ip} is online")
                    hosts_online.append(str(ip))
            except:
                print(f"Error in checking {ip}: {Exception}")

    print(f"Scan complete - {len(hosts_online)} hosts are online")
    return hosts_online



scan_subnet("192.168.1.0/24")