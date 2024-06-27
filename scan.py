import nmap # Import nmap module for network scanning
import datetime #Import datetime module for timestamping results

def scan_network(network_host):
    nm = nmap.PortScanner() #Initialize the nmap port scanner
    nm.scan(hosts=network_host, arguments='-sP')  # Ping the specified host
    results = [] #Initialize empty list for storing results
    for host in nm.all_hosts(): #Iterate over all hosts
        if nm[host].state() == 'up': #Check host is active
            host_info = { #create dictionary of hosts
                'host': host, #IP address of host
                'hostname': nm[host].hostname(),#Hostname
                'state': nm[host].state(), #State of host - up or down
                'open_ports': scan_open_ports(nm, host) #List open ports for host
            }
            results.append(host_info) #append host info to the result list
    return results #Return list

def scan_open_ports(nm, host):
    nm.scan(hosts=host, arguments='-p 1-1000')  # Scan ports 1-1000 of host
    open_ports = [] #Initialize empty list for storing open ports
    for proto in nm[host].all_protocols(): #check all protocols
        ports = nm[host][proto].keys() #Get all ports
        for port in ports: #check every port
            if nm[host][proto][port]['state'] == 'open': #check to see if port is open
                service = nm[host][proto][port]['name'] #get services name
                open_ports.append((port, service)) #append port and service name to list
    return open_ports #Return list of open ports

def print_organized_results(results):
    with open(r'C:/Users/......./Config.txt', 'a') as file: #open file
        file.write("Network Scan Results:\n") #Header for results
        file.write(f"Date:{datetime.datetime.now()}\n") #write current date 
        file.write("-" * 60 + "\n") #separator
        for result in results: #Iterate over scan results
            file.write(f"Host: {result['host']}\n") #write host IP
            file.write(f"  Hostname: {result['hostname']}\n") #write Hostname
            file.write(f"  State: {result['state']}\n") #write state of host
            file.write(f"  Open Ports:\n") #write header for ports
            if result['open_ports']: #check to see if there were open ports
                for port, service in result['open_ports']: #Iterate over each open port
                    file.write(f"    Port: {port}, Service: {service}\n") #write port and service
            else:
                file.write("    None\n") #write none if no ports found
            file.write('-' * 40 + "\n") #separator
        file.write("--" * 60 + "\n") #Long separator

if __name__ == '__main__':
    network_range = '192.168.1.1'  # You can change this to the desired network host
    scan_results = scan_network(network_range) #execute scan
    print_organized_results(scan_results) #print results in a neat format
    

