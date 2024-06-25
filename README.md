# Description
Scanning Host is an open source tool which enables security professional to scan any network host to conduct passive reconnaissance on host. 
The tool can scan an single IP (i.e 192.168.1.110) or can also be modified to scan an entire IP range (i.e. 192.168.1.0/24).
# Modules
•	Python-nmap
# Installation
	pip install python-nmap
# How it works
•	First, the script scans the network host provided. If the host is UP, return Host IP, Hostname, State, Open Ports, and Service running on port.	

        def scan_network(network_host):
            nm = nmap.PortScanner()
            nm.scan(hosts=network_host, arguments='-sP')  # Ping scan
            results = []
            for host in nm.all_hosts():
                if nm[host].state() == 'up':
                    host_info = {
                        'host': host,
                        'hostname': nm[host].hostname(),
                        'state': nm[host].state(),
                        'open_ports': scan_open_ports(nm, host)
                    }
                    results.append(host_info)
            return results

•	Next, scan for open ports and return port number and service
        
        def scan_open_ports(nm, host):
            nm.scan(hosts=host, arguments='-p 1-1024')  # Scan ports 1-1024
            open_ports = []
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    if nm[host][proto][port]['state'] == 'open':
                        service = nm[host][proto][port]['name']
                        open_ports.append((port, service))
            return open_ports

•	Lastly, write the results of Scan on a config.txt file

        def print_organized_results(results):
            with open('YourLocation/Config.txt', 'w') as file:
                file.write("Network Scan Results:\n")
                file.write("-" * 60 + "\n")
                for result in results:
                    file.write(f"Host: {result['host']}\n")
                    file.write(f"  Hostname: {result['hostname']}\n")
                    file.write(f"  State: {result['state']}\n")
                    file.write(f"  Open Ports:\n")
                    if result['open_ports']:
                        for port, service in result['open_ports']:
                            file.write(f"    Port: {port}, Service: {service}\n")
                    else:
                        file.write("    None\n")
                    file.write('-' * 40 + "\n")
                file.write("--" * 60 + "\n")
                
•	Results

        Network Scan Results:
        ------------------------------------------------------------
        Host: 192.168.1.118
          Hostname: my_cool_PC
          State: up
          Open Ports:
            Port: 80, Service: http
	    Port: 443, Service: https
        ----------------------------------------
        ------------------------------------------------------------
