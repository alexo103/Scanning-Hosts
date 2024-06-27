#Import scan_network and print_organized_results from scan.py file
from scan import scan_network, print_organized_results 


if __name__ == '__main__':
    network_host = '192.168.1.1'  # You can change this to the desired network host
    print(f"Scanning Network Host: {network_host}")#Print what host is beign scan
    scan_results = scan_network(network_host) #excute scan_network function
    print_organized_results(scan_results) #excute print_organized_result function
    print("Network scan results saved to Config.txt") #print saved message
