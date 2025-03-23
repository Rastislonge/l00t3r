import psutil
import re
import nmap
import requests
import os
import xml.etree.ElementTree as ET

# Globals
nm = nmap.PortScanner(nmap_search_path=('/usr/bin/nmap',))

# Get interfaces
def get_interfaces():
    interfaces=psutil.net_if_addrs().keys()
    found_wireless_interfaces=[]

    for interface in interfaces:
        try:
            interface_match = re.search(r"Wi-Fi.*|wlan.*|wlp.*", interface)
            found_wireless_interfaces.append(interface_match.group())
        except:
            pass

    if found_wireless_interfaces == ['']:
        print("[x] No wireless interfaces detected! Exiting...")
        exit()

    return found_wireless_interfaces

def get_subnet_mask(wireless_interfaces):
    addrs = psutil.net_if_addrs()
    for iface in wireless_interfaces:
        if iface in addrs:
            for addr in addrs[iface]:
                if addr.family == 2:  # AF_INET (IPv4)
                    return addr.address, addr.netmask
    return None

def get_ip_with_cidr(ip_and_subnet):
    target_subnets = []

    for wireless_interface in ip_and_subnet:
        ip=ip_and_subnet[0]
        subnet=ip_and_subnet[1]
        print("IP Address: "+ip)
        print("Subnet Mask: "+subnet)

        bits = ''.join(f'{int(octet):08b}' for octet in subnet.split('.'))
        cidr_suffix = bits.count('1')
        ip_cidr=f"{ip}/{cidr_suffix}"
        print("IP with cidr: "+ip_cidr)
        target_subnets.append(ip_cidr)
        return target_subnets

def scan_network(target_subnets):
    # Scan the local network for http ports
    i=0
    for target in target_subnets:
        print(f"Subnet {i}: {target}")
        i+=1
    picked_subnet = input("Enter the index of the subnet you want to target (otherwise it will do all): ")

    outputs=[]
    try:
        picked_subnet=int(picked_subnet)
        target=target_subnets[picked_subnet]
        print(f"[*] Starting subnet scan against {target}")
        nm.scan(hosts=f'{target}', arguments='-sn')
        outputs=nm.get_nmap_last_output()
    except:
        for target in target_subnets:
            print(f"[*] Starting subnet scan against all subnets")
            nm.scan(hosts=f'{target}', arguments='-sn')
            outputs+=nm.get_nmap_last_output()

    xml_data = nm.get_nmap_last_output()
    root = ET.fromstring(xml_data)
    ip_list = []

    for host in root.findall('host'):
        addr = host.find('address')
        if addr is not None and addr.get('addrtype') == 'ipv4':
            ip_list.append(addr.get('addr'))
    
    print(f"[+] Discovered IPs: {ip_list}")
    return(ip_list)

# Scan each ip for http/https ports
def get_web_ports(ip_list):
    ips_with_http_ports = []
    #ip_list = ip_list[-1:]  # Only keep the last item for testing
    for ip in ip_list:
        ip_info = {}
        print(f"[*] Scanning {ip} for open web ports...")
        nm.scan(hosts=ip, arguments='-sS -T4 -p 1-65535 --open -n --host-timeout 1m')
        if ip in nm.all_hosts() and 'tcp' in nm[ip]:
            for port in nm[ip]['tcp']:
                port_name = nm[ip]['tcp'][port]['name']
                if "http" in port_name:
                    if "https" in port_name:
                        ip_info[port] = "https"
                    else:
                        ip_info[port] = "http"
        if ip_info:
            ip_info['ip'] = ip
            ips_with_http_ports.append(ip_info)
    print(f"[+] Found HTTP ports on: {ips_with_http_ports}")
    return ips_with_http_ports

# For each web port do a request
def get_index_html(ips_with_http_ports):
    for ip_with_http_ports in ips_with_http_ports:
            print(ip_with_http_ports)
            ip = ip_with_http_ports['ip']
            ip_with_http_ports.popitem()
            for port, protocol in list(ip_with_http_ports.items()):
                try:
                    main_page = requests.get(f'{protocol}://{ip}:{port}/', verify=False, timeout=10)
                except:
                    print(f"[x] There was an error querying for {protocol}://{ip}:{port}/")
                # If the request returns a directory listing then download all files
                if "directory listing" in main_page.text.lower():
                    filenames = re.findall(r'.*href="(.*?)">.*', main_page.text)
                    if not os.path.exists(ip):
                        os.makedirs(ip)
                    for filename in filenames:
                        file_contents = requests.get(f'{protocol}://{ip}:{port}/{filename}', verify=False, timeout=10)
                        file = open(f"{ip}/"+filename, "w")
                        file.write(file_contents.text)
                        file.close()
                        print(f"[+] Saved {filename} to {ip}")
                else:
                    print(f"[*] {protocol}://{ip}:{port}/ did not contain a directory listing.")

def main():
    wireless_interfaces=get_interfaces()
    ip_and_subnet=get_subnet_mask(wireless_interfaces)
    target_subnets=get_ip_with_cidr(ip_and_subnet)
    ip_list=scan_network(target_subnets)
    ips_with_http_ports=get_web_ports(ip_list)
    get_index_html(ips_with_http_ports)


if __name__ == "__main__":
    main()