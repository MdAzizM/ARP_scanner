from scapy.all import ARP, Ether, srp, conf

def default_gateway():
    default_route = conf.route.route("0.0.0.0")
    Local_IP = default_route[1]
    Intr = default_route[0]
    Gateway = default_route[2]  # Get the local IP address
    return Local_IP, Intr, Gateway

def arp_scan(target_ip):
    # Create an ARP request packet
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast MAC

    packet = ether / arp  # Combine Ethernet and ARP

    # Send packet and receive response
    result = srp(packet, timeout=2, verbose=0)[0]

    # Parse the result
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

# Example usage:
if __name__ == "__main__":
    target = input("put network ip: ")
    devices = arp_scan(target)
    Local_IP, Intr, Gateway = default_gateway()
    print("Connected devices:")
    for device in devices:
        print(f"{device['ip']} - {device['mac']}")
    print(len(devices)-1, "devices found.")
    print("Gateway:", Gateway,"\nLoc_IP:", Local_IP, "\nIntrf:", Intr)