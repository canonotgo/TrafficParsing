from scapy.all import sniff, Ether, DHCP, BOOTP
import socket
import psutil

# Configuration
BROADCAST_ADDRESS = "255.255.255.255"
OPTION_MAP = {
    'pad': 0,
    'subnet_mask': 1,
    'time_offset': 2,
    'router': 3,
    'time_server': 4,
    'name_server': 5,
    'domain_name_server': 6,
    'log_server': 7,
    'cookie_server': 8,
    'lpr_server': 9,
    'impress_server': 10,
    'resource_location_server': 11,
    'host_name': 12,
    'boot_file_size': 13,
    'merit_dump_file': 14,
    'domain_name': 15,
    'swap_server': 16,
    'root_path': 17,
    'extensions_path': 18,
    'ip_forwarding': 19,
    'non_local_source_routing': 20,
    'policy_filter': 21,
    'class_id': 22,
    'client_id': 61,
    'vendor_specific_info': 43,
    'requested_addr': 50,
    'lease_time': 51,
    'overload': 52,
    'dhcp_message_type': 53,
    'message-type': 53,
    'server_identifier': 54,
    'server_id': 54,
    'param_req_list': 55,
    'message': 56,
    'max_dhcp_size': 57,
    'renewal_time': 58,
    'rebinding_time': 59,
    'vendor_class_identifier': 60,
    'vendor_class_id': 60,
    'client_identifier': 61,
    'network_interface_identifier': 62,
    'hostname': 12,
    'fqdn': 81,
    'client_fqdn': 81,
    'client_FQDN': 81,
    'option_82': 82,
    'end': 255
}

def get_local_ip_windows():
    """Get the local IP address, subnet mask, and interface name."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("119.29.29.29", 53))
    ip_address = s.getsockname()[0]
    s.close()

    ip_netmask = None
    interface_name = None
    interfaces = psutil.net_if_addrs()

    for interface, addrs in interfaces.items():
        for addr in addrs:
            if addr.family == socket.AF_INET and str(addr.address) == str(ip_address):
                ip_netmask = addr.netmask
                interface_name = interface
                break
        if interface_name:
            break

    return ip_address, ip_netmask, interface_name

def send(packet):
    """Send a packet via UDP broadcast."""
    clientSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    clientSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    clientSock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    clientSock.sendto(packet, (BROADCAST_ADDRESS, 68))

def print_dhcp_options(options):
    """Print DHCP options."""
    for option in options:
        try:
            option_type = option.get_type() if hasattr(option, 'get_type') else 'Unknown'
            option_data = option.get_data() if hasattr(option, 'get_data') else 'Unknown'
            print(f"Option Code: {option_type}, Option Data: {option_data}")
        except AttributeError as e:
            print(f"Error printing option: {e}")

def process_dhcp_packet(dhcp, packet, message_type_name):
    """Process DHCP packet (Discover or Request)."""
    options = {opt[0]: opt[1] for opt in dhcp.options if isinstance(opt, tuple)}

    print(f"------------------------{message_type_name}------------------------")
    # print(f"Transaction ID: {options.get('transaction_id', 'N/A')}")
    transaction_id = packet[BOOTP].xid
    print(f"Transaction ID: {transaction_id}")
    print(f"Client 2mac Address: {packet[Ether].src}")
    # print(f"Client IP Address (CIADDR): {options.get('ciaddr', 'N/A')}")
    client_mac = packet[BOOTP].chaddr[:6]
    client_mac = ':'.join(f'{byte:02x}' for byte in client_mac[:6])
    
    print(f"Client 3mac address: {client_mac}")
    print(f"Requested IP Address (Requested IP): {options.get('requested_addr', 'N/A')}")

    print(f"DHCP Options in {message_type_name}:")
    option_list = []
    parameter_list = None
    for opt in dhcp.options:
        if isinstance(opt, tuple):
            option_key, option_value = opt
            if option_key == 'end':
                break
            option_number = OPTION_MAP.get(option_key, 'unknown')
            if option_key == "client_id":
                option_value = ':'.join(f'{byte:02x}' for byte in option_value[1:])
            option_value = option_value.decode('utf-8') if isinstance(option_value, bytes) else option_value
            print(f"Option Number: {option_number}, Option Key: {option_key}, Option Value: {option_value}")
            if option_key == "param_req_list":
                parameter_list = option_value
            option_list.append(option_number)

    print("Option List:", option_list)
    print("Parameter List:", parameter_list)

    print(f"--------------------end----------------------")

def process_dhcp_discover(dhcp, packet):
    """Process DHCP Discover packet."""
    process_dhcp_packet(dhcp, packet, "DHCP DISCOVER")

def process_dhcp_request(dhcp, packet):
    """Process DHCP Request packet."""
    process_dhcp_packet(dhcp, packet, "DHCP REQUEST")

def handle_packet(packet):
    """Handle incoming DHCP packets."""
    if DHCP in packet:
        dhcp = packet[DHCP]
        if dhcp.options and isinstance(dhcp.options[0], tuple):
            message_type = dhcp.options[0][1]
            if message_type == 1:  # DHCP Discover
                process_dhcp_discover(dhcp, packet)
            elif message_type == 3:  # DHCP Request
                process_dhcp_request(dhcp, packet)

if __name__ == "__main__":
    local_ip, subnet_mask, interface_name = get_local_ip_windows()
    print("\nINTERFACE", interface_name)
    print("\n\tIP address:", local_ip)
    print("\tSubnet mask:", subnet_mask)
    print("\tBroadcast address:", BROADCAST_ADDRESS)
    print("\n**************************************************************************************\n")

    sniff(filter="udp and port 67", prn=handle_packet, iface=interface_name)
    # sniff(filter="udp and port 67", prn=handle_packet)