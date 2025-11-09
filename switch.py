#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name
cam_table = {}
priority = 0
name_to_id = {} # store in format {"r-0-1":1}
interfacesDict = {} # store in format {id:info}
#Debug

def print_cam_table_contents():
    for k,v in cam_table.items() :
        k = ':'.join(f'{b:02x}' for b in k)
        print(f"For {k} port {v}")


def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]

    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    vlan_tci = -1
    # Check for VLAN tag (0x8200 in network byte order is b'\x82\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id, vlan_tci

def create_vlan_tag(ext_id, vlan_id):
    # Use EtherType = 8200h for our custom 802.1Q-like protocol.
    # PCP and DEI bits are used to extend the original VID.
    #
    # The ext_id should be the sum of all nibbles in the MAC address of the
    # host attached to the _access_ port. Ignore the overflow in the 4-bit
    # accumulator.
    #
    # NOTE: Include these 4 extensions bits only in the check for unicast
    #       frames. For multicasts, assume that you're dealing with 802.1Q.
    return struct.pack('!H', 0x8200) + \
           struct.pack('!H', ((ext_id & 0xF) << 12) | (vlan_id & 0x0FFF))

def function_on_different_thread():
    while True:
        time.sleep(1)


def forward_frame(interface, data):
    send_to_link(interface, len(data), data)

def check_mac_in_cam_table(mac):
    if mac in cam_table:
        return cam_table[mac]
    else:
        return -1
    
def parse_switch_config(filename):
    ports = {}
    priority = None

    with open(filename, 'r') as f:
        lines = [line.strip() for line in f if line.strip()]

    if not lines:
        raise ValueError("Config file is empty")

    priority = int(lines[0])

    for line in lines[1:]:
        parts = line.split()
        if len(parts) != 2:
            raise ValueError(f"Invalid line in config: {line}")
        iface, val = parts
        if val.upper() == "T":
            ports[iface] = {"mode": "trunk"}
        else:
            ports[iface] = {"mode": "access", "vlan": int(val)}

    return priority, ports

def sum_nibbles(source_mac_bytes):
    total = 0
    # adun ultimii 4 biti(de la dreapta) cu primii 4(de la stanga)
    for b in source_mac_bytes:
        total+=b&0x0F+b>>4
    return total&0x0F

def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]
    priority,ports_config = parse_switch_config(f"switch{switch_id}.cfg")
    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)
    for interface in interfaces:
        int_real = get_interface_name(interface)
        name_to_id[int_real]=interface
    for name, info in ports_config.items():
        if name in name_to_id:
            idx = name_to_id[name]
            interfacesDict[idx] = info
        else:
            raise ValueError(f"Interface {name} not found in wrapper")

    print("# Starting switch with id {}".format(switch_id), flush=True)
    print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))
    # print the interface table
    print("\n=== Port Configuration Table ===")
    for idx, info in ports.items():
        print(f"Port {idx} ({get_interface_name(idx)}): {info}")
    print("================================\n")

    # Example of running a function on a separate thread.
    t = threading.Thread(target=function_on_different_thread)
    t.start()

    # Printing interface names
    for i in interfaces:
        print(get_interface_name(i))

    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()

        dest_mac, src_mac, ethertype, vlan_id, vlan_tci = parse_ethernet_header(data)
        
        if(ethertype==0x8200):
            # am primit de pe trunk
            cam_table[(src_mac,vlan_id)]=interface
            print_cam_table_contents()
            #Try forward the frame
            dest_interface = check_mac_in_cam_table((dest_mac,vlan_id))
            if dest_interface == -1:
                for i in interfaces:
                    if i != interface:
                        if "vlan" in interfacesDict[i] and interfacesDict[i]["vlan"]==vlan_id:
                            new_data = data[:12] + data[16:]
                            forward_frame(i, new_data)
                        elif interfacesDict[i]["mode"]=="trunk":
                            forward_frame(i, data)
            else:
                # am gasit destinatia in tabela
                if "vlan" in interfacesDict[dest_interface]:
                    if interfacesDict[dest_interface]["vlan"]==vlan_id:
                        new_data = data[:12] + data[16:]
                        forward_frame(dest_interface, new_data)
                elif interfacesDict[dest_interface]["mode"]=="trunk":
                    forward_frame(dest_interface, data)
                        









            dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
            src_mac = ':'.join(f'{b:02x}' for b in src_mac)
            
            # Note. Adding a VLAN tag can be as easy as
            # tagged_frame = data[0:12] + create_vlan_tag(5, 10) + data[12:]

            print(f'Destination MAC: {dest_mac}')
            print(f'Source MAC: {src_mac}')
            print(f'EtherType: {ethertype}')

            print("Received frame of size {} on interface {}".format(length, interface), flush=True)

            # TODO: Implement forwarding with learning
            # TODO: Implement VLAN support
            # TODO: Implement STP support

            # data is of type bytes.
            # send_to_link(i, length, data)
        else:
            # no vlan
            # vlan_id = -1
            cam_table[(src_mac,vlan_id)]=interface
            print_cam_table_contents()
            dest_interface = check_mac_in_cam_table((dest_mac,vlan_id))
            if dest_interface == -1:
                # Flood
                for i in interfaces:
                    if i != interface:
                        forward_frame(i, data)
            else:
                forward_frame(dest_interface, data)


if __name__ == "__main__":
    main()
