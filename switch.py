#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

DST_STP_MAC = b'\x01\x80\xc2\x00\x00\x00'
LINK_COST = 19
PORT_PRIORITY = 0x80

cam_table = {}
priority = 0
name_to_id = {}  # store in format {"r-0-1":1}
interfacesDict = {}  # store in format {id:info}
port_host_ext = {}
port_types = {}
access_vlan = {}
stp_manager = None
# Debug

def print_cam_table_contents():
    for k, v in cam_table.items():
        k_str = k[0]
        print(f"For {k_str} VLAN {k[1]} port {v}")


def mac_bytes_to_int(mac_bytes):
    return int.from_bytes(mac_bytes, byteorder='big')


def build_bridge_id(priority_value, mac_bytes):
    return ((priority_value & 0xFFFF) << 48) | mac_bytes_to_int(mac_bytes)


def compute_port_id(iface):
    return ((PORT_PRIORITY & 0xFF) << 8) | (iface & 0xFF)


def lowest_port_id(stp_state):
    if not stp_state["port_ids"]:
        return 0
    return min(stp_state["port_ids"].values())




def handle_bpdu(stp_state, interface, root_id, root_cost, bridge_id, port_id):
    if stp_state["port_types"].get(interface) != "trunk":
        return
    stp_state["neighbor_info"][interface] = {
        "root_id": root_id,
        "root_cost": root_cost,
        "bridge_id": bridge_id,
        "port_id": port_id,
    }
    select_root(stp_state)
    update_port_states(stp_state)


def select_root(stp_state):
    best_tuple = (stp_state["bridge_id"], 0, stp_state["bridge_id"], lowest_port_id(stp_state))
    best_port = None

    for port, info in stp_state["neighbor_info"].items():
        if stp_state["port_types"].get(port) != "trunk":
            continue
        candidate = (
            info["root_id"],
            info["root_cost"] + LINK_COST,
            info["bridge_id"],
            info["port_id"],
        )
        if candidate < best_tuple:
            best_tuple = candidate
            best_port = port

    stp_state["root_id"] = best_tuple[0]
    stp_state["root_cost"] = best_tuple[1]
    stp_state["root_port"] = best_port


def update_port_states(stp_state):
    for port in stp_state["interfaces"]:
        if stp_state["port_types"].get(port) != "trunk":
            stp_state["port_states"][port] = "forwarding"
            continue

        if stp_state["root_port"] == port:
            stp_state["port_states"][port] = "forwarding"
            continue

        info = stp_state["neighbor_info"].get(port)
        if info is None:
            stp_state["port_states"][port] = "forwarding"
            continue

        my_tuple = (
            stp_state["root_id"],
            stp_state["root_cost"],
            stp_state["bridge_id"],
            stp_state["port_ids"][port],
        )
        neighbor_tuple = (
            info["root_id"],
            info["root_cost"],
            info["bridge_id"],
            info["port_id"],
        )

        if my_tuple < neighbor_tuple:
            stp_state["port_states"][port] = "forwarding"
        else:
            stp_state["port_states"][port] = "blocking"


def is_forwarding_port(stp_state, port):
    if stp_state is None:
        return True
    if stp_state["port_types"].get(port) != "trunk":
        return True
    return stp_state["port_states"].get(port, "forwarding") == "forwarding"


def build_hpdu(src_mac):
    eth_type = struct.pack('!H', 0x0800)
    payload = bytes([0xFF])
    return DST_STP_MAC + src_mac + eth_type + payload


def build_ppdu(src_mac, seq_no, root_id, root_cost, bridge_id_value, port_id):
    eth_hdr = DST_STP_MAC + src_mac + struct.pack('!H', 0x0026)
    llc_hdr = struct.pack('!BBB', 0x42, 0x42, 0x03)
    ppdu_hdr = struct.pack('!HBBI', 0x0002, 0, 0x80, seq_no)

    flags = 0
    bridge_id = bridge_id_value.to_bytes(8, byteorder='big')
    root_bridge = root_id.to_bytes(8, byteorder='big')
    root_path_cost = struct.pack('!I', root_cost)
    port_identifier = struct.pack('!H', port_id & 0xFFFF)
    message_age = struct.pack('!H', 0)
    max_age = struct.pack('!H', 20)
    hello_time = struct.pack('!H', 2)
    forward_delay = struct.pack('!H', 15)

    ppdu_config = (
        struct.pack('!B', flags)
        + root_bridge
        + root_path_cost
        + bridge_id
        + port_identifier
        + message_age
        + max_age
        + hello_time
        + forward_delay
    )

    payload = llc_hdr + ppdu_hdr + ppdu_config
    return eth_hdr + payload


def build_ppdu_frame(stp_state, seq_no, interface):
    root_id = stp_state["root_id"]
    root_cost = stp_state["root_cost"]
    bridge_id = stp_state["bridge_id"]
    port_id = stp_state["port_ids"].get(interface, 0)
    src_mac = stp_state["mac"]
    return build_ppdu(src_mac, seq_no, root_id, root_cost, bridge_id, port_id)


def send_stp_frames(interfaces, stp_state):
    mac = stp_state["mac"]
    seq = 0
    src_mac = mac

    while True:
        for iface in interfaces:
            hpdu = build_hpdu(src_mac)
            send_to_link(iface, len(hpdu), hpdu)

            ppdu = build_ppdu_frame(stp_state, seq, iface)
            send_to_link(iface, len(ppdu), ppdu)

        seq = (seq + 1) % 100
        time.sleep(1)


def parse_ppdu_frame(data):
    if len(data) < 56:
        return None
    ether_type = (data[12] << 8) + data[13]
    if ether_type != 0x0026:
        return None
    llc_header = data[14:17]
    if llc_header != b'\x42\x42\x03':
        return None
    config_offset = 14 + 3 + 8
    config = data[config_offset:]
    if len(config) < 23:
        return None
    root_id = int.from_bytes(config[1:9], byteorder='big')
    root_cost = int.from_bytes(config[9:13], byteorder='big')
    bridge_id = int.from_bytes(config[13:21], byteorder='big')
    port_id = int.from_bytes(config[21:23], byteorder='big')
    return root_id, root_cost, bridge_id, port_id


def handle_stp_frame(interface, data, stp_state):
    parsed = parse_ppdu_frame(data)
    if parsed is None:
        return
    root_id, root_cost, bridge_id, port_id = parsed
    handle_bpdu(stp_state, interface, root_id, root_cost, bridge_id, port_id)


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




def forward_frame(interface, data):
    send_to_link(interface, len(data), data)

def check_mac_in_cam_table(mac):
    return cam_table.get(mac, -1)

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


def is_multicast(mac_bytes):
    # Check if the least significant bit of the first byte is set
    return (mac_bytes[0] & 0x01) == 1


# VLAN helpers adapted for Poli VLAN tagging
def calc_suma_nibbles(mac_str):
    mac_nou = mac_str.replace(":", "")
    suma = 0
    for ch in mac_nou:
        suma += int(ch, 16)
    return suma % 16


def should_check_extension(vlan_tci, dest_mac_str):
    first_octet = int(dest_mac_str.split(":")[0], 16)
    is_multicast_mac = (first_octet & 1) == 1
    return vlan_tci != -1 and not is_multicast_mac


def ext_id_matches(vlan_tci, dest_mac_str, expected_ext):
    if not should_check_extension(vlan_tci, dest_mac_str):
        return True
    if expected_ext is None:
        return True
    ext_id_from_frame = (vlan_tci >> 12) & 0xF
    return ext_id_from_frame == expected_ext


def verifica_mac_table(src_mac_str, vlan, port):
    key = (src_mac_str, vlan)
    if cam_table.get(key) != port:
        cam_table[key] = port

def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    global port_types, access_vlan, stp_manager
    switch_id = sys.argv[1]
    priority, ports_config = parse_switch_config(f"configs/switch{switch_id}.cfg")
    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = list(range(0, num_interfaces))
    for interface in interfaces:
        int_real = get_interface_name(interface)
        name_to_id[int_real] = interface
    print(ports_config)
    print(priority)
    print(switch_id)
    for name, info in ports_config.items():
        if name in name_to_id:
            idx = name_to_id[name]
            interfacesDict[idx] = info
        else:
            raise ValueError(f"Interface {name} not found in wrapper")

    for idx in interfaces:
        interfacesDict.setdefault(idx, {"mode": "trunk"})

    port_types = {}
    access_vlan = {}
    for idx in interfaces:
        info = interfacesDict[idx]
        port_types[idx] = info["mode"]
        if info["mode"] == "access":
            access_vlan[idx] = info["vlan"]

    switch_mac = get_switch_mac()

    print("# Starting switch with id {}".format(switch_id), flush=True)
    print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in switch_mac))
    # print the interface table
    print("\n=== Port Configuration Table ===")
    for idx, info in interfacesDict.items():
        print(f"Port {idx} ({get_interface_name(idx)}): {info}")
    print("================================\n")

    stp_manager = init_stp(interfaces, port_types, priority, switch_mac)
    stp_manager = {}
    stp_manager["interfaces"] = list(interfaces)
    stp_manager["port_types"] = port_types
    stp_manager["priority"] = priority
    stp_manager["mac"] = switch_mac
    stp_manager["bridge_id"] = build_bridge_id(priority, switch_mac)
    stp_manager["root_id"] = stp_manager["bridge_id"]
    stp_manager["root_cost"] = 0
    stp_manager["root_port"] = None
    stp_manager["port_states"] = {iface: "forwarding" for iface in interfaces}
    stp_manager["port_ids"] = {iface: compute_port_id(iface) for iface in interfaces}
    stp_manager["neighbor_info"] = {}
    threading.Thread(target=send_stp_frames, args=(interfaces, stp_manager), daemon=True).start()

    # Printing interface names
    for i in interfaces:
        print(get_interface_name(i))

    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()

        dest_mac_bytes, src_mac_bytes, ethertype, vlan_id, vlan_tci = parse_ethernet_header(data)

        if dest_mac_bytes == DST_STP_MAC:
            handle_stp_frame(interface, data, stp_manager)
            continue

        if ethertype == 0x0800 and data[0] == 255:
            # Received HPDU (hello)
            print(f"Received HPDU on interface {interface}")
            continue
        # Check if interface is configured
        if interface not in interfacesDict:
            print(f"Warning: Received frame on unconfigured interface {interface}")
            continue

        if port_types.get(interface) == "trunk" and not is_forwarding_port(stp_manager, interface):
            print(f"Dropping frame on blocking trunk port {interface}")
            continue

        print(f"Frame received on interface {interface} with mode {interfacesDict[interface]['mode']}")
        print(interfacesDict)
        #interface_mode = interfacesDict[interface]["mode"]
        vlan_tag = (data[12] << 8) + data[13]
        print(f"ethertype: {hex(vlan_tag)}")
        dest_mac_str = ':'.join(f'{b:02x}' for b in dest_mac_bytes)
        src_mac_str = ':'.join(f'{b:02x}' for b in src_mac_bytes)
        if(vlan_tag == 0x8200):
            # am primit de pe trunk
            verifica_mac_table(src_mac_str, vlan_id, interface)
            print_cam_table_contents()
            #Try forward the frame
            dest_interface = check_mac_in_cam_table((dest_mac_str, vlan_id))
            # trimitem pentru toate interfetele din acelasi vlan si trunkuri
            if dest_interface == -1:
                for i in interfaces:
                    if i != interface:
                        if port_types.get(i) == "access" and access_vlan.get(i) == vlan_id:
                            expected_ext = port_host_ext.get(i)
                            if not ext_id_matches(vlan_tci, dest_mac_str, expected_ext):
                                continue
                            new_data = data[:12] + data[16:]
                            forward_frame(i, new_data)
                        elif port_types.get(i) == "trunk":
                            if not is_forwarding_port(stp_manager, i):
                                continue
                            forward_frame(i, data)
            # am gasit destinatia in tabela, daca e trunk trimitem asa cum e daca e access scoatem tagul
            else:
                if port_types.get(dest_interface) == "access":
                    expected_ext = port_host_ext.get(dest_interface)
                    if not ext_id_matches(vlan_tci, dest_mac_str, expected_ext):
                        print("Dropping frame: VLAN extension mismatch for access port")
                        continue
                    new_data = data[:12] + data[16:]
                    forward_frame(dest_interface, new_data)
                elif port_types.get(dest_interface) == "trunk":
                    if not is_forwarding_port(stp_manager, dest_interface):
                        continue
                    forward_frame(dest_interface, data)

            # Note. Adding a VLAN tag can be as easy as
            # tagged_frame = data[0:12] + create_vlan_tag(5, 10) + data[12:]

            print(f'Destination MAC: {dest_mac_str}')
            print(f'Source MAC: {src_mac_str}')
            print(f'EtherType: {ethertype}')

            print("Received frame of size {} on interface {}".format(length, interface), flush=True)

            # TODO: Implement forwarding with learning
            # TODO: Implement VLAN support
            # TODO: Implement STP support

            # data is of type bytes.
            # send_to_link(i, length, data)
        else:
            # Received from access port - get VLAN ID from interface config
            vlan_id = interfacesDict[interface]["vlan"]
            verifica_mac_table(src_mac_str, vlan_id, interface)
            ext_id_src = calc_suma_nibbles(src_mac_str)
            port_host_ext[interface] = ext_id_src
            print_cam_table_contents()
            dest_interface = check_mac_in_cam_table((dest_mac_str, vlan_id))
            if dest_interface == -1:
                # Flood
                for i in interfaces:
                    if i != interface:
                        if port_types.get(i) == "access" and access_vlan.get(i) == vlan_id:
                            expected_ext = port_host_ext.get(i)
                            if not ext_id_matches(vlan_tci, dest_mac_str, expected_ext):
                                continue
                            forward_frame(i, data)
                        elif port_types.get(i) == "trunk":
                            if not is_forwarding_port(stp_manager, i):
                                continue
                            # need to add vlan tag
                            new_data = data[:12] + create_vlan_tag(ext_id_src, vlan_id) + data[12:]
                            forward_frame(i, new_data)
            else:
                if port_types.get(dest_interface) == "access":
                    forward_frame(dest_interface, data)
                elif port_types.get(dest_interface) == "trunk":
                    if not is_forwarding_port(stp_manager, dest_interface):
                        continue
                    tagged_data = data[:12] + create_vlan_tag(ext_id_src, vlan_id) + data[12:]
                    forward_frame(dest_interface, tagged_data)
        print()
            

if __name__ == "__main__":
    main()
 

