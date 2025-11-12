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


def mac_bytes_to_int(mac_bytes):
    return int.from_bytes(mac_bytes, byteorder='big')


def build_bridge_id(priority, mac_bytes):
    return ((priority & 0xFFFF) << 48) | mac_bytes_to_int(mac_bytes)


def init_stp(interfaces, port_types, priority, switch_mac):
    """Initialize STP state."""
    stp = {}
    stp["interfaces"] = list(interfaces)
    stp["port_types"] = port_types
    stp["priority"] = priority
    stp["mac"] = switch_mac
    stp["bridge_id"] = build_bridge_id(priority, switch_mac)
    stp["root_id"] = stp["bridge_id"]
    stp["root_cost"] = 0
    stp["root_port"] = None
    stp["port_states"] = {iface: "forwarding" for iface in interfaces}
    stp["port_ids"] = {iface: compute_port_id(iface) for iface in interfaces}
    stp["neighbor_info"] = {}
    return stp


def compute_port_id(iface):
    return ((PORT_PRIORITY & 0xFF) << 8) | (iface & 0xFF)


def lowest_port_id(stp):
    if not stp["port_ids"]:
        return 0
    return min(stp["port_ids"].values())


def handle_bpdu(stp, interface, root_id, root_cost, bridge_id, port_id):
    """Update neighbor info with received BPDU and recompute root."""
    if stp["port_types"].get(interface) != "trunk":
        return
    stp["neighbor_info"][interface] = {
        "root_id": root_id,
        "root_cost": root_cost,
        "bridge_id": bridge_id,
        "port_id": port_id,
    }
    select_root(stp)
    update_port_states(stp)


def select_root(stp):
    """Select the best root bridge and root port."""
    best_tuple = (stp["bridge_id"], 0, stp["bridge_id"], lowest_port_id(stp))
    best_port = None

    for port, info in stp["neighbor_info"].items():
        if stp["port_types"].get(port) != "trunk":
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

    stp["root_id"] = best_tuple[0]
    stp["root_cost"] = best_tuple[1]
    stp["root_port"] = best_port


def update_port_states(stp):
    """Set the STP state (forwarding/blocking) for each port."""
    for port in stp["interfaces"]:
        if stp["port_types"].get(port) != "trunk":
            stp["port_states"][port] = "forwarding"
            continue

        if stp["root_port"] == port:
            stp["port_states"][port] = "forwarding"
            continue

        info = stp["neighbor_info"].get(port)
        if info is None:
            stp["port_states"][port] = "forwarding"
            continue

        my_tuple = (
            stp["root_id"],
            stp["root_cost"],
            stp["bridge_id"],
            stp["port_ids"][port],
        )
        neighbor_tuple = (
            info["root_id"],
            info["root_cost"],
            info["bridge_id"],
            info["port_id"],
        )

        if my_tuple < neighbor_tuple:
            stp["port_states"][port] = "forwarding"
        else:
            stp["port_states"][port] = "blocking"


def is_forwarding_port(stp, port):
    if stp["port_types"].get(port) != "trunk":
        return True
    return stp["port_states"].get(port, "forwarding") == "forwarding"


def build_ppdu_frame(stp, seq_no, interface):
    root_id = stp["root_id"]
    root_cost = stp["root_cost"]
    bridge_id = stp["bridge_id"]
    port_id = stp["port_ids"].get(interface, 0)
    src_mac = stp["mac"]
    return build_ppdu(src_mac, seq_no, root_id, root_cost, bridge_id, port_id)


def parse_ethernet_header(data):
    dest_mac = data[0:6]
    src_mac = data[6:12]
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    vlan_tci = -1
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id, vlan_tci


def create_vlan_tag(ext_id, vlan_id):
    return struct.pack('!H', 0x8200) + struct.pack(
        '!H', ((ext_id & 0xF) << 12) | (vlan_id & 0x0FFF)
    )


def function_on_different_thread():
    while True:
        time.sleep(1)


def verifica_mac_table(mac_table, src_mac, vlan, port):
    key = (src_mac, vlan)
    if mac_table.get(key) != port:
        mac_table[key] = port


def is_multicast_mac(mac):
    first_octet = int(mac.split(':')[0], 16)
    return (first_octet & 1) == 1


def should_check_extension(vlan_tci, dest_mac):
    return vlan_tci != -1 and not is_multicast_mac(dest_mac)


def ext_id_matches(vlan_tci, dest_mac, expected_ext):
    if not should_check_extension(vlan_tci, dest_mac):
        return True
    if expected_ext is None:
        return True
    ext_id_from_frame = (vlan_tci >> 12) & 0xF
    return ext_id_from_frame == expected_ext


def forwarding(
    mac_table,
    dest_mac,
    port_src,
    interfaces,
    data,
    vlan,
    port_types,
    access_vlan,
    vlan_tci,
    stp_manager,
    port_host_ext,
):
    if dest_mac != "ff:ff:ff:ff:ff:ff":
        if (dest_mac, vlan) in mac_table:
            port_dst = mac_table[(dest_mac, vlan)]
            if port_dst != port_src:
                if port_types.get(port_dst) == "access":
                    if access_vlan.get(port_dst) == vlan:
                        expected_ext = port_host_ext.get(port_dst)
                        if not ext_id_matches(vlan_tci, dest_mac, expected_ext):
                            return
                        if vlan_tci != -1:
                            data_out = data[0:12] + data[16:]
                        else:
                            data_out = data
                        send_to_link(port_dst, len(data_out), data_out)
                elif port_types.get(port_dst) == "trunk":
                    if not is_forwarding_port(stp_manager, port_dst):
                        return
                    send_to_link(port_dst, len(data), data)
        else:
            for o in sorted(interfaces):
                if o != port_src:
                    if port_types.get(o) == "trunk":
                        if not is_forwarding_port(stp_manager, o):
                            continue
                        send_to_link(o, len(data), data)
                    elif port_types.get(o) == "access" and access_vlan.get(o) == vlan:
                        expected_ext = port_host_ext.get(o)
                        if not ext_id_matches(vlan_tci, dest_mac, expected_ext):
                            continue
                        if vlan_tci != -1:
                            data_out = data[0:12] + data[16:]
                        else:
                            data_out = data
                        send_to_link(o, len(data_out), data_out)
    else:
        for o in sorted(interfaces):
            if o != port_src:
                if port_types.get(o) == "trunk":
                    if not is_forwarding_port(stp_manager, o):
                        continue
                    send_to_link(o, len(data), data)
                elif port_types.get(o) == "access" and access_vlan.get(o) == vlan:
                    expected_ext = port_host_ext.get(o)
                    if not ext_id_matches(vlan_tci, dest_mac, expected_ext):
                        continue
                    if vlan_tci != -1:
                        data_out = data[0:12] + data[16:]
                    else:
                        data_out = data
                    send_to_link(o, len(data_out), data_out)


def calc_suma_nibbles(mac):
    mac_nou = mac.replace(":", "")
    suma = 0
    for b in mac_nou:
        suma += int(b, 16)
    result = suma % 16
    return result


def citeste_vlan(switch_id, name_to_interface):
    port_types = {}
    access_vlan = {}
    priority = 32768

    filename = f"configs/switch{switch_id}.cfg"
    with open(filename) as f:
        lines = [line.strip() for line in f if line.strip()]
        priority = int(lines[0])
        for line in lines[1:]:
            parts = line.split()
            if not parts:
                continue

            name = parts[0]
            interface = name_to_interface.get(name)
            if interface is None:
                continue

            if name.startswith("rr-"):
                port_types[interface] = "trunk"
            elif name.startswith("r-"):
                vlan_id = int(parts[1])
                port_types[interface] = "access"
                access_vlan[interface] = vlan_id

    for interface in name_to_interface.values():
        port_types.setdefault(interface, "trunk")

    return port_types, access_vlan, priority


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


def send_stp_frames(interfaces, stp_manager):
    mac = stp_manager["mac"]
    seq = 0
    src_mac = mac

    while True:
        for iface in interfaces:
            hpdu = build_hpdu(src_mac)
            send_to_link(iface, len(hpdu), hpdu)

            ppdu = build_ppdu_frame(stp_manager, seq, iface)
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


def handle_stp_frame(interface, data, stp_manager):
    parsed = parse_ppdu_frame(data)
    if parsed is None:
        return
    root_id, root_cost, bridge_id, port_id = parsed
    handle_bpdu(stp_manager, interface, root_id, root_cost, bridge_id, port_id)


def main():
    switch_id = sys.argv[1]

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = list(range(0, num_interfaces))
    switch_mac = get_switch_mac()

    print("# Starting switch with id {}".format(switch_id), flush=True)
    print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in switch_mac))

    name_to_interface = {}
    for i in interfaces:
        name = get_interface_name(i)
        print(name)
        name_to_interface[name] = i

    port_types, access_vlan, priority = citeste_vlan(switch_id, name_to_interface)
    print("[CONFIG] Port types:", port_types)
    print("[CONFIG] Access VLAN:", access_vlan)

    mac_table = {}
    port_host_ext = {}
    stp_manager = init_stp(interfaces, port_types, priority, switch_mac)
    threading.Thread(
        target=send_stp_frames, args=(interfaces, stp_manager), daemon=True
    ).start()

    while True:
        interface, data, length = recv_from_any_link()

        dest_mac_bytes, src_mac_bytes, ethertype, vlan_id, vlan_tci = parse_ethernet_header(
            data
        )
        if dest_mac_bytes == DST_STP_MAC:
            handle_stp_frame(interface, data, stp_manager)
            continue

        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac_bytes)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac_bytes)

        ext_id_src = None
        if port_types.get(interface) == "access":
            vlan = access_vlan.get(interface)
            if vlan is None:
                continue
            ext_id_src = calc_suma_nibbles(src_mac)
            port_host_ext[interface] = ext_id_src
        else:
            vlan = vlan_id
        if vlan is None:
            continue

        if port_types.get(interface) == "trunk" and not is_forwarding_port(
            stp_manager, interface
        ):
            continue

        if port_types.get(interface) == "access" and vlan_id == -1:
            if ext_id_src is None:
                ext_id_src = calc_suma_nibbles(src_mac)
            tag = create_vlan_tag(ext_id_src, vlan)
            data = data[0:12] + tag + data[12:]
            vlan_tci = int.from_bytes(tag[2:4], byteorder='big')

        print(f'Destination MAC: {dest_mac}')
        print(f'Source MAC: {src_mac}')
        print(f'EtherType: {ethertype}')

        print("Received frame of size {} on interface {}".format(length, interface), flush=True)

        verifica_mac_table(mac_table, src_mac, vlan, interface)
        forwarding(
            mac_table,
            dest_mac,
            interface,
            interfaces,
            data,
            vlan,
            port_types,
            access_vlan,
            vlan_tci,
            stp_manager,
            port_host_ext,
        )
        print("[TABLE]", mac_table, flush=True)


if __name__ == "__main__":
    main()

 
