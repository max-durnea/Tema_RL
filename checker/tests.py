from collections import namedtuple, OrderedDict
import sys

from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import Ether, ARP, checksum, Dot1Q

import info


ETHER_BROADCAST = "ff:ff:ff:ff:ff:ff"


def error(msg, *args):
    print("-- {}".format(msg), *args, file=sys.stderr)


def dump_packets(packets):
    print("###################################")
    print("All packets:\n")
    for p in packets:
        error("Packet\n{}".format(p.show(dump=True)))

    print("###################################")


def check_nothing(testname, packets):
    """Verify a machine received 0 packages. Used as a default."""
    #if len(packets) != 0:
    #   error("Excess packets")
    #  dump_packets(packets)
    # return False

    return True


def valid_arp_req(host, packet, addr):
    if ARP not in packet:
        return False

    a = packet[ARP]
    if not a.get_field("op").i2repr(a, a.op) == "who-has":
        return False

    if a[ARP].hwsrc != addr:
        return False

    return True


def valid_arp_req_from_router(host, router, packet):
    return valid_arp_req(host, packet, info.get("router_mac", host, router))


def valid_arp_req_to_router(host, router, packet):
    return valid_arp_req(host, packet, info.get("host_mac", host))


def valid_arp_reply(host, packet, addr_s, addr_d):
    if ARP not in packet:
        return False

    a = packet[ARP]
    if not a.get_field("op").i2repr(a, a.op) == "is-at":
        return False

    if a[ARP].hwsrc != addr_s:
        return False

    if a[ARP].hwdst != addr_d:
        return False

    return True


def valid_arp_reply_from_router(host, router, packet):
    src = info.get("router_mac", router, host)
    dst = info.get("host_mac", host)
    return valid_arp_reply(host, packet, src, dst)


def valid_arp_reply_to_router(host, router, packet):
    src = info.get("host_mac", host)
    dst = info.get("router_mac", host, router)
    return valid_arp_reply(host, packet, src, dst)


def valid_icmp_unreachable(host, packet):
    return ICMP in packet and packet[ICMP].type == 3 and packet[ICMP].code == 2


def cull_icmp_unreachable(host, packets):
    culled_packets = []
    count = 0
    for packet in packets:
        if valid_icmp_unreachable(host, packet):
            count += 1
        else:
            culled_packets.append(packet)

    return count, culled_packets


def cull_dull_packets(host, router, packets):
    """Remove uninteresting packets"""
    router_f = {
        valid_arp_req_from_router : False,
        valid_arp_reply_to_router : False,
    }
    host_f = {
        valid_arp_req_to_router,
        valid_arp_reply_from_router,
    }

    culled_packets = []
    for packet in packets:
        v = False
        for fn, b in router_f.items():
            if fn(host, router, packet):
                if b:
                    return False, []

                router_f[fn] = True
                v = True
                break

        for fn in host_f:
            if fn(host, router, packet):
                v = True

        if not v:
            culled_packets.append(packet)

    return True, culled_packets


def validate_all_from_host(host, packets):
    """True if all packets are sent from host (an eventual replies)"""
    for packet in packets:
        if Ether not in packet:
            return False

        if packet[Ether].src != info.get("host_mac", host):
            return False

    return True


def validate_all_from_host_or_replies(host, packets):
    """True if all packets are sent from host (an eventual replies)"""
    for ps, pr in zip(packets[::2], packets[1::2]):
        if Ether not in ps or Ether not in pr:
            return False

        if ps[Ether].src != info.get("host_mac", host):
            return False

        if pr[Ether].dst != info.get("host_mac", host):
            return False

    return True


def sender_default(testname, packets):
    hs = TESTS[testname].host_s
    router = TESTS[testname].router
    #res, packets = cull_dull_packets(hs, router, packets)
    #_, packets = cull_icmp_unreachable(hs, packets)
    #ok = validate_all_from_host(hs, packets)
    #if not ok:
    #    ok = validate_all_from_host_or_replies(hs, packets)

    #return res and ok
    
    return True


# Learning (30p)
# STP (40p)
# VLAN (20p)

def icmp_a(testname):
    hs = TESTS[testname].host_s
    hr = TESTS[testname].host_r
    hp = TESTS[testname].host_p
    router = TESTS[testname].router
    r_mac = info.get("host_mac", hp)
    s_mac = info.get("host_mac", hs)
    s_ip = info.get("host_ip", hs + 1)
    target_ip = info.get("host_ip", hp + 1)

    return [Ether(src=s_mac, dst=r_mac) / IP(src=s_ip, dst=target_ip) / ICMP()]


def icmp_check_arrival_p(testname, packets):
    hs = TESTS[testname].host_s
    router = TESTS[testname].router
    hr = TESTS[testname].host_r

    origpackets = packets.copy()
    res, packets = cull_dull_packets(hr, router, packets)

    res = False
    for p in packets:
        if ICMP in p:
            res = True
            break

    if res is False:
        error("ICMP has not arrived at destination")
        dump_packets(origpackets)
        return False

    return res


def bad_mac_icmp_a(testname):
    hs = TESTS[testname].host_s
    hr = TESTS[testname].host_r
    hp = TESTS[testname].host_p
    router = TESTS[testname].router
    r_mac = info.get("host_mac", hp)
    s_mac = info.get("host_mac", hs)
    s_ip = info.get("host_ip", hs + 1)
    target_ip = info.get("host_ip", hp + 1)

    return [Ether(src=s_mac, dst='de:ad:be:ef:00:09') / IP(src=s_ip, dst=target_ip) / ICMP()]

def bad_icmp_check_arrival_p(testname, packets):
    hs = TESTS[testname].host_s
    router = TESTS[testname].router
    hr = TESTS[testname].host_r

    origpackets = packets.copy()
    res, packets = cull_dull_packets(hr, router, packets)

    k = 0
    res = True
    for p in packets:
        if ICMP in p:
            k = k + 1

    if k != 1:
        res = False

    if res is False:
        error("Too many ICMPs arrived at the destination. Meaning we have a cycle. {} packets".format(k))
        dump_packets(origpackets)
        return False

    return res

def icmp_check_no_arrival_p(testname, packets):
    hs = TESTS[testname].host_s
    router = TESTS[testname].router
    hr = TESTS[testname].host_r

    origpackets = packets.copy()
    res, packets = cull_dull_packets(hr, router, packets)

    # Check that no packet arrived at hp
    res = True
    for p in packets:
        if ICMP in p:
            res = False
            break

    if res is False:
        error("ICMP shouldn't have arrived here")
        dump_packets(origpackets)
        return False

    return res


def icmp_check_arrival_p(testname, packets):
    hs = TESTS[testname].host_s
    router = TESTS[testname].router
    hr = TESTS[testname].host_r

    origpackets = packets.copy()
    res, packets = cull_dull_packets(hr, router, packets)

    res = False
    for p in packets:
        if ICMP in p:
            res = True
            break

    if res is False:
        error("ICMP has not arrived at destination")
        dump_packets(origpackets)
        return False

    return res


Test = namedtuple("Test", ["host_s", "host_r", "router", "active_fn", "passive_fn", "categories", "host_p"])
TESTS = OrderedDict([

        # MAC table tests
        ("ICMP_0_2_ARRIVES_2", Test(0, 2, 0, icmp_a, icmp_check_arrival_p, ["1. learning"], 2)),
        ("ICMP_0_3_ARRIVES_3", Test(0, 3, 0, icmp_a, icmp_check_arrival_p, ["1. learning"], 3)),
        ("ICMP_0_2_NOT_ARRIVES_3", Test(0, 3, 0, icmp_a, icmp_check_no_arrival_p, ["1. learning"], 2)),
        ("ICMP_0_3_NOT_ARRIVES_2", Test(0, 2, 0, icmp_a, icmp_check_no_arrival_p, ["1. learning"], 3)),

        # VLAN tests
        ("ICMP_0_2_ARRIVES_1_VLAN", Test(0, 2, 0, icmp_a, icmp_check_arrival_p, ["2. VLAN"], 2)),
        ("ICMP_3_5_ARRIVES_2_VLAN", Test(3, 5, 0, icmp_a, icmp_check_arrival_p, ["2. VLAN"], 5)),
        ("ICMP_1_4_ARRIVES_3_VLAN", Test(1, 4, 0, icmp_a, icmp_check_arrival_p, ["2. VLAN"], 4)),

        ("ICMP_0_1_NOT_ARRIVES_1_VLAN", Test(0, 1, 1, icmp_a, icmp_check_no_arrival_p, ["2. VLAN"], 1)),
        ("ICMP_0_3_NOT_ARRIVES_1_VLAN", Test(0, 3, 1, icmp_a, icmp_check_no_arrival_p, ["2. VLAN"], 3)),
        ("ICMP_3_2_NOT_ARRIVES_2_VLAN", Test(3, 2, 1, icmp_a, icmp_check_no_arrival_p, ["2. VLAN"], 2)),
        ("ICMP_3_4_NOT_ARRIVES_2_VLAN", Test(3, 4, 1, icmp_a, icmp_check_no_arrival_p, ["2. VLAN"], 4)),
        ("ICMP_4_5_NOT_ARRIVES_3_VLAN", Test(4, 5, 1, icmp_a, icmp_check_no_arrival_p, ["2. VLAN"], 5)),
        ("ICMP_4_0_NOT_ARRIVES_3_VLAN", Test(4, 0, 1, icmp_a, icmp_check_no_arrival_p, ["2. VLAN"], 0)),

        # STP tests
        ("ICMP_4_1_ARRIVES_1_STP", Test(4, 1, 0, icmp_a, icmp_check_arrival_p, ["3. STP"], 1)),
        ("ICMP_3_5_ARRIVES_3_STP", Test(3, 3, 0, icmp_a, icmp_check_arrival_p, ["3. STP"], 5)),
        ("ICMP_3_5_BAD_MAC_ARRIVES_5_ONCE_STP", Test(3, 5, 0, bad_mac_icmp_a, bad_icmp_check_arrival_p, ["3. STP"], 5)),

        ])

CATEGORY_POINTS = {
        "2. VLAN": 30,
        "1. learning": 30,
        "3. STP": 40,
        }

CATEGORY_DICT = {}
for test in TESTS.values():
    for cat in test.categories:
        CATEGORY_DICT[cat] = CATEGORY_DICT.get(cat, 0) + 1
