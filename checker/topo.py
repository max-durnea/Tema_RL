import os
from pathlib import Path
import tempfile
import threading
import time
import signal
import shutil
import sys

import tests
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.link import Link
from mininet.util import dumpNodeConnections

import info

import os.path
from os import path

POINTS_PER_TEST = 1


def signal_handler(signal, frame):
    sys.exit(0)


def static_arp():
    srcp = os.path.join("", info.ARP_TABLE)
    return path.exists(srcp)


class FullTopo(Topo):
    def build(self, nr=2, nh=2):
        routers = []
        for i in range(nr):
            routers.append(self.addHost(info.get("switch_name", i)))

        for i in range(nr):
            for j in range(i + 1, nr):
                ifn = info.get("r2r_if_name", i, j)
                self.addLink(routers[i], routers[j], delay="1ms", intfName1=ifn,
                             intfName2=ifn)
        
        for i in range(nr):
            for j in range(nh):
                hidx = i * nh + j

                host = self.addHost(info.get("host_name", hidx))
                i1 = info.get("host_if_name", hidx)
                i2 = info.get("router_if_name", j)
                self.addLink(host, routers[i], delay="1ms", intfName1=i1, intfName2=i2)


class FullNM(object):
    def __init__(self, net, n_routers, n_hosts):
        self.net = net
        self.hosts = []
        self.routers = []
        self.n_hosts = n_hosts
        self.i = 0
        for i in range(n_routers):
            r = self.net.get(info.get("switch_name", i))
            hosts = []
            for j in range(n_hosts):
                hidx = i * n_hosts + j
                h = self.net.get(info.get("host_name", hidx))
                hosts.append(h)
                self.hosts.append(h)

            self.routers.append((r, hosts))

    def setup_ifaces(self):
        for i, (router, hosts) in enumerate(self.routers):
            for j, host in enumerate(hosts):
                hidx = i * len(hosts) + j
                host_ip = info.get("host_ip", hidx + 1)
                router_ip = info.get("router_ip", hidx + 100)
                host_if = info.get("host_if_name", hidx)
                router_if = info.get("router_if_name", j)

                router.setIP(router_ip, prefixLen=24, intf=router_if)
                host.setIP(host_ip, prefixLen=24, intf=host_if)
                host.cmd("echo 3600 > /proc/sys/net/ipv4/neigh/{}/gc_stale_time".format(host_if))

        nr = len(self.routers)
        for i in range(nr):
            for j in range(i + 1, nr):
                ri_if = info.get("r2r_if_name", i, j)
                rj_if = info.get("r2r_if_name", i, j)
                ri_ip = info.get("r2r_ip1", i, j)
                rj_ip = info.get("r2r_ip2", i, j)
                self.routers[i][0].setIP(ri_ip, prefixLen=24, intf=ri_if)
                self.routers[j][0].setIP(rj_ip, prefixLen=24, intf=rj_if)

        #i = nr - 1
        #j = 0
        #ri_if = info.get("r2r_if_name", i, j)
        #rj_if = info.get("r2r_if_name", i, j)
        #ri_ip = info.get("r2r_ip1", i, j)
        #rj_ip = info.get("r2r_ip2", i, j)
        #self.routers[i][0].setIP(ri_ip, prefixLen=24, intf=ri_if)
        #self.routers[j][0].setIP(rj_ip, prefixLen=24, intf=rj_if)

    def setup_macs(self):
        for i, (router, hosts) in enumerate(self.routers):
            for j, host in enumerate(hosts):
                hidx = i * len(hosts) + j
                h_mac = info.get("host_mac", hidx)
                h_if = info.get("host_if_name", hidx)
                host.cmd("ifconfig {} hw ether {}".format(h_if, h_mac))

                r_mac = info.get("router_mac", hidx, i)
                r_if = info.get("router_if_name", j)
                router.cmd("ifconfig {} hw ether {}".format(r_if, r_mac))

        nr = len(self.routers)
        for i in range(nr):
            for j in range(i + 1, nr):
                ri_mac = info.get("r2r_mac", i, j)
                rj_mac = info.get("r2r_mac", j, i)
                ri_if = info.get("r2r_if_name", i, j)
                rj_if = info.get("r2r_if_name", i, j)
                self.routers[i][0].cmd("ifconfig {} hw ether {}".format(ri_if,
                                                                    ri_mac))
                self.routers[j][0].cmd("ifconfig {} hw ether {}".format(rj_if,
                                                                    rj_mac))

    def disable_unneeded(self):
        def disable_ipv6(host):
            host.cmd('sysctl -w net.ipv6.conf.all.disable_ipv6=1')
            host.cmd('sysctl -w net.ipv6.conf.default.disable_ipv6=1')

        def disable_nic_checksum(host, iface):
            host.cmd('ethtool iface {} --offload rx off tx off'.format(iface))
            host.cmd('ethtool -K {} tx-checksum-ip-generic off'.format(iface))

        def disable_arp(host, iface):
            host.cmd("ip link set dev {} arp off".format(iface))

        for i, (router, hosts) in enumerate(self.routers):
            disable_ipv6(router)
            for j, host in enumerate(hosts):
                disable_ipv6(host)
                hidx = i * len(hosts) + j
                h_if = info.get("host_if_name", hidx)
                disable_nic_checksum(host, h_if)

            # we want complete control over these actions
            router.cmd('echo "0" > /proc/sys/net/ipv4/ip_forward')
            router.cmd('echo "1" > /proc/sys/net/ipv4/icmp_echo_ignore_all')
            if not static_arp():
                for (i, (router, hosts)) in enumerate(self.routers):
                    for j in range(len(hosts)):
                        hidx = i * len(hosts) + j
                        ifn = info.get("router_if_name", hidx)
                        disable_arp(router, ifn)

    def add_default_routes(self):
        for i, (router, hosts) in enumerate(self.routers):
            for j, host in enumerate(hosts):
                hidx = i * len(hosts) + j
                ip = info.get("router_ip", hidx)
                host.cmd("ip route add default via {}".format(ip))

    def add_hosts_entries(self):
        with open("/etc/hosts", "r") as fin:
            lines = fin.readlines()

        def not_a_comment(line):
            return len(line) > 0 and line[0] != "#"

        entries = set(filter(not_a_comment, lines))
        for i, (router, hosts) in enumerate(self.routers):
            for j, host in enumerate(hosts):
                for h in range(len(self.hosts)):
                    ip = info.get("host_ip", h + 1)
                    new_entry = "{} host{}\n".format(ip , h)

                    ok = 0
                    for e in entries:
                        if "host{}".format(h) in e and "local" not in e:
                            entries.remove(e)
                            entries.add(new_entry)
                            ok = 1
                            break

                    for e in entries:
                        if "h{}".format(h) in e and "local" not in e and "host" not in e:
                            entries.remove(e)
                            entries.add(new_entry)
                            break
                    
                    if ok == 0 and new_entry not in entries:
                        entries.add(new_entry)
                        lines.append(new_entry)

        fd, path = tempfile.mkstemp()
        try:
            with os.fdopen(fd, "w") as tmp:
                for i in entries:
                    tmp.writelines(i)
                #tmp.writelines(lines)

            shutil.copy(path, "/etc/hosts")
        finally:
            os.remove(path)

    def setup(self):
        self.disable_unneeded()
        self.setup_ifaces()
        self.setup_macs()
        self.add_hosts_entries()
        self.add_default_routes()


    # Starts all routers with the except of routers in list wo
    def start_routers(self, wo=[]):
        ifaces = ""
        for i in range(len(self.routers)):
            for j in range(i + 1, len(self.routers)):
                ifaces += "{} ".format(info.get("r2r_if_name", i, j))

        for i in range(self.n_hosts):
            ifaces += "{} ".format(info.get("router_if_name", i))

        for i, (router, _) in enumerate(self.routers):

            if i in wo:
                continue

            out = info.get("out_file", i)
            err = info.get("err_file", i)
            rtable = info.get("rtable", i)
            rname = "switch{}".format(i)

            #if int(router.cmd("ps -aux | grep {} | wc -l".format(rname))) == 1:
                #cmd = 'bash -c "exec -a {} ./switch {} > {} 2> {} &"'.format(rname, ifaces,
                 #                               out, err)
            cmd = 'bash -c "exec -a {} python3 switch.py {} $(ifconfig -a | grep -o \'^[^ :]*\' | grep -v \'lo\' | tr \'\n\' \' \') > {} 2> {} &"'.format(rname, i, out, err)
            print("[INFO] Starting {}".format(rname))
            router.cmd(cmd)
        time.sleep(4)

    def setup_capture(self, testname, log):
        nr = len(self.routers)
        for i, (router, hosts) in enumerate(self.routers):
            if_str = ""
            for j, _ in enumerate(hosts):
                hidx = i * len(hosts) + j
                router_if = info.get("router_if_name", j)
                if_str += f"-i {router_if} "

            for j in range(nr):
                if i == j:
                    continue

                f = min(i, j)
                s = max(i, j)
                ri_if = info.get("r2r_if_name", f, s)
                if_str += f"-i {ri_if} "

            pcap = f"router{i}.pcap"
            pcap_file = os.path.join(log, pcap)

            # tshark can only work if started from a folder owned by the
            # launching user, even if that is root (!!!)
            router.cmd(f"cd {log}")
            try:
                cmd = f"tshark -l {if_str} -w {pcap} &"
         
                router.cmd(cmd)
            finally:
                router.cmd(f"cd -")

    def teardown_capture(self, testname, log):
        for i, (router, _) in enumerate(self.routers):
            router.cmd("pkill tshark")

            # Make it world-readable to not bother students with chmod or
            # WS-as-root
            pcap = f"router{i}.pcap"
            pcap_file = os.path.join(log, pcap)
            old_mask = os.umask(0)
            try:
                os.chmod(pcap_file, 0o666)
            except FileNotFoundError as e:
                time.sleep(1)  # perhaps tshark didn't have enough time to
                               # write it
                os.chmod(pcap_file, 0o666)
            finally:
                os.umask(old_mask)
    
    def run_test(self, testname):
        # restart router if dead

        if self.i == 0:
            self.start_routers()

        self.i = 1

        log = os.path.join(info.LOGDIR, testname)
        Path(log).mkdir(parents=True, exist_ok=True)

        self.setup_capture(testname, log)

        test = tests.TESTS[testname]
        n_passive_hosts = len(self.hosts)
        for hp in range(n_passive_hosts):
            lout = os.path.join(log, info.get("output_file", hp))
            lerr = os.path.join(log, info.get("error_file", hp))
            cmd = "./checker/checker.py \
                    --passive \
                    --testname={} \
                    --host={} \
                    > {} \
                    2> {} &".format(testname, hp, lout, lerr)
            self.hosts[hp].cmd(cmd)

        time.sleep(2)
        cmd = "./checker/checker.py \
                --active \
                --testname={} \
                --host={} &".format(testname, test.host_s)
        self.hosts[test.host_s].cmd(cmd)

        time.sleep(info.TIMEOUT)
        self.teardown_capture(testname, log)
        time.sleep(info.TIMEOUT)

        results = {}
        for hp in range(len(self.hosts)):
            lout = os.path.join(log, info.get("output_file", hp))
            with open(lout, "r") as fin:
                results[hp] = fin.read().strip("\r\n")

        return results


def validate_test_results(results):
    passed = True
    for result in results.values():
        passed = passed and (result == "PASS")

    return passed


def should_skip(testname):
    if static_arp():
        return testname in {"router_arp_reply", "router_arp_request"}

    return False


def main(run_tests=False, run=None):
    topo = FullTopo(nr=info.N_ROUTERS, nh=info.N_HOSTSEACH)

    net = Mininet(topo, controller=None, link = Link)
    net.start()

    nm = FullNM(net, info.N_ROUTERS, info.N_HOSTSEACH)

    nm.setup()
    viz_cats = []
    points = {}

    if run_tests:
        total_points = 0
        print("{:=^85}\n".format(" Running tests "))
        for (testname, test) in tests.TESTS.items():
            if test.categories[0] not in viz_cats:
                print(">> Running tests for {}".format(test.categories[0]))
                print("")
                viz_cats.append(test.categories[0])
                points[test.categories[0]] = 0
                if test.categories[0] == '3. STP':
                    nm.start_routers([0,1,2])


            skipped = False

            if should_skip(testname):
                skipped = True
                passed = False
            else:
                results = nm.run_test(testname)
                passed = validate_test_results(results)
            str_status = "PASSED" if passed else "FAILED"
            if skipped:
                str_status = "SKIPPED"

            current_points = 0
            if not skipped and passed:
                for cat in test.categories:
                    current_points += tests.CATEGORY_POINTS[cat] / tests.CATEGORY_DICT[cat]
            else:
                current_points = -9999999

            points[test.categories[0]] += current_points
            
            print("{: >20} {:.>50} {: >8}".format(testname, "", str_status, round(0 if current_points < 0 else current_points)))
            if str_status != "SKIPPED":
                time.sleep(2)
        
        for k,v in points.items():
            if v > 0:
                total_points += v

        print(f"\nTOTAL: {round(total_points)}/100")
    elif run is not None:
        print("{:=^80}\n".format(f" Running test \"{run}\" "))
        results = nm.run_test(run)
        passed = validate_test_results(results)
    else:
        net.startTerms()
        signal.signal(signal.SIGINT, signal_handler)
        forever = threading.Event()
        forever.wait()

    net.stop()


if __name__ == "__main__":
    # Tell mininet to print useful information
    if len(sys.argv) > 1 and sys.argv[1] == "tests":
        main(run_tests=True)
    elif len(sys.argv) > 1 and sys.argv[1] == "run":
        assert(len(sys.argv) > 2), "Usage: python3 topo.py run <testname>"
        testname = sys.argv[2]
        assert(testname in tests.TESTS.keys()), "Unknown test name!"
        main(run=testname)
    else:
        setLogLevel("info")
        main()

