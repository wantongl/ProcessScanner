import psutil
from socket import AF_INET, AF_INET6, SOCK_STREAM, SOCK_DGRAM
from ipfinder import IpFinder
from scapy.all import sniff


class ProcessSearch:
    """
    A class to manage, scan, and display information related to processes that is running on windows.

    Attributes:
    -----------
    __PROTOCOL: CONST Dict
        Use for making information display more readable by switching out AF_INET, AF_INET6, SOCK_STREAM, SOCK_DGRAM.

    __HEADER: CONST List
        Header data for organizing the columns and the displayed data easier to understand.

    ip_locator: IpFinder(path to GeoLite2-city.mmdb)
        Object instance of IpFinder that used for matching IP addresses to a physical locations (country).

    Methods:
    --------
    scan_process: List
        Return nested list with scan information of processes and network/socket connections,

    print_all(scan_process: list): None
        Print scan information in right-align separated columns.

    sort_info(scan_process: list, **kwargs): List
        Return nested list that was sorted by key= arg: 'name', 'pid', and 'country'.

    filter_by(scan_process: list, country_iso: set): List
        Return nested list with filtered data that matches country_iso.

    kill_pid(pid: int): None
        Kill process with matching pid if exist.

    """

    def __init__(self, pathtodb=None):
        self.__PROTOCOL = {
            (AF_INET, SOCK_STREAM): 'TCP',
            (AF_INET6, SOCK_STREAM): 'TCP6',
            (AF_INET, SOCK_DGRAM): 'UDP',
            (AF_INET6, SOCK_DGRAM): 'UDP6'
        }
        self.__HEADER = [
            'Name',
            'Pid',
            'Protocol',
            'Local address',
            'Local port',
            'Remote address',
            'Remote port',
            'Status',
            'Country',
            'City'
        ]
        if pathtodb is None:
            self.ip_locator = None
        else:
            self.ip_locator = IpFinder(pathtodb)

    def scan_process(self) -> list:
        scan_info = []
        proc_names = {proc.pid: proc.info['name'] for proc in psutil.process_iter(['name'])}
        # family, type, laddr=(ip,port), raddr=(ip,port), status, pid
        conns = psutil.net_connections(kind='inet')

        for conn in conns:
            # extracting data from conns
            name = str(proc_names[conn.pid])
            pid = str(conn.pid)
            protocol = str(self.__PROTOCOL[conn.family, conn.type])
            local_address = str(conn.laddr[0])
            local_port = str(conn.laddr[1])
            status = str(conn.status)

            if conn.raddr:  # check if remote IP address exists (UDP socket connections always return None)
                remote_address = str(conn.raddr[0])
                remote_port = str(conn.raddr[1])

                if self.ip_locator is not None:  # check if geoip2 object exists (path to database was provided)
                    country = str(self.ip_locator.find_ip_country(remote_address))
                    city = str(self.ip_locator.find_ip_city(remote_address))
                else:
                    country, city = ["-"] * 2
            else:
                remote_address, remote_port, country, city = ["-"] * 4

            # store data in scan_info for later use
            scan_info.append([
                name,
                pid,
                protocol,
                local_address,
                local_port,
                remote_address,
                remote_port,
                status,
                country,
                city
            ])

        return scan_info

    def print_all(self, info: list) -> None:
        print("{: >20} {: >10} {: >10} {: >40} {: >15} {: >40} {: >15} {: >15} {: >15} {: >15}".format(*self.__HEADER))
        for row in info:
            print("{: >20} {: >10} {: >10} {: >40} {: >15} {: >40} {: >15} {: >15} {: >15} {: >15}".format(*row))

    def sort_info(self, info: list, **kwargs):
        # kwargs: key={'name','pid','country'}
        if kwargs['key'] == 'name':
            return sorted(info[1:], key=lambda x: x[0])

        elif kwargs['key'] == 'pid':
            return sorted(info[1:], key=lambda x: int(x[1]))

        elif kwargs['key'] == 'country':
            return sorted(info[1:], key=lambda x: x[8])

    def filter_by(self, info: list, country_iso: set) -> list:
        return list(filter(lambda x: True if x[8] in country_iso else False, info[1:]))

    @classmethod
    def kill_pid(cls, pid):
        if psutil.pid_exists(pid):
            ps = psutil.Process(pid)
            ps.kill()
            print(f"Successfully kill {ps.name()} with pid: {pid}")
        else:
            print(f"Process with pid: {pid} don't exist")


class PacketSniffer:
    """
    A class to manage, scan, and display information related to processes that is running on windows.

    Attributes:
    -----------
    __PROTOCOL: CONST Dict
        Use for making information display more readable by switching out AF_INET, AF_INET6, SOCK_STREAM, SOCK_DGRAM.

    __HEADER: CONST List
        Header data for organizing the columns and the displayed data easier to understand.

    process_info: Dict
        Dict created by using __HEADER list elements as keys.
        The keys are assigned with values collected from process_packet(self, pkt) method later.

    country_iso_filter: Set(('country_iso_codes',))
        Provides parameter to input country_iso_code to filter out unnecessary packets.
        We only care about countries that is in country_iso_filter.

    shutdown: Boolean
        Default=0: Does not kill process with matching country in country_iso_filter.
                1: Kill process with matching country in country_iso_filter.

    Methods:
    --------
    process_packet(pkt: EthernetFrame from scapy.all.sniff): None
        Parameter:
            pkt: packet data captured by scapy.all.sniff method.

        Process pkt data and put it into dict(process_info).
        If packet's remote IP address matches a country_iso that is in country_iso_filter.
        Then search current processes for local IP address and port that matches to packet data.
        Finally display information related to Country, Protocol, Remote_IP, and Process_Name,
        and kill process if shutdown is true.

    sniffer(packet_count: int): scapy.all.packetlist
        Parameter:
            packet_count: decides how many packets to capture before sniff stops looping.

        Calls scapy.all.sniff with packet_count.
        Sniff captures packet data from network interfaces using npcap and pass it to process_packet


    """

    def __init__(self, pathtodb=None, country_iso_filter=set(), shutdown=0):
        self.__PROTOCOL = {
            (AF_INET, SOCK_STREAM): 'TCP',
            (AF_INET6, SOCK_STREAM): 'TCP6',
            (AF_INET, SOCK_DGRAM): 'UDP',
            (AF_INET6, SOCK_DGRAM): 'UDP6'
        }
        self.__HEADER = [
            'Country',
            'Protocol',
            'Remote_IP',
            'Process_Name',
            'Pid'
        ]

        self.process_info = dict.fromkeys(self.__HEADER, '-')
        self.country_iso_filter = country_iso_filter
        self.shutdown = shutdown

        if pathtodb is None:
            raise Exception("Path to geoip2 database not provided")
        else:
            self.ip_locator = IpFinder(pathtodb)

    def process_packet(self, pkt):
        # show and dissect UDP packets
        packet_info = {
            'IP_src': 'IP_ADDRESS_SOURCE',
            'IP_dst': 'IP_ADDRESS_DESTINATION',
            'sport': 'SOURCE_PORT',
            'dport': 'DESTINATION_PORT',
        }
        # IPv4
        if pkt.haslayer('IP'):
            packet_info['IP_src'] = str(pkt['IP'].src)
            packet_info['IP_dst'] = str(pkt['IP'].dst)

        # IPv6
        if pkt.haslayer('IPv6'):
            packet_info['IP_src'] = str(pkt['IPv6'].src)
            packet_info['IP_dst'] = str(pkt['IPv6'].dst)

        # TCP segment
        if pkt.haslayer('TCP'):
            packet_info['sport'] = str(pkt['TCP'].sport)
            packet_info['dport'] = str(pkt['TCP'].dport)

        # UDP segment
        if pkt.haslayer('UDP'):
            packet_info['sport'] = str(pkt['UDP'].sport)
            packet_info['dport'] = str(pkt['UDP'].dport)

        # Check country of IP Address
        country_iso = self.ip_locator.find_ip_country(packet_info['IP_dst'])
        self.process_info['Country'] = country_iso

        if self.process_info['Country'] == 'Not in database':
            print("IP address no match found, not in database")

        if country_iso in self.country_iso_filter:
            # Need further optimization:
            # Reason: O(n) searching through netconnections everytime to match packet's IP address.
            conns = psutil.net_connections(kind='inet')
            for conn in conns:
                if (packet_info['IP_src'] == str(conn.laddr[0])
                        and packet_info['sport'] == str(conn.laddr[1])
                    or ('0.0.0.0' == str(conn.laddr[0])
                        and packet_info['sport'] == str(conn.laddr[1]))):
                    self.process_info['Protocol'] = self.__PROTOCOL[(conn.family, conn.type)]
                    self.process_info['Remote_IP'] = f"{packet_info['IP_dst']}:{packet_info['dport']}"
                    proc = psutil.Process(conn.pid)
                    self.process_info['Pid'] = str(conn.pid)
                    self.process_info['Process_Name'] = proc.name()
                    break
            ###
            print("Found Match")
            print("{: >10} {: >10} {: >40} {: >30} {: >15}".format(*self.__HEADER))
            print("{: >10} {: >10} {: >40} {: >30} {: >15}".format(*self.process_info.values()))

            if self.shutdown:
                # Default=0:
                ProcessSearch.kill_pid(int(self.process_info['Pid']))
                return

    def sniffer(self, packet_count=1):
        # Call scapy.all.sniff that uses npcap to capture packet information from network interfaces.
        sniff(prn=self.process_packet, filter="udp or tcp", count=packet_count)


if __name__ == "__main__":
    # p = ProcessSearch() # can include 'GeoLite2-City.mmdb' as arg
    # result = p.scan_process()
    # result = p.filter_by(result, {"US", "CZ"})
    # result = p.sort_info(result, key='pid')
    # p.print_all(result)

    DB_PATH = r"path_to_database"
    p = PacketSniffer(DB_PATH, {'US',}, 0)
    p.sniffer(100)
