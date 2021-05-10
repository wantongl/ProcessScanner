import psutil
from socket import AF_INET, AF_INET6, SOCK_STREAM, SOCK_DGRAM
from ipfinder import IpFinder


class ProcessSearch:
    """
    A class to manage, scan, and kill processes

    Attributes:
    -----------
    ip_locator: IpFinder(path to GeoLite2-city.mmdb)
        object instance of IpFinder class use for tracking ip address to get physical locations

    protocol: CONST Dict
        use for displaying and filtering tcp/udp information

    header: CONST List
        header of the display columns

    Methods:
    --------
    scan_process: list
        scan and show information related to processes and network/socket connections.

    print_all: None
        print scan information in right-align separated columns.

    sort_info: list
        sorts scanned information by name, pid, country

    filter_by: list
        filters scanned information by countries.

    kill_pid: None
        kill process with matching pid if exist.

    """

    def __init__(self, pathtodb=None):
        self.__PROTOCOL = {
            (AF_INET, SOCK_STREAM): 'TCP',
            (AF_INET6, SOCK_STREAM): 'TCP6',
            (AF_INET, SOCK_DGRAM): 'UDP',
            (AF_INET6, SOCK_DGRAM): 'UDP6'
        }
        self.__HEADER = [[
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
        ]]
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
            name = str(proc_names[conn.pid])
            pid = str(conn.pid)
            protocol = str(self.__PROTOCOL[conn.family, conn.type])
            local_address = str(conn.laddr[0])
            local_port = str(conn.laddr[1])
            status = str(conn.status)

            if conn.raddr:  # in case when remote address don't exist
                remote_address = str(conn.raddr[0])
                remote_port = str(conn.raddr[1])
                if self.ip_locator is not None:
                    country = str(self.ip_locator.find_ip_country(remote_address))
                    city = str(self.ip_locator.find_ip_city(remote_address))
                else:
                    country, city = ["-"] * 2
            else:
                remote_address, remote_port, country, city = ["-"] * 4

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
        print("{: >20} {: >10} {: >10} {: >40} {: >15} {: >40} {: >15} {: >15} {: >15} {: >15}".format(*self.__HEADER[0]))
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

    def kill_pid(self, pid):
        if psutil.pid_exists(pid):
            ps = psutil.Process(pid)
            ps.kill()
            print(f"Successfully kill {ps.name()} with pid: {pid}")
        else:
            print(f"Process with pid: {pid} don't exist")


if __name__ == "__main__":
    p = ProcessSearch() # can include 'GeoLite2-City.mmdb' as arg
    result = p.scan_process()
    # result = p.filter_by(result, {"US", "CZ"})
    # result = p.sort_info(result, key='pid')
    p.print_all(result)
