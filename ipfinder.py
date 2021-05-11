import geoip2.database


class IpFinder:
    """
    A class to manage and extract information related to IP addresses in GeoLite2-City.mmdb database

    Attributes:
    -----------
    city_reader: geoip2.database.Reader
        reader handle of GeoLite2-City.mmdb

    Methods:
    --------
    find_ip_country(ipaddr: str(IP ADDRESS))
        return ip address' associated country iso code

    find_ip_city(ipaddr: str(IP ADDRESS))
        return ip address' associated city name
    """

    def __init__(self, pathtodb: str = None) -> None:
        self.city_reader = pathtodb

        if self.city_reader is not None:
            try:
                self.city_reader = geoip2.database.Reader(self.city_reader)
            except:
                raise

    def find_ip_country(self, ipaddr: str) -> str:
        if self.city_reader is not None:
            try:
                response = self.city_reader.city(ipaddr)
            except geoip2.errors.AddressNotFoundError:
                return "Not in database"

            return response.country.iso_code
        else:
            print("Database not loaded into reader")

    def find_ip_city(self, ipaddr: str) -> str:
        if self.city_reader is not None:
            try:
                response = self.city_reader.city(ipaddr)
            except geoip2.errors.AddressNotFoundError:
                return "Not in database"

            return response.city.name
        else:
            print("Database not loaded into reader")

    def __del__(self):
        if isinstance(self.city_reader, geoip2.database.Reader):
            self.city_reader.close()
