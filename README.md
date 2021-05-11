# ProcessScanner
<p>
  Scans processes to find their name, pid, and TCP/UDP connections (local IP address, and remote IP addresses).
  Then find the remote IP addresses' physical location (country and city). 
</p>

# Requirements
<p>
  psutil is use for getting process and network information.
</p>

>pip install psutil

<p>
  geoip2 is used to get the physical locations of IP addresses.
  You can use either the web api service or database to do look ups (this repo uses the database in ipfinder.py).
  There are other similar services to try if this one don't meet your requirements.
</p>

>pip install geoip2
>
# Limitations
<p>
  Having difficulty getting the UDP remote IP address because it's stateless and psutil can't seem to detect it using sockets.
  Plans to learn about Scapy to further improve the scanner.
</p>
