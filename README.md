# ProcessScanner
<p>
  Scans processes to find their name, pid, and TCP/UDP connections (local IP address, and remote IP addresses).
  Then find the remote IP addresses' physical location (country and city). 
</p>

# PacketSniffer
<p>
  Read packet information that is being send over network interfaces to understand what countries are window proccess
  interacting with in the background. <br>
  Scapy to sniff packet, geoip2 to find physical location, and psutil to find process sending the packet.
</p>


# Requirements
<p>
  Psutil is use for getting process and network information.
</p>

>pip install psutil

<p>
  Geoip2 is used to get the physical locations of IP addresses.
  You can use either the web api service or database to do look ups (this repo uses the database in ipfinder.py).
  There are other similar services to try if this one don't meet your requirements.
</p>

>pip install geoip2

<p>
  Packet Sniffer uses scapy to function. It will read network packets that are being sent in network interfaces.
  Then dissect the packet information to find out where the packets are going in order to decide whether processes are suspicious or not.
</p>

>  pip install --pre scapy\[complete\]

> Scapy needs additional Platform-specific instructions best to follow:
> 
> https://scapy.readthedocs.io/en/latest/installation.html

# Limitations
<p>
  Having difficulty getting the UDP remote IP address because it's stateless and psutil can't seem to detect it using sockets.
  
  Packet Sniffer functions and is doing what it's suppose to do, but there are still room for optimization.
  
  TODO: Find a better method to detect what processes are doing and sending over the network. Ideally substitude psutil package with something better.
</p>
