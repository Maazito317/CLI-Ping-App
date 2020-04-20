# CLI-Ping-App
[main-ping.c](https://github.com/Maazito317/CLI-Ping-App/blob/master/main-ping.c) is a command line application which allows the user to ping a hostname or IP address, much like the command line ping.

## Summary

 - Build: using gcc
 - Execution: sudo ./main-ping <hostname_OR_IP> 
 - Performs DNS lookup on the hostname and returns the IP
 - Opens RAW socket connection with ICMP protocol
 - Uses the send_ping function to send continuous echo messages to hostname
 - Return ping statistics upon receiving interrupt

## Solution

My program accepts a host name or an IP address as input. It first performs a dns lookup on the input using gethostbyname(). This returns information about the host, allowing the extraction of IP address and population of the sockaddr_in struct used for the address being connected to.
Following this, I set up a RAW socket connection with ICMP protocol. 
The send_ping function then sets socket options for TTL and receiving. I then create a while loop that runs until a user interrupt is received. In this loop, I create the header and the message and send the packet over the connection. Upon receiving the message, I calculate the round trip time and print out the message count, ttl, and rtt.
Upon receiving interrupt, I print out the statistics: no of packets sent, packets received, % loss, and total time.

## Output
'''
Resolving DNS..

Trying to connect to 'google.com' IP: 172.217.27.206

Socket file descriptor 3 received

Socket set to TTL..
64 bytes from (h: google.com) (172.217.27.206) msg_seq=1 ttl=64 rtt = 57.320584 ms.

64 bytes from (h: google.com) (172.217.27.206) msg_seq=2 ttl=64 rtt = 58.666775 ms.

64 bytes from (h: google.com) (172.217.27.206) msg_seq=3 ttl=64 rtt = 58.081148 ms.

64 bytes from (h: google.com) (172.217.27.206) msg_seq=4 ttl=64 rtt = 58.700630 ms.

64 bytes from (h: google.com) (172.217.27.206) msg_seq=5 ttl=64 rtt = 58.281802 ms.

64 bytes from (h: google.com) (172.217.27.206) msg_seq=6 ttl=64 rtt = 58.360916 ms.

===172.217.27.206 ping statistics===

6 packets sent, 6 packets received, 0.000000 percent packet loss. Total time: 6295.187804 ms.

