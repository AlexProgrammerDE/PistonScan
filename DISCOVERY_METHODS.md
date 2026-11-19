# Discovery methods

PistonScan sends ICMP echo requests before it starts discovery for a host. A host that replies gets a latency summary. The collector then runs its name lookups, service probes, SMB discovery, and MAC lookup in parallel.

| Method | What PistonScan records |
| --- | --- |
| DNS | Reverse lookup through the host operating system |
| mDNS | Host and instance names, advertised service types, and selected TXT fields |
| LLMNR | Names returned by a reverse PTR query |
| NetBIOS | Workstation and server names from a node status reply |
| SMB | Computer and domain names from workstation or server information |
| TCP | Common services, short banners, and TLS certificate details on selected ports |
| UDP | Replies from common services, including DNS, SSDP, and SNMP |
| ARP | MAC address from the local neighbor cache, with an offline vendor lookup |
| AirPlay | Device metadata from the HTTP information endpoint on TCP port 7000 |

Discovery results feed the device name, OS estimate, insight score, and source list. The scan manager streams each result to the desktop window. See [PROTOCOLS.md](PROTOCOLS.md) for protocol details.
