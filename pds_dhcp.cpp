#include "pds_dhcp.h"
using namespace std;

PDS_DHCP::PDS_DHCP(string interface, PDS_Raw_Socket& s, IP_address lower, IP_address upper, IP_address gateway, IP_address name, string d, unsigned long lease):
	sock(s)
{
	interf = interface;
	IP_address IP = lower;
	do
	{
		pool.push_back(DHCP_lease(IP));
		IP = IP.inc();
	}
	while(!(IP == upper.inc()));

	gate = gateway;
	dns = name;
	domain = d;
	lease_time = lease;
}

void PDS_DHCP::get_own_address()
{
	struct ifaddrs *ifap, *ifa;
	struct sockaddr_in *sa;
	char *addr;

	getifaddrs(&ifap);

	for(ifa = ifap; ifa; ifa = ifa->ifa_next)
	{
		if(ifa->ifa_addr->sa_family == AF_INET)
		{
			sa = (struct sockaddr_in*)ifa->ifa_addr;
			addr = inet_ntoa(sa->sin_addr);

			if(string(ifa->ifa_name) == interf)
			{
				server = IP_address(string(addr));
				break;
			}
			//cout << "NAME: " << ifa->ifa_name << "  ADDRESS: " << addr << endl;
		}
	}

	freeifaddrs(ifap);
}

void PDS_DHCP::offer(PDS_Full_Packet disc)
{
	disc.extract_eth_header();
	disc.extract_IP_header();
	disc.extract_UDP_header();

	if((disc.raw_data[11] & 0x01) == 1)		// Ignore packets from pds-dhcpstarve
		return;

	PDS_Full_Packet off = disc;


	off.raw_data[0] = 2;

	int lease_index = -1;
	for(int i = 0; i < pool.size(); i++)
	{
		if(pool[i].MAC == NULL)
		{
			lease_index = i;
			break;
		}
	}
	if(lease_index == -1)					// Ignore, if pool is exhausted
		return;

	pool[lease_index].MAC = new MAC_address(&off.raw_data[28]);
	pool[lease_index].TOD = time(NULL) + lease_time;

	off.raw_data[16] = pool[lease_index].addr.octets[0];		// Client IP
	off.raw_data[17] = pool[lease_index].addr.octets[1];
	off.raw_data[18] = pool[lease_index].addr.octets[2];
	off.raw_data[19] = pool[lease_index].addr.octets[3];
	
	off.raw_data[20] = server.octets[0];		// Server IP
	off.raw_data[21] = server.octets[1];
	off.raw_data[22] = server.octets[2];
	off.raw_data[23] = server.octets[3];

	off.raw_data.erase(off.raw_data.begin() + 240, off.raw_data.end());

	// OPTIONS
	// Message type: offer
	off.raw_data.push_back(53);
	off.raw_data.push_back(1);
	off.raw_data.push_back(2);

	// gateway
	off.raw_data.push_back(3);
	off.raw_data.push_back(4);
	off.raw_data.push_back(gate.octets[0]);
	off.raw_data.push_back(gate.octets[1]);
	off.raw_data.push_back(gate.octets[2]);
	off.raw_data.push_back(gate.octets[3]);

	// DNS
	off.raw_data.push_back(6);
	off.raw_data.push_back(4);
	off.raw_data.push_back(dns.octets[0]);
	off.raw_data.push_back(dns.octets[1]);
	off.raw_data.push_back(dns.octets[2]);
	off.raw_data.push_back(dns.octets[3]);

	// Domain
	off.raw_data.push_back(15);
	off.raw_data.push_back(domain.size());
	for(int i = 0; i < domain.size(); i++)
		off.raw_data.push_back(domain[i]);

	// Lease time
	off.raw_data.push_back(51);
	off.raw_data.push_back(4);
	off.raw_data.push_back((unsigned char)((lease_time >> 24) % 256));
	off.raw_data.push_back((unsigned char)((lease_time >> 16) % 256));
	off.raw_data.push_back((unsigned char)((lease_time >> 8) % 256));
	off.raw_data.push_back((unsigned char)(lease_time % 256));

	// END
	off.raw_data.push_back(255);

	for(int i = off.raw_data.size(); i <= 300; i++)
		off.raw_data.push_back(0);

	off.add_udp_header(67, 68);
	off.add_ip_header(server, pool[lease_index].addr);
	off.add_ether_header(MAC_address(sock.device.sll_addr), *(pool[lease_index].MAC));

	

	sock.send_data(off);
}

void PDS_DHCP::grant(PDS_Full_Packet req)
{
	req.extract_eth_header();
	req.extract_IP_header();
	req.extract_UDP_header();

	if((req.raw_data[11] & 0x01) == 1)		// Ignore packets from pds-dhcpstarve
		return;	

	MAC_address client_mac = MAC_address(&req.raw_data[28]);
	int crs = 240;
	while(crs < req.raw_data.size())
	{
		if(req.raw_data[crs] == 50)
		{
			crs += 2;
			break;
		}
		if(req.raw_data[crs] == 255)
			return;
		
		crs += req.raw_data[crs+1] + 2;
	}
	IP_address requested_IP = IP_address(&req.raw_data[crs]);


	// Look for requested address in pool
	int lease_index = -1;
	for(int i = 0; i < pool.size(); i++)
	{
		if(pool[i].addr == requested_IP)
		{
			lease_index = i;
		}
	}
	if(lease_index == -1)
		return;

	unsigned char granted;
	if(!(pool[lease_index].MAC == NULL) && !(*(pool[lease_index].MAC) == client_mac))
	{
		granted = 6;
	}
	else
	{
		granted = 5;
		if(pool[lease_index].MAC == NULL)
			pool[lease_index].MAC == new MAC_address(client_mac.octets);

		pool[lease_index].TOD = time(NULL) + lease_time;
	}

	PDS_Full_Packet ack = req;

	ack.raw_data[0] = 2;

	ack.raw_data[12] = pool[lease_index].addr.octets[0];		// Client IP
	ack.raw_data[13] = pool[lease_index].addr.octets[1];
	ack.raw_data[14] = pool[lease_index].addr.octets[2];
	ack.raw_data[15] = pool[lease_index].addr.octets[3];

	ack.raw_data[16] = pool[lease_index].addr.octets[0];		// Your IP
	ack.raw_data[17] = pool[lease_index].addr.octets[1];
	ack.raw_data[18] = pool[lease_index].addr.octets[2];
	ack.raw_data[19] = pool[lease_index].addr.octets[3];
	
	ack.raw_data[20] = server.octets[0];		// Server IP
	ack.raw_data[21] = server.octets[1];
	ack.raw_data[22] = server.octets[2];
	ack.raw_data[23] = server.octets[3];

	ack.raw_data.erase(ack.raw_data.begin() + 240, ack.raw_data.end());

	// OPTIONS
	// Message type: offer
	ack.raw_data.push_back(53);
	ack.raw_data.push_back(1);
	ack.raw_data.push_back(granted);

	// gateway
	ack.raw_data.push_back(3);
	ack.raw_data.push_back(4);
	ack.raw_data.push_back(gate.octets[0]);
	ack.raw_data.push_back(gate.octets[1]);
	ack.raw_data.push_back(gate.octets[2]);
	ack.raw_data.push_back(gate.octets[3]);

	// DNS
	ack.raw_data.push_back(6);
	ack.raw_data.push_back(4);
	ack.raw_data.push_back(dns.octets[0]);
	ack.raw_data.push_back(dns.octets[1]);
	ack.raw_data.push_back(dns.octets[2]);
	ack.raw_data.push_back(dns.octets[3]);

	// Domain
	ack.raw_data.push_back(15);
	ack.raw_data.push_back(domain.size());
	for(int i = 0; i < domain.size(); i++)
		ack.raw_data.push_back(domain[i]);

	// Lease time
	ack.raw_data.push_back(51);
	ack.raw_data.push_back(4);
	ack.raw_data.push_back((unsigned char)((lease_time >> 24) % 256));
	ack.raw_data.push_back((unsigned char)((lease_time >> 16) % 256));
	ack.raw_data.push_back((unsigned char)((lease_time >> 8) % 256));
	ack.raw_data.push_back((unsigned char)(lease_time % 256));

	// END
	ack.raw_data.push_back(255);

	for(int i = ack.raw_data.size(); i <= 300; i++)
		ack.raw_data.push_back(0);

	ack.add_udp_header(67, 68);
	ack.add_ip_header(server, pool[lease_index].addr);
	ack.add_ether_header(MAC_address(sock.device.sll_addr), *(pool[lease_index].MAC));

	sock.send_data(ack);
}

void PDS_DHCP::check_dead()
{
	unsigned long now = time(NULL);
	for(int i = 0; i < pool.size(); i++)
	{
		if((pool[i].TOD != 0) && (pool[i].TOD < now))
		{
			delete pool[i].MAC;
			pool[i].TOD = 0;
		}
	}
}

void PDS_DHCP::run()
{
	get_own_address();
	
	PDS_Full_Packet pak;
	while(true)
	{
		pak = sock.recieve_data();
		if(pak.raw_data.size() == 0)
			continue;

		DHCP_type what = pak.get_DHCP_type();
		switch(what)
		{
			case DHCP_DISCOVER:	offer(pak);
								break;
			case DHCP_REQUEST: 	grant(pak);
								break;
			case DHCP_OFFER: 	cout << "OFFER" << endl;
								break;
			case DHCP_NOT:		cout << "NOT" << endl;
								break;
			case DHCP_ACK:		cout << "ACK" << endl;
								break;
			case DHCP_OTHER:	cout << "OTHER" << endl;
								break;
		}
		check_dead();

	}
}

void PDS_DHCP::dump()
{
	cout << "POOL:\n";
	for(int i = 0; i < pool.size(); i++)
		cout << "\t" << pool[i].addr.dump() << "\n";

	cout << "GATE: " << gate.dump() << "\n";
	cout << "DNS: " << dns.dump() << "\n";
	cout << "DOMAIN: " << domain << "\n";
	cout << "TIME: " << lease_time << "\n";
}

PDS_Full_Packet PDS_DHCP::makeDiscoverPacket(MAC_address srcMAC)
{
	unsigned char msgType = 1;			// request
	unsigned char HWType = 1;			// ethernet
	unsigned char HWLen = 6;			// 6-byte MAC address
	unsigned char hops = 0;				// routers will set this
	unsigned long transID = 0;			// ???
	unsigned short secondsEl = 0;		// ???
	unsigned short bootpFlags = 1;		// nothing
	unsigned long clientIP = 0;
	unsigned long yourIP = 0;			// IP addresses
	unsigned long nextIP = 0;
	unsigned long relayIP = 0;
	
	unsigned char dstMAC[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	unsigned long DHCPCookie = 0x63825363;

	string myHostName = "example";



	vector<unsigned char> gd;
	gd.push_back(msgType);
	gd.push_back(HWType);
	gd.push_back(HWLen);
	gd.push_back(hops);

	gd.push_back((unsigned char)(transID >> 24) % 256);
	gd.push_back((unsigned char)(transID >> 16) % 256);
	gd.push_back((unsigned char)(transID >> 8) % 256);
	gd.push_back((unsigned char)transID % 256);

	gd.push_back((unsigned char)(secondsEl >> 8) % 256);
	gd.push_back((unsigned char)secondsEl % 256);

	gd.push_back((unsigned char)(bootpFlags >> 8) % 256);
	gd.push_back((unsigned char)bootpFlags % 256);

	gd.push_back((unsigned char)(clientIP >> 24) % 256);
	gd.push_back((unsigned char)(clientIP >> 16) % 256);
	gd.push_back((unsigned char)(clientIP >> 8) % 256);
	gd.push_back((unsigned char)clientIP % 256);

	gd.push_back((unsigned char)(yourIP >> 24) % 256);
	gd.push_back((unsigned char)(yourIP >> 16) % 256);
	gd.push_back((unsigned char)(yourIP >> 8) % 256);
	gd.push_back((unsigned char)yourIP % 256);

	gd.push_back((unsigned char)(nextIP >> 24) % 256);
	gd.push_back((unsigned char)(nextIP >> 16) % 256);
	gd.push_back((unsigned char)(nextIP >> 8) % 256);
	gd.push_back((unsigned char)nextIP % 256);

	gd.push_back((unsigned char)(relayIP >> 24) % 256);
	gd.push_back((unsigned char)(relayIP >> 16) % 256);
	gd.push_back((unsigned char)(relayIP >> 8) % 256);
	gd.push_back((unsigned char)relayIP % 256);

	for(int i = 0; i < HWLen; i++)
		gd.push_back(srcMAC.octets[i]);

	for(int i = HWLen; i < 16; i++)		// Padding source MAC address
		gd.push_back(0);

	for(int i = 0; i < 64; i++)			// No server name given
		gd.push_back(0);

	for(int i = 0; i < 128; i++)		// No boot file given
		gd.push_back(0);


	gd.push_back((unsigned char)(DHCPCookie >> 24) % 256);
	gd.push_back((unsigned char)(DHCPCookie >> 16) % 256);
	gd.push_back((unsigned char)(DHCPCookie >> 8) % 256);
	gd.push_back((unsigned char)DHCPCookie % 256);


	// OPTIONS:
	gd.push_back(53);
	gd.push_back(1);								// Type: Discover
	gd.push_back(1);

	gd.push_back(12);
	gd.push_back(myHostName.length());				// My host name
	for(int i = 0; i < myHostName.length(); i++)
		gd.push_back(myHostName[i]);

	// PARAMETER REQUEST LIST
	gd.push_back(55);
	gd.push_back(13);
	gd.push_back(1);
	gd.push_back(28);
	gd.push_back(2);
	gd.push_back(3);
	gd.push_back(15);
	gd.push_back(6);
	gd.push_back(119);
	gd.push_back(12);
	gd.push_back(44);
	gd.push_back(47);
	gd.push_back(26);
	gd.push_back(121);
	gd.push_back(42);
	
	// END
	gd.push_back(255);

	// PADDING:
	for(int i = gd.size(); i < 300; i++)
		gd.push_back(0);


	//MAC_address tk(srcMAC);
	MAC_address bk(dstMAC);

	PDS_Full_Packet pack(gd);
	pack.add_udp_header(68, 67);
	pack.add_ip_header(IP_address(string("0.0.0.0")), IP_address(string("255.255.255.255")));
	pack.add_ether_header(srcMAC, bk);

	return pack;
}

Fake_Machine::Fake_Machine(PDS_Raw_Socket* s)
{
	sock = s;
}

void Fake_Machine::emit_discover_packet()
{
	sock->send_data(PDS_DHCP::makeDiscoverPacket(MAC));
}

Fake_Machine::~Fake_Machine()
{}

bool Fake_Machine::is_dead()
{
	if(time(NULL) > TOD)
		return true;
	else
		return false;
}

///////////////////////////////////////
// Sends request for offered IP address
////////////////////////////////////////
void Fake_Machine::accept_offer(PDS_Full_Packet off)
{
	off.extract_eth_header();
	off.extract_IP_header();
	off.extract_UDP_header();

	PDS_Full_Packet request = PDS_DHCP::makeDiscoverPacket(MAC);

	vector<unsigned char> reth = request.extract_eth_header();
	vector<unsigned char> rip = request.extract_IP_header();
	vector<unsigned char> rudp = request.extract_UDP_header();

	request.raw_data[242] = 3;			// Message type: request


	IP.octets[0] = off.raw_data[16];	// Copy requested IP from offer
	IP.octets[1] = off.raw_data[17];
	IP.octets[2] = off.raw_data[18];
	IP.octets[3] = off.raw_data[19];
	IP.valid = true;
	// Requested IP option
	vector<unsigned char> option;
	option.push_back(50);
	option.push_back(4);
	option.push_back(off.raw_data[16]);
	option.push_back(off.raw_data[17]);
	option.push_back(off.raw_data[18]);
	option.push_back(off.raw_data[19]);

	request.raw_data.insert(request.raw_data.begin()+243, option.begin(), option.end());

	// Server identifier option
	option.erase(option.begin(), option.end());
	
	unsigned int crs = 240;
	unsigned char len = 4;
	while(crs < off.raw_data.size())
	{
		if(off.raw_data[crs] == 54)
		{
			len = off.raw_data[crs+1];
			option.push_back(54);
			option.push_back(len);
			for(int i = 0; i < len; i++)
			{
				option.push_back(off.raw_data[crs+2+i]);
			}
		}
		else if(off.raw_data[crs] == 51)
		{
			TOD = off.raw_data[crs+2];
			TOD = (TOD << 8) + off.raw_data[crs+3];
			TOD = (TOD << 8) + off.raw_data[crs+4];
			TOD = (TOD << 8) + off.raw_data[crs+5];
			TOD += time(NULL);
		}
		crs += off.raw_data[crs+1] + 2;
	}
	request.raw_data.insert(request.raw_data.begin()+243, option.begin(), option.end());
	for(int i = off.raw_data.size(); i <= 300; i++)
		off.raw_data.push_back(0);


	request.raw_data.insert(request.raw_data.begin(), rudp.begin(), rudp.end());
	request.raw_data.insert(request.raw_data.begin(), rip.begin(), rip.end());
	request.raw_data.insert(request.raw_data.begin(), reth.begin(), reth.end());


	sock->send_data(request);
}