#include "pds_utils.h"
#include <bitset>

IP_address::IP_address(unsigned char *in)
{
	octets[0] = in[0];
	octets[1] = in[1];
	octets[2] = in[2];
	octets[3] = in[3];

	valid = true;
}

/////////////////////////////////
// Parse string style IP address
/////////////////////////////////
IP_address::IP_address(string in)
{
	string parsed;
	stringstream sinput(in);

	valid = true;
	int i = 0;
	while(getline(sinput, parsed, '.'))
	{
		unsigned int t = atoi((parsed + "1").data());
		if(t < 1 || t > 2551)
		{
			valid = false;
			break;
		}
		t = (t-1)/10;
		octets[i] = t;
		i++;
		if(i > 3)
			break;
	}
}

////////////////////////////////////
// Create uninitialized IP address
///////////////////////////////////
IP_address::IP_address()
{
	for(int i = 0; i < 4; i++)
		octets[i] = 0;

	valid = false;
}

///////////////////////////////////
// Compute IPv4 checksum from data
///////////////////////////////////
unsigned short IPv4_checksum(vector<unsigned char> data)
{
	unsigned short *val = (unsigned short*)data.data();
	unsigned long sum = 0;

	for(int i = 0; i < data.size(); i += 2)
	{
		sum += ((unsigned short)data[i] << 8) + data[i+1];
	}

	if(data.size()%2)
		sum += data.back();

	while(sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return (unsigned short)~sum;

}

/////////////////////////////////
// returns IP address as string
/////////////////////////////////
string IP_address::dump()
{
	string address("");

	if(valid)
	{
		address += to_string(octets[0]);
		address += ".";
		address += to_string(octets[1]);
		address += ".";
		address += to_string(octets[2]);
		address += ".";
		address += to_string(octets[3]);
	}
	else
		address = "<invalid address>";
	return address;
}

//////////////////////////////////////////
// Create socket, bind to interface and
// set read timeout to 1/2 second
////////////////////////////////////////////
PDS_Raw_Socket::PDS_Raw_Socket(string interface, bool blocking)
{
	descriptor = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(descriptor == -1)
	{
		valid = false;
		cerr << "Unable to open socket\n";
		return;
	}


	device.sll_ifindex = if_nametoindex(interface.data());
	if(device.sll_ifindex == 0)
	{
		cerr << "Index of interface " << interface << " was not found\n";
		valid = false;
		return;
	}

	struct ifreq mac;
	memset(&mac, 0, sizeof(struct ifreq));
	strncpy(mac.ifr_name, interface.data(), IFNAMSIZ-1);
	if(ioctl(descriptor, SIOCGIFHWADDR, &mac) < 0)
	{
		cerr << "Hardware address of interface " << interface << " was not found\n";
		valid = false;
		return;
	}

	device.sll_halen = ETH_ALEN;
	device.sll_addr[0] = mac.ifr_hwaddr.sa_data[0];
	device.sll_addr[1] = mac.ifr_hwaddr.sa_data[1];
	device.sll_addr[2] = mac.ifr_hwaddr.sa_data[2];
	device.sll_addr[3] = mac.ifr_hwaddr.sa_data[3];
	device.sll_addr[4] = mac.ifr_hwaddr.sa_data[4];
	device.sll_addr[5] = mac.ifr_hwaddr.sa_data[5];
	device.sll_addr[6] = mac.ifr_hwaddr.sa_data[6];
	device.sll_addr[7] = mac.ifr_hwaddr.sa_data[7];

	device.sll_family = AF_PACKET;
	device.sll_hatype = 0;
	device.sll_pkttype = 0;

	valid = true;

	if(!blocking)
	{
		struct timeval read_timeout;
		read_timeout.tv_sec = 0;
		read_timeout.tv_usec = 500000;

		setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &read_timeout, sizeof read_timeout);
	}
}

void PDS_Raw_Socket::reset(bool blocking)
{
	close(descriptor);
	descriptor = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if(!blocking)
	{
		struct timeval read_timeout;
		read_timeout.tv_sec = 0;
		read_timeout.tv_usec = 500000;

		setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &read_timeout, sizeof read_timeout);
	}
}

PDS_Raw_Socket::~PDS_Raw_Socket()
{
	close(descriptor);
}

///////////////////////////////////
// Send packet through socket
//////////////////////////////////
void PDS_Raw_Socket::send_data(PDS_Full_Packet pkt)
{
	int bytes_sent = sendto(descriptor, pkt.data(), pkt.size(), 0, (struct sockaddr*)&device, sizeof(device));

	if(bytes_sent < 0)
		perror("Failed to send packet");
}

///////////////////////////////////////////////////////
// Retrieve packet from socket.
// Returns empty packet, if reading timed out or failed
///////////////////////////////////////////////////////
PDS_Full_Packet PDS_Raw_Socket::recieve_data()
{
	unsigned char buf[2000] = {0};

	int bytes_recieved = recvfrom(descriptor, &buf, 2000, 0, NULL, NULL);

	if(bytes_recieved > 0)
		return	PDS_Full_Packet(vector<unsigned char>(buf, buf+bytes_recieved));
	else
		return PDS_Full_Packet();
}


PDS_Full_Packet::PDS_Full_Packet(vector<unsigned char> payload)
{
	raw_data = payload;
}

//////////////////////////////////////
// Remove ethernet header from packet
// and return it
///////////////////////////////////////
vector<unsigned char> PDS_Full_Packet::extract_eth_header()
{
	vector<unsigned char> rt;

	for(int i = 0; i < 14; i++)
		rt.push_back(raw_data[i]);

	raw_data.erase(raw_data.begin(), raw_data.begin() + 14);

	return rt;
}

//////////////////////////////////////
// Remove IP header from packet
// and return it
///////////////////////////////////////
vector<unsigned char> PDS_Full_Packet::extract_IP_header()
{
	vector<unsigned char> rt;

	unsigned int hdr_len = (raw_data[0] & 0x0f) * 4;

	if(hdr_len > raw_data.size())
		hdr_len = raw_data.size();

	for(int i = 0; i < hdr_len; i++)
		rt.push_back(raw_data[i]);

	raw_data.erase(raw_data.begin(), raw_data.begin() + hdr_len);

	return rt;
}

//////////////////////////////////////
// Remove UDP header from packet
// and return it
///////////////////////////////////////
vector<unsigned char> PDS_Full_Packet::extract_UDP_header()
{
	vector<unsigned char> rt;

	for(int i = 0; i < 8; i++)
		rt.push_back(raw_data[i]);

	raw_data.erase(raw_data.begin(), raw_data.begin() + 8);

	return rt;		
}

//////////////////////////////////////
// Return message type of DHCP packet
// or DHCP_NOT
//////////////////////////////////////
DHCP_type PDS_Full_Packet::get_DHCP_type()
{
	if(raw_data.size() < 300)
	{
		return DHCP_NOT;
	}

	vector<unsigned char> ether = this->extract_eth_header();
	if((ether[12] != 8) || (ether[13] != 0))							// NOT IP PACKET?
	{
		raw_data.insert(raw_data.begin(), ether.begin(), ether.end());
		return DHCP_NOT;
	}

	
	vector<unsigned char> IP = this->extract_IP_header();
	if(IP.size() < 20 || (IP[0] >> 4 != 4))								// NOT version 4?
	{
		raw_data.insert(raw_data.begin(), IP.begin(), IP.end());
		raw_data.insert(raw_data.begin(), ether.begin(), ether.end());
		return DHCP_NOT;
	}

	if(IP[9] != 17)														// NOT UDP?
	{
		raw_data.insert(raw_data.begin(), IP.begin(), IP.end());
		raw_data.insert(raw_data.begin(), ether.begin(), ether.end());
		return DHCP_NOT;
	}


	unsigned int chck = (IP[10] << 8) + IP[11];
	IP[10] = IP[11] = 0;
	if(chck != IPv4_checksum(IP))										// WRONG CHECKSUM?
	{
		IP[10] = (unsigned char)((chck >> 8) % 256);
		IP[11] = (unsigned char)chck % 256;
		raw_data.insert(raw_data.begin(), IP.begin(), IP.end());
		raw_data.insert(raw_data.begin(), ether.begin(), ether.end());
		return DHCP_NOT;
	}
	IP[10] = (unsigned char)((chck >> 8) % 256);
	IP[11] = (unsigned char)chck % 256;

	vector<unsigned char> UDP = this->extract_UDP_header();

	// DHCP control
	if(raw_data.size() < 243)											// Packet below minimal length?
	{
		raw_data.insert(raw_data.begin(), UDP.begin(), UDP.end());
		raw_data.insert(raw_data.begin(), IP.begin(), IP.end());
		raw_data.insert(raw_data.begin(), ether.begin(), ether.end());
		return DHCP_NOT;
	}
	
	if(raw_data[0] > 2)													// Packet is not request, nor reply?
	{
		raw_data.insert(raw_data.begin(), UDP.begin(), UDP.end());
		raw_data.insert(raw_data.begin(), IP.begin(), IP.end());
		raw_data.insert(raw_data.begin(), ether.begin(), ether.end());
		return DHCP_NOT;
	}


	if((raw_data[236] != 0x63) || (raw_data[237] != 0x82) || (raw_data[238] != 0x53) || (raw_data[239] != 0x63)) // DHCP magic cookie is wrong?
	{
		raw_data.insert(raw_data.begin(), UDP.begin(), UDP.end());
		raw_data.insert(raw_data.begin(), IP.begin(), IP.end());
		raw_data.insert(raw_data.begin(), ether.begin(), ether.end());
		return DHCP_NOT;
	}

	DHCP_type ret;
	int crs = 240;
	while(crs < raw_data.size())
	{
		if(raw_data[crs] == 53)					// Look for message type option
		{
			switch(raw_data[crs+2])
			{
				case 1: ret = DHCP_DISCOVER;
						break;
				case 2: ret = DHCP_OFFER;
						break;
				case 3:	ret = DHCP_REQUEST;
						break;
				case 5:
				case 6: ret = DHCP_ACK;
						break;
				default: 	ret = DHCP_OTHER;
							break;
			}
			raw_data.insert(raw_data.begin(), UDP.begin(), UDP.end());
			raw_data.insert(raw_data.begin(), IP.begin(), IP.end());
			raw_data.insert(raw_data.begin(), ether.begin(), ether.end());
			return ret;
		}

		crs += raw_data[crs+1] + 2;
	}

	raw_data.insert(raw_data.begin(), UDP.begin(), UDP.end());
	raw_data.insert(raw_data.begin(), IP.begin(), IP.end());
	raw_data.insert(raw_data.begin(), ether.begin(), ether.end());
	return DHCP_NOT;
}

///////////////////////////////////////////
// Adds ethernet header with specified MACs
// to this packet
//////////////////////////////////////////
void PDS_Full_Packet::add_ether_header(MAC_address src, MAC_address dst)
{
	vector<unsigned char> ether_header;
	ether_header.push_back(dst.octets[0]);
	ether_header.push_back(dst.octets[1]);
	ether_header.push_back(dst.octets[2]);	// destination MAC address
	ether_header.push_back(dst.octets[3]);
	ether_header.push_back(dst.octets[4]);
	ether_header.push_back(dst.octets[5]);

	ether_header.push_back(src.octets[0]);
	ether_header.push_back(src.octets[1]);
	ether_header.push_back(src.octets[2]);	// Source MAC address
	ether_header.push_back(src.octets[3]);
	ether_header.push_back(src.octets[4]);
	ether_header.push_back(src.octets[5]);
	
	/*ether_header.push_back((unsigned char)raw_data.size() / 256);
	ether_header.push_back((unsigned char)raw_data.size() % 256);*/

	ether_header.push_back(0x08);  // Expecting IPv4 protocol on next layer
	ether_header.push_back(0x00);

	raw_data.insert(raw_data.begin(), ether_header.begin(), ether_header.end());
}

///////////////////////////////////////////
// Adds ethernet header with hardcoded MACs
// to this packet (only for debugging)
//////////////////////////////////////////
void PDS_Full_Packet::add_ether_header()
{
	vector<unsigned char> ether_header;
	ether_header.push_back(0x08);
	ether_header.push_back(0x00);
	ether_header.push_back(0x27);	// destination MAC address
	ether_header.push_back(0xC5);
	ether_header.push_back(0xD7);
	ether_header.push_back(0xCC);

	ether_header.push_back(0x00);
	ether_header.push_back(0x27);
	ether_header.push_back(0xC5);	// Source MAC address
	ether_header.push_back(0xD7);
	ether_header.push_back(0xCC);
	ether_header.push_back(0x08);
	
	/*ether_header.push_back((unsigned char)raw_data.size() / 256);
	ether_header.push_back((unsigned char)raw_data.size() % 256);*/

	ether_header.push_back(0x08);  // Expecting IPv4 protocol on next layer
	ether_header.push_back(0x00);

	raw_data.insert(raw_data.begin(), ether_header.begin(), ether_header.end());
}

///////////////////////////////////////////
// Adds IP header with specified IPs
// to this packet
//////////////////////////////////////////
void PDS_Full_Packet::add_ip_header(IP_address src, IP_address dst)
{
	unsigned char version = 4; 									// IPv4 - always 4
	unsigned char IHL = 5;										// IP header length - probably 5 (20 bytes)
	unsigned char DSCP = 4;									// diferrentiated services - 16
	unsigned char ECN = 0;										// explicit congestion notification - 0
	unsigned short total_length = raw_data.size() + IHL*4;		// total length including header
	unsigned short identification = 0;							// fragment identification - 0 if not fragmented
	unsigned char flags = 0;									// reserved, dont fragment, more fragments - 0
	unsigned short f_offset = 0;								// fragment offset - 0 if not fragmented
	unsigned char TTL = 128;									// time to live - 128 should be enough
	unsigned char protocol = 17;								// transport porotocol - prolly UDP - 17
	unsigned short chcksum	= 0;								// checksum - IP header only - 0 before calculation


	vector<unsigned char> IP_header;
	IP_header.push_back((version << 4) + IHL);
	IP_header.push_back((DSCP << 2) + ECN);
	IP_header.push_back((unsigned char)(total_length >> 8) % 255);
	IP_header.push_back((unsigned char)total_length % 256);
	IP_header.push_back((unsigned char)(identification >> 8) % 255);
	IP_header.push_back((unsigned char)identification % 256);
	IP_header.push_back((flags << 5) + (unsigned char)(f_offset >> 8) % 255);
	IP_header.push_back((unsigned char)f_offset % 256);
	IP_header.push_back(TTL);
	IP_header.push_back(protocol);
	IP_header.push_back((unsigned char)(chcksum >> 8) % 255);
	IP_header.push_back((unsigned char)chcksum % 256);

	IP_header.push_back(src.octets[0]);
	IP_header.push_back(src.octets[1]);
	IP_header.push_back(src.octets[2]);
	IP_header.push_back(src.octets[3]);

	IP_header.push_back(dst.octets[0]);
	IP_header.push_back(dst.octets[1]);
	IP_header.push_back(dst.octets[2]);
	IP_header.push_back(dst.octets[3]);	

	// NO OPTIONS

	chcksum = IPv4_checksum(IP_header);
	IP_header[10] = chcksum >> 8;
	IP_header[11] = chcksum % 256;

	 

	raw_data.insert(raw_data.begin(), IP_header.begin(), IP_header.end());
}

///////////////////////////////////////////
// Adds UDP header with specified ports
// to this packet
//////////////////////////////////////////
void PDS_Full_Packet::add_udp_header(unsigned short src, unsigned short dst)
{
	vector<unsigned char> UDP_header;

	UDP_header.push_back(src >> 8);
	UDP_header.push_back(src % 256);
	UDP_header.push_back(dst >> 8);
	UDP_header.push_back(dst % 256);

	unsigned short len = raw_data.size() + 8;
	UDP_header.push_back(len >> 8);
	UDP_header.push_back(len % 256);

	UDP_header.push_back(0);				// Udp checksum is optional, do not bother
	UDP_header.push_back(0);	

	raw_data.insert(raw_data.begin(), UDP_header.begin(), UDP_header.end());

}


MAC_address::MAC_address(unsigned char* in)
{
	octets[0] = in[0];
	octets[1] = in[1];
	octets[2] = in[2];
	octets[3] = in[3];
	octets[4] = in[4];
	octets[5] = in[5];

	valid = true;
}

/////////////////////////////////
// Constructor with no arguments
// creates random MAC address
/////////////////////////////////
MAC_address::MAC_address()
{
	octets[0] = rand() % 256;
	octets[1] = rand() % 256;
	octets[2] = rand() % 256;
	octets[3] = rand() % 256;
	octets[4] = rand() % 256;
	octets[5] = rand() % 256;

	octets[0] = octets[0] & (unsigned char)254;	// Should not be a group address

	valid = true;	
}

////////////////////////////////////
// Returns MAC address as a string
///////////////////////////////////
string MAC_address::dump()
{
	stringstream address;

	if(valid)
	{
		address << setfill('0') << setw(2) << hex << octets[0] << ":";
		address << setfill('0') << setw(2) << hex << octets[1] << ":";
		address << setfill('0') << setw(2) << hex << octets[2] << ":";
		address << setfill('0') << setw(2) << hex << octets[3] << ":";
		address << setfill('0') << setw(2) << hex << octets[4] << ":";
		address << setfill('0') << setw(2) << hex << octets[5];
	}
	else
		address << "<invalid address>";
	return address.str();
}