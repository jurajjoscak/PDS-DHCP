#include <iostream>
#include <string>
#include <sstream>
#include <cstdlib>
#include <ctime>
#include <cstdio>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <cstring>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <iomanip>
#include <ifaddrs.h>
using namespace std;

enum DHCP_type
{	DHCP_NOT,
	DHCP_DISCOVER,
	DHCP_OFFER,
	DHCP_REQUEST,
	DHCP_ACK,
	DHCP_OTHER
};

class IP_address
{
	public:
		bool valid;
		unsigned char octets[4];
		IP_address(unsigned char *in);
		IP_address(string in);
		IP_address();
		string dump();
		bool operator<(const IP_address& b)
		{
			for(int i = 0; i < 4; i++)
			{
				if(b.octets[i] > octets[i])
					return true;
			}
			return false;
		}
		bool operator==(const IP_address& b)
		{
			for(int i = 0; i < 4; i++)
			{
				if(b.octets[i] != octets[i])
					return false;
			}
			return true;
		}
		IP_address inc()
		{
			IP_address r(octets);
			r.octets[3] += 1;
			if(r.octets[3] == 0)
				r.octets[2] += 1;
			else
				return r;

			if(r.octets[2] == 0)
				r.octets[1] += 1;
			else
				return r;

			if(r.octets[1] == 0)
				r.octets[0] += 1;
				
			return r;
		}
};

class MAC_address
{
	public:
		bool valid;
		unsigned char octets[6];
		MAC_address(unsigned char *in);
		MAC_address();
		string dump();
		bool operator==(const MAC_address& b)
		{
			for(int i = 0; i < 6; i++)
			{
				if(b.octets[i] != octets[i])
					return false;
			}
			return true;
		}
};

//////////////////////////////////////////
// Full_packet can be sent through socket
//////////////////////////////////////////
class PDS_Full_Packet
{
	public:
		vector<unsigned char> raw_data;					// Actual octets in packet
		PDS_Full_Packet(vector<unsigned char> payload);
		PDS_Full_Packet(){}
		void add_ether_header(MAC_address src, MAC_address dest);	// Adds ethernet header with specified MACs to this packet
		void add_ether_header();									// hardcoded MACs for debugging purposes
		void add_ip_header(IP_address src, IP_address dst);				// Adds IP header with specified IPs to this packet
		void add_udp_header(unsigned short src, unsigned short dst);	// Adds UDP header with specified ports to this packet
		unsigned int size(){return raw_data.size();}
		unsigned char* data(){return raw_data.data();}
		vector<unsigned char> extract_eth_header();
		vector<unsigned char> extract_IP_header();			// Deletes individual headers from packet and returns them
		vector<unsigned char> extract_UDP_header();
		DHCP_type get_DHCP_type();							// Returns DHCP message type, or DHCP_NOT
};


//////////////////////////////////////////
// Raw socket bound directly to interface
// Can send and recieve PDS_Full_Packet
/////////////////////////////////////////
class PDS_Raw_Socket
{
	public:
		int descriptor;
		bool valid;
		struct sockaddr_ll device;
		PDS_Raw_Socket(string interface, bool blocking);
		PDS_Raw_Socket(){}
		void send_data(PDS_Full_Packet pkt);	// Sends packet
		PDS_Full_Packet recieve_data();			// Recieves packet
		~PDS_Raw_Socket();
		void reset(bool blocking);
};