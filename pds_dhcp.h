#include "pds_utils.h"
using namespace std;

class DHCP_lease
{
	public:
		IP_address addr;
		MAC_address* MAC;
		unsigned long TOD;
		DHCP_lease(IP_address IP){addr = IP; MAC = NULL; TOD = 0;}
		~DHCP_lease(){if(MAC != NULL) delete MAC;}
};

class PDS_DHCP
{
	public:
		vector<DHCP_lease> pool;
		string interf;
		PDS_Raw_Socket& sock;
		IP_address server;
		IP_address gate;
		IP_address dns;
		string domain;
		unsigned long lease_time;
		static PDS_Full_Packet makeDiscoverPacket(MAC_address srcMAC);
		void get_own_address();
		PDS_DHCP(string interface, PDS_Raw_Socket& s, IP_address lower, IP_address upper, IP_address gateway, IP_address name, string d, unsigned long lease);
		void run();
		void offer(PDS_Full_Packet disc);
		void grant(PDS_Full_Packet req);
		void check_dead();
		void dump();
};

class Fake_Machine
{
	public:
		MAC_address MAC;
		IP_address IP;
		PDS_Raw_Socket* sock;
		unsigned long TOD;					// Time, when IP lease expires
		Fake_Machine(PDS_Raw_Socket* s);
		~Fake_Machine();
		bool is_dead();
		void emit_discover_packet();
		void accept_offer(PDS_Full_Packet off);
};