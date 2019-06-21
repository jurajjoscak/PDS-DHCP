#include <iostream>
#include <unistd.h>
#include <cstdlib>
#include <csignal>
#include "pds_dhcp.h"
using namespace std;

void wrong_input()
{
	cout << "Wrong input arguments!\n";
	exit(1);
}

void sigint_handler(int signal)
{
	exit(0);
}

int main(int argc, char** argv)
{
	string interface_name = "";
	string pool = "";
	string gateway = "";
	string dns_server = "";
	string domain = "";
	unsigned long lease_time = 0; 


	int c;
	while((c = getopt(argc, argv, "i:p:g:n:d:l:")) != -1)
	{
		switch(c)
		{
			case 'i':
				interface_name = optarg;
				break;
			case 'p':
				pool = optarg;
				break;
			case 'g':
				gateway = optarg;
				break;
			case 'n':
				dns_server = optarg;
				break;
			case 'd':
				domain = optarg;
				break;
			case 'l':
				lease_time = atoi(optarg);
				break;
			default:
				wrong_input();
		}
	}
	if(interface_name == "")
		wrong_input();
	

	string parsed;
	stringstream sinput(pool);
	IP_address pool_lower;
	if(getline(sinput, parsed, '-'))
		pool_lower = IP_address(parsed);

	
	IP_address pool_upper;
	if(getline(sinput, parsed, '-'))
		pool_upper = IP_address(parsed);

	if(!pool_upper.valid || !pool_lower.valid)
		wrong_input();
	if(pool_upper < pool_lower)
		wrong_input();
	

	IP_address gateway_IP(gateway);
	if(!gateway_IP.valid)
		wrong_input();
	IP_address dns_IP(dns_server);
	if(!dns_IP.valid)
		wrong_input();
	if(domain == "")
		wrong_input();
	if(lease_time < 1)
		wrong_input();



	PDS_Raw_Socket mysock(interface_name, false);


	PDS_DHCP server(interface_name, mysock, pool_lower, pool_upper, gateway_IP, dns_IP, domain, lease_time);


	signal(SIGINT, sigint_handler);

	server.run();

	return 0;
}