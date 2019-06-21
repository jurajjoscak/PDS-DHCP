all:
	g++ -std=c++11 -o pds-dhcpstarve pds-dhcpstarve.cpp pds_utils.cpp pds_dhcp.cpp
	g++ -std=c++11 -o pds-dhcprogue pds-dhcprogue.cpp pds_utils.cpp pds_dhcp.cpp

run:
	./pds-dhcpstarve