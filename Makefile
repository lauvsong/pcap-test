all: pcap-test

pcap-test: main.o my_tools.o
	g++ -g -o pcap_test main.o my_tools.o -lpcap
	
main.o:
	g++ -g -c -o main.o main.cpp
	
my_tools.o:
	g++ -g -c -o my_tools.o my_tools.cpp

clean:
	rm -f pcap-test
