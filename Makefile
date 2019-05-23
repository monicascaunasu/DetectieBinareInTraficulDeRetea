all: 
	gcc -Wall -ggdb -o detector live_payloadtype.c -lpcap 

clean: 
	rm detector
