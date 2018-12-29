all: hw3.c hw3.h
	gcc  hw3.c -lpcap -o hw3
clean:
	rm hw3
	
