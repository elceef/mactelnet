all: mt

clean: dist-clean

dist-clean:
	rm -f mactelnet

mt:
	gcc -Wall mactelnet.c md5.c -o mactelnet -I/usr/local/include/libnet11 -L/usr/local/lib/libnet11 -lnet -lpcap
debug:
	gcc -Wall mactelnet.c md5.c -o mactelnet -I/usr/local/include/libnet11 -L/usr/local/lib/libnet11 -lnet -lpcap -D__DEBUG
