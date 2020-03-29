CC=gcc

# FreeBSD
#CC=gcc48

# Standard build with pcap installed on the system
CFLAGS = -Wall -W -O2 -std=gnu99

# Standard build
LDFLAGS = -lpcap

# Build for Mac OS X
#CFLAGS = -Wall -W -O2 -framework CoreFoundation

# Build for Mac OS X 10.10 and later
#CFLAGS = -Wall -W -O2 -framework CoreFoundation -DCFPROPERTYLISTCREATEWITHSTREAM 

# Build for architectures that require memory alignment, such as Sparc
#CFLAGS = -Wall -W -O2 -std=gnu99 -DEMULATE_UNALIGNED

# Build for Solaris
#LDFLAGS = -lsocket -lnsl -lpcap

cdpr: cdpr.c cdps.c os_version_info.c cdp.c cdp.h cdpr.h cdps.h lldp.c
	$(CC) $(CFLAGS) cdpr.c cdps.c cdp.c os_version_info.c lldp.c $(LDFLAGS) -o cdpr

clean:
	rm -f cdpr

