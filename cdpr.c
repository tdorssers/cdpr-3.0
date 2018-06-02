/*
* cdpr - Cisco Discovery Protocol Reporter
* Copyright (c) 2002-2010 MonkeyMental.com
* Copyright (c) 2015 Tim Dorssers
*
* This program will show you which Cisco device your machine is
* connected to based on CDP packets received.
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License
* as published by the Free Software Foundation; either version 2
* of the License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*
* Version History:
*
* 3.0.1 Removed the functionality to report CDP data back to a centralized server
*       Removed the ability to read files
*       Added all known TLVs and CDP capabilities
*       Added more TLV decoding functionality to the print_cdp_packet routine
*       Added CDP send module to send a VLAN request to trigger advertisements
*       Added multiple interface support
*       Added friendly interface name support under Win32
* 3.0.2 Added IPv6 support to the CDP send module
* 3.0.3 Added LLDP reporting support
*       Added LLDP to send module to trigger advertisements
*/

#ifdef _MSC_VER
/*
* we do not want the warnings about the old deprecated and unsecure CRT functions
* since this program can be compiled under *nix as well
*/
#define _CRT_SECURE_NO_WARNINGS
#endif
#include <stdlib.h>
#include <string.h>
#include <time.h>
#if defined(__APPLE_CC__) || defined(__APPLE__)
#include <net/bpf.h>
#endif
#ifdef WIN32
#include "capture_win_ifnames.h"
#include "xgetopt.h"
#include <conio.h>
#include "capture_wpcap_packet.h"
#else
#include <unistd.h>
#include <termios.h>
#include <sys/ioctl.h>
#if defined(__sun) && defined(__SVR4)
#include <sys/filio.h>
#endif
#endif
#include "cdpr.h"
#include "cdps.h"
#include "cdp.h"
#include "lldp.h"

int
usage(void)
{
	puts("");
	puts("-a: LLDP 802.1AB only mode");
	puts("-o: CDP only mode");
	puts("-c: Continuous capture mode; does not stop upon first reception"); 
	puts("-s: Silent mode; do not send trigger packet");
	puts("-i: Interactive mode; lets user pick a device to listen on");
	puts("-l: Lists devices");
	puts("-d: Specify device to use (eth0, hme0, etc.)");
	puts("-h: Print this usage");
	puts("-t: Time in seconds to abort waiting for packets (default is 300)");
	puts("-v[vv]: Set verbose mode");
	exit(0);
}

int
list_interfaces(void)
{
	pcap_if_t *d;
	pcap_if_t *alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];
	int i = 0;

	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	printf("\nAvailable devices:\n\n");
	for (d = alldevs; d; d = d->next)
	{
#ifdef WIN32
		printf("%d. %s [%s]", ++i, d->name, get_windows_interface_friendly_name(d->name));
#else
		printf("%d. %s", ++i, d->name);
#endif
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure pcap is installed.\n");
		return -1;
	}

	/* Free the device list */
	pcap_freealldevs(alldevs);
	return 0;
}

void advance_cursor(void) {
	static int pos = 0;
	char cursor[4] = { '/','-','\\','|' };
	printf("%c\b", cursor[pos]);
	fflush(stdout);
	pos = (pos + 1) % 4;
}

#ifndef WIN32
int _kbhit(void) {
	static const int STDIN = 0;
	static bool initialized = false;

	if (!initialized) {
		struct termios term;
		tcgetattr(STDIN, &term);
#if defined(__sun) && defined(__SVR4)
		term.c_lflag &= ~(ICANON | IEXTEN);
		term.c_cc[VTIME] = 0;
		term.c_cc[VMIN] = 1;
#else
		term.c_lflag &= ~ICANON;
#endif
		tcsetattr(STDIN, TCSANOW, &term);
		setbuf(stdin, NULL);
		initialized = false;
	}
	int bytesWaiting;
	ioctl(STDIN, FIONREAD, &bytesWaiting);
	return bytesWaiting;
}
#endif

int
main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program filter;
	char filter_app[] = "(ether host 01:00:0c:cc:cc:cc and ether[20:2] = 0x2000) or ether proto 0x88cc";
	bpf_u_int32 mask, net;
	struct pcap_pkthdr header;
	const u_char *packet = NULL;
	int num_devs=0, eth_devs=0;
	bool pick = false, continuous = false, silent = false, more = false;
	char *specified_dev = NULL;
	int c, verbose = 0, i = 0, inum, num_packets = 0;
	int seconds=300;
	time_t start_time=0, cdp_time=0;
	pcap_if_t *d, *alldevs;
	IFACE *iface;
	bool cdp_disabled = false, lldp_disabled = false;

	// Inititalize
	memset(errbuf, 0, sizeof(errbuf));

	/* Print out header */
	printf("Cisco Discovery Protocol Reporter\n");
	printf("Version 3.0.3 by Tim Dorssers\n\n");

	/* Check command-line options */
	while((c = getopt(argc, argv, "aoscvhlid:t:")) !=EOF)
		switch(c)
		{
		case 'a':
			cdp_disabled = true;
			break;
		case 'o':
			lldp_disabled = true;
			break;
		case 's':
			silent = true;
			break;
		case 'c':
			continuous = true;
			break;
		case 'l':
			exit(list_interfaces());
			break;
		case 'i':
			pick = true;
			break;
		case 'd':
			specified_dev = optarg;
			pick = false;
			break;
		case 'v':
			verbose++;
			break;
		case 't':
			seconds = atoi(optarg);
			printf("Timeout enabled for %u seconds\n", seconds);
			break;
		case 'h':
		case '?':
			usage();
			break;
		}

	printf("Use -h option to see usage\n\n");
	if (cdp_disabled && lldp_disabled) {
		printf("No discovery protocol enabled!\n");
		return -1;
	}

#ifdef WIN32
	// Load packet.dll
	wpcap_packet_load();
#endif
	
	/* Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	// Count devices
	if (specified_dev == NULL)
	{
		/* Print the list */
		if (pick) {
			printf("\nPlease select an adapter from the list:\n\n");
			for (d = alldevs; d; d = d->next)
			{
#ifdef WIN32
				printf("%d. %s", ++i, get_windows_interface_friendly_name(d->name));
#else
				printf("%d. %s", ++i, d->name);
#endif
				if (d->description)
					printf(" (%s)\n", d->description);
				else
					printf(" (No description available)\n");
			}

			if (i == 0)
			{
				printf("\nNo interfaces found! Make sure pcap is installed.\n");
				return -1;
			}

			printf("\nEnter the interface number (1-%d):", i);
			scanf("%d", &inum);
			printf("\n");

			if (inum < 1 || inum > i)
			{
				printf("Interface number out of range.\n");
				/* Free the device list */
				pcap_freealldevs(alldevs);
				return -1;
			}

			/* Jump to the selected adapter */
			for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

			// One adapter selected
			num_devs = 1;
		}
		else
		{
			// Just count the adapters so we can allocate memory
			for (d = alldevs; d; d = d->next)
				num_devs++;
			// Quit if no adapters found
			if (num_devs == 0)
			{
				printf("\nNo interfaces found! Make sure pcap is installed.\n");
				return -1;
			}
		}
	}
	else
	{
		i = 0;
		// Jump to specified adapter
		for (d = alldevs; d; d = d->next) {
#ifdef WIN32
			if (strcmp(get_windows_interface_friendly_name(d->name), specified_dev) == 0) {
#else
			if (strcmp(d->name, specified_dev) == 0) {
#endif
				i = 1;
				break;
			}
			}
		if (i == 0) {
			printf("Device %s not found\n", specified_dev);
			/* Free the device list */
			pcap_freealldevs(alldevs);
			return -1;
		}
		else
			printf("Using device %s\n\n", specified_dev);

		// One adapter specified
		num_devs = 1;
	}

	// Allocate memory to hold devices and handles
	iface = (IFACE*)malloc((num_devs + 1) * sizeof(IFACE));
	if (iface == NULL) {
		/* Free the device list */
		pcap_freealldevs(alldevs);
		free(iface);
		return -1;
	}

	// Store device pointers
	if (specified_dev || pick) 
		iface[num_devs].dev = d;
	else
	{
		i = 1;
		for (d = alldevs; d; d = d->next)
			iface[i++].dev = d;
	}

	// Get MAC addresses
	for (i = 1; i <= num_devs; i++) {
		getadaptermac(iface[i].dev->name, iface[i].addr);
	}

	// Prepare interfaces
	for (i = 1; i <= num_devs; i++) {

		/* Open the pcap device */
		if ((iface[i].handle = pcap_open_live(iface[i].dev->name, 65536, 1, 1000, errbuf)) == NULL)
		{
			printf("%s\n", errbuf);
			free(iface);
			pcap_freealldevs(alldevs);
			exit(1);
		}
#if defined(__APPLE_CC__) || defined(__APPLE__)
		int v = 1;
		ioctl(pcap_fileno(iface[i].handle), BIOCIMMEDIATE, &v);
#endif
		// Dislay warning if set
		if (strlen(errbuf))
			printf("%s\n", errbuf);

		// We only support Ethernet adapters
		if (pcap_datalink(iface[i].handle) != DLT_EN10MB) {
			if (num_devs == 1) {
				fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", iface[i].dev->name);
				pcap_close(iface[i].handle);
				free(iface);
				pcap_freealldevs(alldevs);
				exit(1);
			}
		} else {
			eth_devs++;

			/* Get the network number and netmask */
			pcap_lookupnet(iface[i].dev->name, &net, &mask, errbuf);
			if (strlen(errbuf))
				printf("%s\n", errbuf);

			/* Compile the pcap filter */
			pcap_compile(iface[i].handle, &filter, filter_app, 0, net);

			/* Activate the pcap filter */
			pcap_setfilter(iface[i].handle, &filter);
			pcap_freecode(&filter);
		}

		/* Set non-blocking mode */
		if (pcap_setnonblock(iface[i].handle, 1, errbuf))
			pcap_perror(iface[i].handle, NULL);
	}

	// Send CDP packet with VLAN ID request to trigger switch CDP advertisement
	// or send LLDP packet with TTL of 0 and then a LLDP-MED packet to trigger
	// switch LLDP advertisement
	if (!silent) {
		printf("Sending on %d interface(s)\n", eth_devs);
		for (i = 1; i <= num_devs; i++) {
			// Send on ethernet adapters only
			if (pcap_datalink(iface[i].handle) == DLT_EN10MB) {
				if (!cdp_disabled)
					cdp_send(&iface[i], true);
				if (!lldp_disabled) {
					lldp_send(&iface[i], 0);
					lldp_send(&iface[i], 120);
				}
			}
		}
		printf("Done\n");
	}

	printf("\nPress any key to quit or wait for timeout\n"); 
	printf("Listening on %d interface(s)\n", eth_devs);
	/* Get current time to check for timeout */
	start_time = time(NULL);
	cdp_time = time(NULL);
	do
	{
		advance_cursor();
		// For each interface
		for (i = 1; i <= num_devs; i++) {
			packet = pcap_next(iface[i].handle, &header);
			// Check if packet has been received on an Ethernet adapter
			if (packet && pcap_datalink(iface[i].handle) == DLT_EN10MB) {
				// Do not decode our own cdp packet
				if (memcmp(packet + 6, iface[i].addr, 6)) {
					num_packets++;
					printf(" \n-------------------------\n");
#ifdef WIN32
					printf("Interface\t: %s\n", get_windows_interface_friendly_name(iface[i].dev->name));
#else
					printf("Interface\t: %s\n", iface[i].dev->name);
#endif
					// print cdp packet
					if (!cdp_disabled)
						print_cdp_packet(packet + 22, header.len - 22, verbose, &more);
					// print lldp packet
					if (!lldp_disabled)
						print_lldp_packet(packet + 14, header.len - 14, verbose, &more);
					// stop if only a single packet is needed by setting timeout to zero
					if (!continuous)
						seconds = 0;
				}
			}
		}
		// Periodically send regular advertisement
		if (time(NULL) - cdp_time > 59) {
			cdp_time = time(NULL);
			for (i = 1; i <= num_devs; i++)
				if (pcap_datalink(iface[i].handle) == DLT_EN10MB) {
					if (!cdp_disabled)
						cdp_send(&iface[i], false);
					if (!lldp_disabled)
						lldp_send(&iface[i], 120);
				}
		}
		
		// Sleep and check key press
#ifdef WIN32
		Sleep(100);
		if (_kbhit()) {
			_getch();
			break;
		}
#else
		usleep(100000);
		if (_kbhit()) {
			fflush(stdout);
			break;
		}
#endif
	} while (start_time+seconds > time(NULL));

	printf(" \nDone\n");
	// Cleanup
	for (i = 1; i < num_devs;i++)
		pcap_close(iface[i].handle);
	free(iface);
	pcap_freealldevs(alldevs);
	// If one or more packets have been received, display message if not all TLVs are displayed
	if (num_packets) {
		if (more)
			printf("\nNot all TLVs displayed, use -vv to display all TLVs\n");
		else if (verbose == 0)
			printf("\nUse -v to display more TLVs\n");
	}

#ifdef WIN32
	printf("\nPress ENTER to quit\n");
	getchar();
#endif
	return(0);
}
