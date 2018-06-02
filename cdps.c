/*
* cdpr - Cisco Discovery Protocol Reporter
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
*/

#include "cdps.h"
#ifdef WIN32
#include "capture_wpcap_packet.h"
#include "capture_win_ifnames.h"
#else
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/utsname.h>
#if defined(__sun) && defined(__SVR4)
#include <sys/socket.h>
#include <sys/sockio.h>
#elif !defined(__linux) && !defined(__linux__)
#include <sys/sysctl.h>
#include <net/if_dl.h>
#endif
#endif
#include "os_version_info.h"
#include "cdp.h"
#include "lldp.h"

u_int16_t chksum(u_char *data, unsigned long count) {

	u_int32_t sum = 0;
	u_int16_t *wrd;

	wrd = (u_int16_t *)data;
	while (count > 1) {
		sum = sum + *wrd;
		wrd++;
		count -= 2;
	}

	if (count > 0) {
		sum = sum + ((*wrd & 0xFF) << 8);
	}

	/*  Fold 32-bit sum to 16 bits */
	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}

	return ((u_int16_t)~sum);
}

void getadaptermac(char *dev, char *mac) {
#if defined(WIN32)
	// For Windows OS use PacketRequest OID_802_3_CURRENT_ADDRESS method
	LPADAPTER  adapter;
	unsigned char  values[100];
	unsigned int len = sizeof(values);

	/* open the network adapter */
	adapter = wpcap_packet_open(dev);
	if (adapter == NULL) {
		fprintf(stderr, "Error loading packet.dll\n");
		return;
	}
	/* get 802.3 address */
	if (wpcap_packet_request(adapter, OID_802_3_CURRENT_ADDRESS, FALSE, values, &len)) {
		memcpy(mac, &values, 6);
	}
	else
		printf("Error in wpcap_packet_request\n");
	/* close the network adapter */
	wpcap_packet_close(adapter);
#elif defined(__sun) && defined(__SVR4)
	// For Solaris use ioctl SIOCGARP method
	int i=0, sock, nicount;
	struct arpreq arpreq;
	struct ifreq nicnumber[24];
	struct ifconf ifconf;

	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) > -1) {
		ifconf.ifc_buf = (caddr_t)nicnumber;
		ifconf.ifc_len = sizeof(nicnumber);
	}   
	if (!ioctl(sock, SIOCGIFCONF, (char*)&ifconf)) {
        nicount = ifconf.ifc_len / (sizeof(struct ifreq));
		for (i=0; i<=nicount; i++) { 
			if (!strcmp(nicnumber[i].ifr_name,dev))
				break;
			if (i == (nicount - 1))
				close(sock);
		}
	} else
		close(sock);
    ((struct sockaddr_in*)&arpreq.arp_pa)->sin_addr.s_addr = ((struct sockaddr_in*)&nicnumber[i].ifr_addr)->sin_addr.s_addr;
	if (!(ioctl(sock, SIOCGARP, (char*)&arpreq))) {
		memcpy(mac, arpreq.arp_ha.sa_data, 6);
		close (sock);
	}
#elif defined(__linux) || defined(__linux__)
	// For Linux OS use ioctl SIOCGIFHWADDR method
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
	int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (fd != -1) {
		if (ioctl(fd, SIOCGIFHWADDR, &ifr) != -1) {
			if (ifr.ifr_hwaddr.sa_family == ARPHRD_ETHER) {
				memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
			}
		}
		close(fd);
	}
#else
	// For Mac OS X and others use sysctl method
    int mib[6];
    size_t len;
    char *buf;
    struct if_msghdr *ifm;
    struct sockaddr_dl *sdl;

    mib[0] = CTL_NET;
    mib[1] = AF_ROUTE;
    mib[2] = 0;
    mib[3] = AF_LINK;
    mib[4] = NET_RT_IFLIST;
    if ((mib[5] = if_nametoindex(dev)) == 0) {
        return;
    }
    if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0) {
        return;
    }
    if ((buf = (char*)malloc(len)) == NULL) {
        return;
    }
    if (sysctl(mib, 6, buf, &len, NULL, 0) < 0) {
        return;
    }
    ifm = (struct if_msghdr *)buf;
    sdl = (struct sockaddr_dl *)(ifm + 1);
    memcpy(mac, LLADDR(sdl), 6);
#endif
}

void lldp_send(IFACE *iface, u_int16_t ttl) {
	u_char LLDP_DEST[6] = { 0x01,0x80,0xC2,0x00,0x00,0x0E };
	u_char lldpframe[1700];
	u_char *lldp_end;
	char *mportid;
	u_int16_t type_and_length;
	u_int16_t ttl_val;
	char hname[150], version[250];
	pcap_addr_t *a;

#ifdef WIN32
	mportid = get_windows_interface_friendly_name(iface->dev->name);
#else
	mportid = iface->dev->name;
#endif
	// Inititalize
	memset(hname, 0, sizeof(hname));
	memset(version, 0, sizeof(version));
	memset(&lldpframe, 0, sizeof(lldpframe));
	lldp_end = (u_char *)lldpframe;
	/* make Ethernet II header */
	memcpy(((ETH_HDR *)lldp_end)->ether_dhost, &LLDP_DEST, 6); // Destination MAC
	memcpy(((ETH_HDR *)lldp_end)->ether_shost, iface->addr, 6); // Source MAC
	put_unaligned(htons(0x88cc), &((ETH_HDR *)lldp_end)->type_length); // Ethertype
	lldp_end += sizeof(ETH_HDR);
	// This TLV *MUST* be first.
	type_and_length = CHASSIS_ID_TLV_TYPE << 9;
	type_and_length |= 7; //The size of a MAC + the size of the subtype (1 byte)
	put_unaligned(htons(type_and_length), (u_int16_t *)lldp_end);
	lldp_end += sizeof(u_int16_t);
	*lldp_end++ = 4; /* MAC address */
	memcpy(lldp_end, iface->addr, 6);
	lldp_end += 6;
	// This TLV *MUST* be second.
	type_and_length = PORT_ID_TLV_TYPE << 9;
	type_and_length |= 1 + (u_int16_t)strlen(mportid); //The length of the interface name + the size of the subtype (1 byte)
	put_unaligned(htons(type_and_length), (u_int16_t *)lldp_end);
	lldp_end += sizeof(u_int16_t);
	*lldp_end++ = 5; /* Interface name */
	memcpy(lldp_end, mportid, strlen(mportid));
	lldp_end += strlen(mportid);
	// This TLV *MUST* be third.
	type_and_length = TIME_TO_LIVE_TLV_TYPE << 9;
	type_and_length |= 2; // Static length defined by IEEE 802.1AB section 9.5.4
	put_unaligned(htons(type_and_length), (u_int16_t *)lldp_end);
	lldp_end += sizeof(u_int16_t);
	ttl_val = htons(ttl);
	memcpy(lldp_end, &ttl_val, 2);
	lldp_end += 2;
	// Optional TLVs are inserted between Time to live TLV and End of LLDPDU TLV
	if (ttl) {
		// System Name TLV
		gethostname(hname, sizeof(hname));
		type_and_length = SYSTEM_NAME_TLV_TYPE << 9;
		type_and_length |= (u_int16_t)strlen(hname);
		put_unaligned(htons(type_and_length), (u_int16_t *)lldp_end);
		lldp_end += sizeof(u_int16_t);
		memcpy(lldp_end, hname, strlen(hname));
		lldp_end += (u_int16_t)strlen(hname);
		// System Description TLV
		get_os_version_info(version);
		type_and_length = SYSTEM_DESCRIPTION_TLV_TYPE << 9;
		type_and_length |= (u_int16_t)strlen(version);
		put_unaligned(htons(type_and_length), (u_int16_t *)lldp_end);
		lldp_end += sizeof(u_int16_t);
		memcpy(lldp_end, version, strlen(version));
		lldp_end += (u_int16_t)strlen(version);
		// Port description TLV
		if (strlen(iface->dev->description)) {
			type_and_length = PORT_DESCRIPTION_TLV_TYPE << 9;
			type_and_length |= (u_int16_t)strlen(iface->dev->description);
			put_unaligned(htons(type_and_length), (u_int16_t *)lldp_end);
			lldp_end += sizeof(u_int16_t);
			memcpy(lldp_end, iface->dev->description, strlen(iface->dev->description));
			lldp_end += (u_int16_t)strlen(iface->dev->description);
		}
		// System Capabilities TLV
		type_and_length = SYSTEM_CAPABILITIES_TLV_TYPE << 9;
		type_and_length |= 4; // Size of the TLV
		put_unaligned(htons(type_and_length), (u_int16_t *)lldp_end);
		lldp_end += sizeof(u_int16_t);
		put_unaligned(htons(SYSTEM_CAPABILITY_STATION), (u_int16_t *)lldp_end); // Supported capabilities
		lldp_end += sizeof(u_int16_t);
		put_unaligned(htons(SYSTEM_CAPABILITY_STATION), (u_int16_t *)lldp_end); // Enabled capabilities
		lldp_end += sizeof(u_int16_t);
		// Management Address TLV
		for (a = iface->dev->addresses; a; a = a->next)
			switch (a->addr->sa_family)
			{
			case AF_INET:
				type_and_length = MANAGEMENT_ADDR_TLV_TYPE << 9;
				type_and_length |= 12; // Size of the TLV
				put_unaligned(htons(type_and_length), (u_int16_t *)lldp_end);
				lldp_end += sizeof(u_int16_t);
				*lldp_end++ = 5; // Address String Length
				*lldp_end++ = AFNUM_INET; // Address Subtype
				put_unaligned(((struct sockaddr_in *)a->addr)->sin_addr.s_addr, ((u_int32_t *)lldp_end));
				lldp_end += sizeof(struct in_addr);
				*lldp_end++ = 1; // Interface Subtype
				put_unaligned(htonl(1), (u_int32_t *)lldp_end); // Interface number
				lldp_end += sizeof(u_int32_t);
				*lldp_end++ = 0; // OID String Length
				break;
			case AF_INET6:
				type_and_length = MANAGEMENT_ADDR_TLV_TYPE << 9;
				type_and_length |= 24; // Size of the TLV
				put_unaligned(htons(type_and_length), (u_int16_t *)lldp_end);
				lldp_end += sizeof(u_int16_t);
				*lldp_end++ = 17; // Address String Length
				*lldp_end++ = AFNUM_INET6; // Address Subtype
				memcpy(lldp_end, &((struct sockaddr_in6 *)a->addr)->sin6_addr, sizeof(struct in6_addr));
				lldp_end += sizeof(struct in6_addr);
				*lldp_end++ = 1; // Interface Subtype
				put_unaligned(htonl(1), (u_int32_t *)lldp_end); // Interface number
				lldp_end += sizeof(u_int32_t);
				*lldp_end++ = 0; // OID String Length
				break;
			}
		/* LLDP-MED TLV */
		type_and_length = ORGANIZATION_SPECIFIC_TLV_TYPE << 9;
		type_and_length |= 7; // 3 byte OUI + 1 byte subType + 2 bytes Media capabilities + 1 byte device type
		put_unaligned(htons(type_and_length), (u_int16_t *)lldp_end);
		lldp_end += sizeof(u_int16_t);
		*(u_int32_t *)lldp_end = hton24(OUI_MEDIA_ENDPOINT);
		lldp_end += 3;
		*lldp_end++ = 1; /* LLDP-MED Capabilities */
		put_unaligned(htons(MEDIA_CAPABILITY_LLDP) ,(u_int16_t *)lldp_end);
		lldp_end += sizeof(u_int16_t);
		*lldp_end++ = 1; // Endpoint Class I
	}
	// End of LLDPDU
	type_and_length = END_OF_LLDPDU_TLV_TYPE << 9;
	type_and_length |= 0;
	put_unaligned(htons(type_and_length), (u_int16_t *)lldp_end);
	lldp_end += sizeof(u_int16_t);
	// Pad to 64 bytes
	if (lldp_end - (u_char*)lldpframe < 64)
		lldp_end = (u_char*)lldpframe + 64;
	// Put packet on the wire
	if (pcap_sendpacket(iface->handle, lldpframe, lldp_end - (u_char*)lldpframe))
		printf("Error in pcap_sendpacket [%s]\n", iface->dev->name);
}

void cdp_send(IFACE *iface, bool vvq) {
	u_char CDP_DEST[6] = { 0x01,0x00,0x0C,0xCC,0xCC,0xCC };
	u_char cdpframe[1700];
	u_char *cdp_end;
	u_int16_t cs;
	u_char vvq_send_bytes[4] = { 0x20,0x02,0x00,0x01 };
	char hname[150], version[250];
	char *mportid;
	pcap_addr_t *a;
	u_int32_t num = 0;

#if defined(WIN32)
	char mplatform[] = "Windows";
#elif defined(__APPLE_CC__) || defined(__APPLE__)
	char mplatform[] = "Mac OS X";
#else
	struct utsname unameData;
	uname(&unameData);
	char *mplatform = unameData.sysname;
#endif
#ifdef WIN32
	mportid = get_windows_interface_friendly_name(iface->dev->name);
#else
	mportid = iface->dev->name;
#endif
	// Inititalize
	memset(hname, 0, sizeof(hname));
	memset(version, 0, sizeof(version));
	// Get hostname
	gethostname(hname, sizeof(hname));
	// Get OS version
	get_os_version_info(version);
	// Initialize buffer
	memset(&cdpframe, 0, sizeof(cdpframe));
	cdp_end = (u_char *)cdpframe;
	/* make IEEE 802.3 header */
	memcpy(((ETH_HDR *)cdp_end)->ether_dhost, &CDP_DEST, 6); // Destination MAC
	memcpy(((ETH_HDR *)cdp_end)->ether_shost, iface->addr, 6); // Source MAC
	cdp_end += sizeof(ETH_HDR);
	/* build LLC header */
	((LLC *)cdp_end)->dsapigbit = 0xAA;
	((LLC *)cdp_end)->ssapcrbit = 0xAA;
	((LLC *)cdp_end)->controlfield = 0x03; /* unnumbered */
	((LLC *)cdp_end)->organizationc[0] = 0x00;
	((LLC *)cdp_end)->organizationc[1] = 0x00;
	((LLC *)cdp_end)->organizationc[2] = 0x0C; /* cisco */
	put_unaligned(htons(0x2000), &((LLC *)cdp_end)->pid);
	cdp_end += sizeof(LLC);
	/* build CDP header */
	((CDP_HDR *)cdp_end)->version = 2;
	((CDP_HDR *)cdp_end)->time_to_live = 180;
	cdp_end += sizeof(CDP_HDR);
	/* make a device id entry */
	put_unaligned(htons(TYPE_DEVICE_ID), &((CDP_DATA *)cdp_end)->type);
	put_unaligned(htons((u_int16_t)strlen(hname) + sizeof(CDP_DATA)), &((CDP_DATA *)cdp_end)->length);
	cdp_end += sizeof(CDP_DATA);
	memcpy(cdp_end, hname, strlen(hname));
	cdp_end += strlen(hname);
	/* make address entry */
	u_char *address_start = cdp_end;
	put_unaligned(htons(TYPE_ADDRESS), &((CDP_DATA *)cdp_end)->type);
	cdp_end += sizeof(CDP_DATA);
	for (a = iface->dev->addresses; a; a = a->next)
		if (a->addr->sa_family == AF_INET || a->addr->sa_family == AF_INET6)
			num++;
	put_unaligned(htonl(num), ((u_int32_t *)cdp_end)); // Number of addresses
	cdp_end += sizeof(u_int32_t);
	for (a = iface->dev->addresses; a; a = a->next)
		switch (a->addr->sa_family)
		{
		case AF_INET:
			*cdp_end++ = 0x01; // Protocol Type NLPID
			*cdp_end++ = sizeof(u_char); // Protocol Length
			*cdp_end++ = 0xCC; // Protocol IP
			put_unaligned(htons(sizeof(struct in_addr)), ((u_int16_t *)cdp_end)); // Address length
			cdp_end += sizeof(u_int16_t);
			put_unaligned(((struct sockaddr_in *)a->addr)->sin_addr.s_addr, ((u_int32_t *)cdp_end));
			cdp_end += sizeof(struct in_addr);
			break;
		case AF_INET6:
			*cdp_end++ = 0x02; // Protocol Type 802.2
			*cdp_end++ = sizeof(u_int64_t); // Protocol Length
			put_unaligned(ntohll(0xAAAA0300000086DD), ((u_int64_t *)cdp_end)); // Protocol IPv6
			cdp_end += sizeof(u_int64_t);
			put_unaligned(htons(sizeof(struct in6_addr)), ((u_int16_t *)cdp_end)); // Address length
			cdp_end += sizeof(u_int16_t);
			memcpy(cdp_end, &((struct sockaddr_in6 *)a->addr)->sin6_addr, sizeof(struct in6_addr));
			cdp_end += sizeof(struct in6_addr);
			break;
		}
	put_unaligned(htons(cdp_end - address_start), &((CDP_DATA *)address_start)->length);
	/* make CDP port entry */
	put_unaligned(htons(TYPE_PORT_ID), &((CDP_DATA *)cdp_end)->type);
	put_unaligned(htons((u_int16_t)strlen(mportid) + sizeof(CDP_DATA)), &((CDP_DATA *)cdp_end)->length);
	cdp_end += sizeof(CDP_DATA);
	memcpy(cdp_end, mportid, strlen(mportid));
	cdp_end += strlen(mportid);
	/* make CDP capabilities entry */
	put_unaligned(htons(TYPE_CAPABILITIES), &((CDP_DATA *)cdp_end)->type);
	put_unaligned(htons(sizeof(u_int32_t) + sizeof(CDP_DATA)), &((CDP_DATA *)cdp_end)->length);
	cdp_end += sizeof(CDP_DATA);
	put_unaligned(htonl(0x010), ((u_int32_t *)cdp_end)); // Host capability
	cdp_end += sizeof(u_int32_t);
	/* make CDP software version */
	put_unaligned(htons(TYPE_IOS_VERSION), &((CDP_DATA *)cdp_end)->type);
	put_unaligned(htons((u_int16_t)strlen(version) + sizeof(CDP_DATA)), &((CDP_DATA *)cdp_end)->length);
	cdp_end += sizeof(CDP_DATA);
	memcpy(cdp_end, version, strlen(version));
	cdp_end += strlen(version);
	/* make CDP platform */
	put_unaligned(htons(TYPE_PLATFORM), &((CDP_DATA *)cdp_end)->type);
	put_unaligned(htons((u_int16_t)strlen(mplatform) + sizeof(CDP_DATA)), &((CDP_DATA *)cdp_end)->length);
	cdp_end += sizeof(CDP_DATA);
	memcpy(cdp_end, mplatform, strlen(mplatform));
	cdp_end += strlen(mplatform);
	/* make CDP VoIP VLAN Query */
	if (vvq) {
		put_unaligned(htons(TYPE_VOIP_VLAN_QUERY), &((CDP_DATA *)cdp_end)->type);
		put_unaligned(htons(sizeof(vvq_send_bytes) + sizeof(CDP_DATA)), &((CDP_DATA *)cdp_end)->length);
		cdp_end += sizeof(CDP_DATA);
		memcpy(cdp_end, vvq_send_bytes, sizeof(vvq_send_bytes));
		cdp_end += sizeof(vvq_send_bytes);
	}
	// Calculate length for IEEE 802.3 header
	put_unaligned(htons(cdp_end - (u_char*)cdpframe - sizeof(ETH_HDR)), &((ETH_HDR *)cdpframe)->type_length);
	/*
	* CDP doesn't adhere to RFC 1071 section 2. (B). It incorrectly assumes
	* checksums are calculated on a big endian platform, therefore i.s.o.
	* padding odd sized data with a zero byte _at the end_ it sets the last
	* big endian _word_ to contain the last network _octet_. This byteswap
	* has to be done on the last octet of network data before feeding it to
	* the Internet checksum routine.
	* CDP checksumming code has a bug in the addition of this last _word_
	* as a signed number into the long word intermediate checksum. When
	* reducing this long to word size checksum an off-by-one error can be
	* made. This off-by-one error is compensated for in the last _word_ of
	* the network data.
	*/
	u_int16_t data_length;
	data_length = cdp_end - (u_char*)cdpframe - 22;
	if (data_length & 1) {
		u_char *padded_buffer;
		/* Allocate new buffer */
		padded_buffer = (u_char *)malloc(data_length + 1);
		memcpy(padded_buffer, (u_char*)cdpframe + 22, data_length);
		/* Swap bytes in last word */
		padded_buffer[data_length] = padded_buffer[data_length - 1];
		padded_buffer[data_length - 1] = 0;
		/* Compensate off-by-one error */
		if (padded_buffer[data_length] & 0x80) {
			padded_buffer[data_length]--;
			padded_buffer[data_length - 1]--;
		}
		cs = chksum(padded_buffer, data_length + 1);
		free(padded_buffer);
	}
	else
		cs = chksum((u_char*)cdpframe + 22, data_length);
	// Store checksum value in CDP header
	put_unaligned(cs, &((CDP_HDR *)((u_char*)cdpframe + 22))->checksum);
	// Put packet on the wire
	if (pcap_sendpacket(iface->handle, cdpframe, cdp_end - (u_char*)cdpframe))
		printf("Error in pcap_sendpacket [%s]\n", iface->dev->name);
}

