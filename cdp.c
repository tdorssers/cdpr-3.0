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

#ifndef WIN32
#include <arpa/inet.h>
#if !defined(__linux) && !defined(__linux__)
#include <sys/socket.h>
#endif
#endif
#include "pcap.h"
#include "cdp.h"
#include "lldp.h"

struct
{
	int type;
	const char *val;
}
type_vals[] = {
	{ TYPE_DEVICE_ID,       "Device ID" },
	{ TYPE_ADDRESS,         "Addresses" },
	{ TYPE_PORT_ID,         "Port-ID (out)" },
	{ TYPE_CAPABILITIES,    "Capability" },
	{ TYPE_IOS_VERSION,     "Version" },
	{ TYPE_PLATFORM,        "Platform" },
	{ TYPE_IP_PREFIX,       "IP Prefix" },
	{ TYPE_HELLO,           "Protocol Hello" },
	{ TYPE_VTP_MGMT_DOMAIN, "VTP Domain" },
	{ TYPE_NATIVE_VLAN,     "Native VLAN" },
	{ TYPE_DUPLEX,          "Duplex" },
	{ TYPE_VOIP_VLAN_REPLY, "VoIP VLAN reply" },
	{ TYPE_VOIP_VLAN_QUERY, "VoIP VLAN query" },
	{ TYPE_POWER,           "Power" },
	{ TYPE_MTU,             "MTU" },
	{ TYPE_TRUST_BITMAP,    "Extended Trust" },
	{ TYPE_UNTRUSTED_COS,   "Port COS" },
	{ TYPE_SYSTEM_NAME,     "System Name" },
	{ TYPE_SYSTEM_OID,      "System OID" },
	{ TYPE_MANAGEMENT_ADDR, "Mgmt Addresses" },
	{ TYPE_LOCATION,        "Location" },
	{ TYPE_EXT_PORT_ID,     "Extended PortID" },
	{ TYPE_POWER_REQUESTED, "Power Requested" },
	{ TYPE_POWER_AVAILABLE, "Power Available" },
	{ TYPE_PORT_UNIDIR,     "Port Unidir" },
	{ TYPE_NRGYZ,           "EnergyWise" },
	{ TYPE_SPARE_POE,       "Spare Pair POE" },
	{ TYPE_HP_BSSID,        "BSSID" },
	{ TYPE_HP_SERIAL,       "Serial number" },
	{ TYPE_HP_SSID,         "SSID" },
	{ TYPE_HP_RADIO1_CH,    "Radio1 channel" },
	{ TYPE_HP_SNMP_PORT,    "SNMP UDP port" },
	{ TYPE_HP_MGMT_PORT,    "Web TCP port" },
	{ TYPE_HP_SOURCE_MAC,   "Source MAC" },
	{ TYPE_HP_RADIO2_CH,    "Radio2 channel" },
	{ TYPE_HP_RADIO1_OMODE, "Radio1 Oper mode" },
	{ TYPE_HP_RADIO2_OMODE, "Radio2 Oper mode" },
	{ TYPE_HP_RADIO1_RMODE, "Radio1 Radio mode" },
	{ TYPE_HP_RADIO2_RMODE, "Radio2 Radio mode" },
	{ 0,                    NULL },
};

void
dump_ip(const u_char *ip)
{
	printf("    IPv4 Address: %d.%d.%d.%d", (int)ip[0], (int)ip[1], (int)ip[2], (int)ip[3]);
}

void
dump_ipv6(const u_char *ip)
{
	char ipv6_buf[INET6_ADDRSTRLEN];

	printf("    IPv6 Address: %s", inet_ntop(AF_INET6, (struct in6_addr *)ip, ipv6_buf, sizeof(ipv6_buf)));
}

void
dump_hex(const u_char *p, int len)
{
	while (len--)
		printf("%02X", *p++);
}

void
dump_ascii(const u_char *p, int len)
{
	while (len--)
	{
		printf("%c", (*p < ' ' || *p > '~') ? '.' : *p);
		++p;
	}
}

const char *
get_cdp_type(int type)
{
	int i;

	for (i = 0; type_vals[i].type != 0; ++i)
	{
		if (type == type_vals[i].type)
			return type_vals[i].val;
	}
	return "Unknown type";
}

void
print_cdp_address(u_char *v)
{
	u_int32_t i;
	u_int32_t number;

	number = ntohl(get_unaligned((u_int32_t *)v));
	v += sizeof(u_int32_t);

	printf("%u\n", number);

	for (i = 0; i < number; ++i)
	{
		u_char protocol = *v;
		u_char protocol_len = *(v + 1);
		u_char *protocol_val = v + 2;
		u_int16_t address_len = ntohs(get_unaligned((u_int16_t *)(v + 2 + protocol_len)));
		u_char *address_val = v + 2 + protocol_len + sizeof(address_len);

		if (protocol == 1 && protocol_len == sizeof(u_char) && *protocol_val == 0xCC && address_len == sizeof(struct in_addr))
			dump_ip(address_val);
		else if (protocol == 2 && protocol_len == sizeof(u_int64_t) && ntohll(get_unaligned((u_int64_t *)protocol_val)) == 0xAAAA0300000086DD && address_len == sizeof(struct in6_addr))
			dump_ipv6(address_val);
		else
			dump_hex(address_val, address_len);
		printf("\n");

		v += (2 + protocol_len + sizeof(address_len) + address_len);
	}
}

void
print_cdp_capabilities(u_char *v)
{
	u_int32_t cap;

	cap = ntohl(get_unaligned((u_int32_t *)v));
	if (cap & 0x001) printf("Router ");
	if (cap & 0x002) printf("Trans-Bridge ");
	if (cap & 0x004) printf("Source-Route-Bridge ");
	if (cap & 0x008) printf("Switch ");
	if (cap & 0x010) printf("Host ");
	if (cap & 0x020) printf("IGMP ");
	if (cap & 0x040) printf("Repeater ");
	if (cap & 0x080) printf("VoIP-Phone ");
	if (cap & 0x100) printf("Remotely-Managed-Device ");
	if (cap & 0x200) printf("CVTA/Supports-STP-Dispute ");
	if (cap & 0x400) printf("Two-Port MAC Relay ");
	printf("\n");
}

// ASN.1 DER Encoded OID
void
print_system_oid(u_char *v)
{
	u_char slen, octet, i;

	// Data type for OID is 0x06
	if ((u_char)*v == 0x06) {
		slen = (u_char)*(v + 1);
		// Decode first two OID string octets
		octet = (u_char)*(v + 2) / 40;
		printf("%u.", octet);
		octet = (u_char)*(v + 2) - (40 * octet);
		printf("%u.", octet);
		// Decode other OID string octets
		for (i = 3; i < slen + 1; i++) {
			octet = (u_char)*(v + i);
			if (octet < 128)
				// One octet for values less then 128
				printf("%u.", octet);
			else
				// Two octets for values greater then 127
				printf("%u ", ((u_int16_t)(octet - 128) << 7) + (u_char)*(v + ++i));
		}
	}
}

void
dump_prefix(u_char *v, int num_prefix)
{
	for (int i = 0; i < num_prefix; i++) {
		dump_ip(v + i * 5);
		printf("/%u\n", (u_char)*(v + i * 5 + 4));
	}
}

void
print_power_avail(u_char *v, int vlen)
{
	printf("Request ID\t: %u\n", ntohs(get_unaligned((u_int16_t *)v)));
	printf("Management ID\t: %u\n", ntohs(get_unaligned((u_int16_t *)(v + 2))));
	for (int i = 4; i < vlen; i += 4)
		printf("Value\t\t: %u mW\n", ntohl(get_unaligned((u_int32_t *)(v + i))));
}

void
print_spare_poe(u_char *v)
{
	printf("PSE Four wire\t: %s\n", ((u_char)*v & 0x01) ? "Supported" : "Not Supported");
	printf("PD Arch shared\t: %s\n", ((u_char)*v & 0x02) ? "Shared" : "Independent");
	printf("PD Request\t: %s\n", ((u_char)*v & 0x04) ? "On" : "Off");
	printf("PSE\t\t: %s\n", ((u_char)*v & 0x08) ? "On" : "Off");
}

void
print_ip_prefix(u_char *v, int vlen, int type)
{
	/* if length is 4 then this is default gw not prefix */
	if (vlen == 4) {
		printf("ODR Default GW\t:\n");
		dump_ip(v);
		printf("\n");
	}
	else {
		int num_prefix = vlen / 5;
		printf("%s\t: %d\n", get_cdp_type(type), num_prefix);
		dump_prefix(v, num_prefix);
	}
	printf("\n");
}

void
print_vlan_reply(u_char *v)
{
	u_int16_t vlan = ntohs(get_unaligned((u_int16_t *)(v + 1)));

	if (vlan == 0)
		printf("dot1p\n");
	else if (vlan == 4095)
		printf("untagged\n");
	else
		printf("%u\n", vlan);
}

void
print_hello(u_char *v, int vlen)
{
	u_int32_t oui = ntoh24(get_unaligned((u_int32_t *)v));
	u_int16_t prot = ntohs(get_unaligned((u_int16_t *)(v + 3)));
	printf("OUI=0x%06X, Protocol ID=0x%04X; payload Len=%d,\nvalue=", oui, prot, vlen - 5);
	dump_hex(v + 5, vlen - 5);
	printf("\n");
}

void
print_cdp_packet(const u_char *p, unsigned int plen, int verbose, bool *more)
{
	CDP_HDR *h;
	CDP_DATA *d;

	h = (CDP_HDR *)p;

	if (h->version < 1 || h->version > 2)
		return;

	printf("CDP Version\t: %x\n", h->version);
	printf("Holdtime\t: %u sec\n", h->time_to_live);

	d = (CDP_DATA *)(p + sizeof(CDP_HDR));
	plen -= sizeof(CDP_HDR);

	while (plen > sizeof(CDP_DATA))
	{
		int type, length;
		u_char *v;  /* variable data */
		int vlen;   /* length of variable data */
		u_int8_t temp;

		type = ntohs(get_unaligned(&((CDP_DATA *)d)->type));
		length = ntohs(get_unaligned(&((CDP_DATA *)d)->length));
		v = (u_char *)d + sizeof(CDP_DATA);
		vlen = length - sizeof(CDP_DATA);

		switch (type)
		{
		case TYPE_DEVICE_ID:
		case TYPE_PORT_ID:
		case TYPE_PLATFORM:
		case TYPE_VTP_MGMT_DOMAIN:
		case TYPE_SYSTEM_NAME:
			printf("%s\t: %.*s\n", get_cdp_type(type), vlen, v);
			break;

		case TYPE_ADDRESS:
		case TYPE_MANAGEMENT_ADDR:
			printf("%s\t: ", get_cdp_type(type));
			print_cdp_address(v);
			printf("\n");
			break;

		case TYPE_CAPABILITIES:
			printf("%s\t: ", get_cdp_type(type));
			print_cdp_capabilities(v);
			break;

		case TYPE_IOS_VERSION:
			if (verbose > 0)
				printf("%s\t\t:\n%.*s\n\n", get_cdp_type(type), vlen, v);
			break;

		case TYPE_NATIVE_VLAN:
			printf("%s\t: %u\n", get_cdp_type(type), ntohs(get_unaligned((u_int16_t *)v)));
			break;

		case TYPE_DUPLEX:
			printf("%s\t\t: %s\n", get_cdp_type(type), (u_char)*v ? "Full" : "Half");
			break;

		case TYPE_TRUST_BITMAP:
			if (verbose > 0)
				printf("%s\t: %s\n", get_cdp_type(type), (u_char)*v ? "Trusted" : "No trust");
			break;

		case TYPE_UNTRUSTED_COS:
			if (verbose > 0)
				printf("%s\t: %u\n", get_cdp_type(type), (u_char)*v);
			break;

		case TYPE_MTU:
			if (verbose > 0)
				printf("%s\t\t: %u\n", get_cdp_type(type), ntohl(get_unaligned((u_int32_t *)v)));
			break;

		case TYPE_IP_PREFIX:
			if (verbose > 0)
				print_ip_prefix(v, vlen, type);
			break;

		case TYPE_VOIP_VLAN_REPLY:
			printf("%s\t: ", get_cdp_type(type));
			print_vlan_reply(v);
			break;

		case TYPE_SYSTEM_OID:
			printf("%s\t: ", get_cdp_type(type));
			print_system_oid(v);
			printf("\n");
			break;

		case TYPE_LOCATION:
			if (verbose > 0) {
				printf("%s\t:\n", get_cdp_type(type)); 
				temp = 0;
				while (temp < vlen)
					temp += print_location_id(v + temp, vlen - temp);
				printf("\n");
			}
			break;

		case TYPE_POWER_AVAILABLE:
			if (verbose > 0) {
				printf("%s\t:\n", get_cdp_type(type));
				print_power_avail(v, vlen);
				printf("\n");
			}
			break;

		case TYPE_SPARE_POE:
			if (verbose > 0) {
				printf("%s\t:\n", get_cdp_type(type));
				print_spare_poe(v);
				printf("\n");
			}
			break;

		case TYPE_HELLO:
			if (verbose > 0) {
				printf("%s\t: ", get_cdp_type(type));
				print_hello(v, vlen);
				printf("\n");
			}
			break;

		case TYPE_HP_BSSID:
		case TYPE_HP_SERIAL:
		case TYPE_HP_SSID:
		case TYPE_HP_RADIO1_CH:
		case TYPE_HP_SNMP_PORT:
		case TYPE_HP_MGMT_PORT:
		case TYPE_HP_SOURCE_MAC:
		case TYPE_HP_RADIO2_CH:
		case TYPE_HP_RADIO1_OMODE:
		case TYPE_HP_RADIO2_OMODE:
		case TYPE_HP_RADIO1_RMODE:
		case TYPE_HP_RADIO2_RMODE:
			if (verbose > 0)
				printf("%s\t: %.*s\n", get_cdp_type(type), vlen, v);
			break;

		default:
			if (verbose > 1) {
				printf("%s\t: ", get_cdp_type(type));
				dump_hex(v, vlen);
				printf("\n");
			}
			else
				*more = true;
		}

		plen -= length;
		d = (CDP_DATA *)((u_char *)d + length);
	}
}
