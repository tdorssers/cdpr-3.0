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
*/

#ifndef CDP_H
#define CDP_H

#include <stdbool.h>

#ifndef WIN32

#include <netinet/in.h>

#if defined(__sun) && defined(__SVR4)

typedef unsigned char u_int8_t;
typedef unsigned short int u_int16_t;
typedef unsigned int u_int32_t;
typedef	unsigned long long	u_int64_t;
#include <sys/byteorder.h>

#elif !defined(__APPLE_CC__) && !defined(__APPLE__)

#if __BYTE_ORDER == __LITTLE_ENDIAN

#if defined(__FreeBSD__)
#include <sys/endian.h>
#elif defined(__NetBSD__)
#include <machine/bswap.h>
#else
#include <byteswap.h>
#endif

#ifndef ntohll
static inline u_int64_t ntohll(u_int64_t x) {
#if defined(__FreeBSD__) || defined (__NetBSD__)
	return bswap64(x);
#else
	return bswap_64(x);
#endif
}
#endif
#ifndef htonll
static inline u_int64_t htonll(u_int64_t x) {
#if defined(__FreeBSD__) || defined (__NetBSD__)
	return bswap64(x);
#else
	return bswap_64(x);
#endif
}
#endif
#elif __BYTE_ORDER == __BIG_ENDIAN
#ifndef ntohll
static inline u_int64_t ntohll(u_int64_t x) {
	return x;
}
#endif
#ifndef htonll
static inline u_int64_t htonll(u_int64_t x) {
	return x;
}
#endif

#endif	/* __BYTE_ORDER == __BIG_ENDIAN */

#endif

#else

#endif /* WIN32 */

#if __BYTE_ORDER == __LITTLE_ENDIAN

#ifndef hton24
inline u_int32_t hton24(u_int32_t x) {
	u_int32_t ergebnis;

	ergebnis = (x & 0xFF00) | ((x & 0xFF) << 16) | ((x & 0xFF0000) >> 16);
	return ergebnis;
}
#endif
#ifndef ntoh24
inline u_int32_t ntoh24(u_int32_t x) {
	u_int32_t ergebnis;

	ergebnis = (x & 0xFF00) | ((x & 0xFF) << 16) | ((x & 0xFF0000) >> 16);
	return ergebnis;
}
#endif

#elif __BYTE_ORDER == __BIG_ENDIAN

#ifndef ntoh24
static inline u_int32_t ntoh24(u_int32_t x) {
	return x;
}
#endif
#ifndef hton24
static inline u_int24_t htonll(u_int32_t x) {
	return x;
}
#endif

#endif /* __BYTE_ORDER == __BIG_ENDIAN */

#if defined(EMULATE_UNALIGNED) && defined(__GNUC__)

#include <string.h> 

#define get_unaligned(ptr) \
({ __typeof__(*(ptr)) __tmp; memmove(&__tmp, (ptr), sizeof(*(ptr))); \
__tmp; })

#define put_unaligned(val, ptr) \
({ __typeof__(*(ptr)) __tmp = (val); \
	memmove((ptr), &__tmp, sizeof(*(ptr))); \
	(void)0; })
#else 

#define get_unaligned(ptr) (*(ptr)) 
#define put_unaligned(val, ptr) ((void)( *(ptr) = (val) )) 

#endif /* EMULATE_UNALIGNED */

/* Define the constants and text values for the 'type' field: */
#define TYPE_DEVICE_ID			0x0001 /* Mandatory */
#define TYPE_ADDRESS			0x0002 /* Mandatory */
#define TYPE_PORT_ID			0x0003
#define TYPE_CAPABILITIES		0x0004
#define TYPE_IOS_VERSION		0x0005
#define TYPE_PLATFORM			0x0006
#define TYPE_IP_PREFIX			0x0007
#define TYPE_HELLO				0x0008 /* Protocol Hello */
#define TYPE_VTP_MGMT_DOMAIN	0x0009 /* VTP Domain */
#define TYPE_NATIVE_VLAN		0x000a /* Native VLAN */
#define TYPE_DUPLEX				0x000b /* Full/Half Duplex */
#define TYPE_VOIP_VLAN_REPLY    0x000e /* VoIP VLAN reply */
#define TYPE_VOIP_VLAN_QUERY    0x000f /* VoIP VLAN query */
#define TYPE_POWER              0x0010 /* Power consumption */
#define TYPE_MTU                0x0011 /* MTU */
#define TYPE_TRUST_BITMAP       0x0012 /* Trust bitmap */
#define TYPE_UNTRUSTED_COS      0x0013 /* Untrusted port CoS */
#define TYPE_SYSTEM_NAME        0x0014 /* System Name */
#define TYPE_SYSTEM_OID         0x0015 /* System OID */
#define TYPE_MANAGEMENT_ADDR    0x0016 /* Management Address(es) */
#define TYPE_LOCATION           0x0017 /* Location */
#define TYPE_EXT_PORT_ID        0x0018 /* External Port-ID */
#define TYPE_POWER_REQUESTED    0x0019 /* Power Requested */
#define TYPE_POWER_AVAILABLE    0x001a /* Power Available */
#define TYPE_PORT_UNIDIR        0x001b /* Port Unidirectional */
/*								0x001c    Second Port Status */
#define TYPE_NRGYZ              0x001d /* EnergyWise over CDP */
#define TYPE_SPARE_POE          0x001f /* Spare Pair PoE */
#define TYPE_HP_BSSID           0x1000 /* BSSID */
#define TYPE_HP_SERIAL          0x1001 /* Serial number */
#define TYPE_HP_SSID            0x1002 /* SSID */
#define TYPE_HP_RADIO1_CH       0x1003 /* Radio1 channel */
#define TYPE_HP_SNMP_PORT       0x1006 /* SNMP listening UDP port */
#define TYPE_HP_MGMT_PORT       0x1007 /* Web interface TCP port */
#define TYPE_HP_SOURCE_MAC      0x1008 /* Sender MAC address for the AP, both wired and wireless */
#define TYPE_HP_RADIO2_CH       0x1009 /* Radio2 channel */
#define TYPE_HP_RADIO1_OMODE    0x100A /* Radio1 Operating mode */
#define TYPE_HP_RADIO2_OMODE    0x100B /* Radio2 Operating mode */
#define TYPE_HP_RADIO1_RMODE    0x100C /* Radio1 Radio mode */
#define TYPE_HP_RADIO2_RMODE    0x100D /* Radio2 Radio mode */

typedef struct _cdp_packet_header
{
	u_int8_t  version;
	u_int8_t  time_to_live;
	u_int16_t checksum;
} CDP_HDR;

typedef struct _cdp_packet_data
{
	u_int16_t type;			// see TYPE_ above
	u_int16_t length;		// total length of type/length/value
	//        value;		// variable length value
} CDP_DATA;

typedef struct ethernet_header {
	u_char ether_dhost[6];
	u_char ether_shost[6];
	u_int16_t type_length;
#if defined(__GNUC__) && (__GNUC__ >= 4)
} __attribute__((__may_alias__)) ETH_HDR;
#else
} ETH_HDR;
#endif

typedef struct logical_link_control {
	u_char  dsapigbit;
	u_char  ssapcrbit;
	u_char  controlfield;
	u_char  organizationc[3];
	u_int16_t  pid;
} LLC;

typedef struct _iface {
	pcap_t *handle;
	pcap_if_t *dev;
	char addr[6];
} IFACE;

void dump_ip(const u_char *ip);
void dump_ipv6(const u_char *ip);
void dump_hex(const u_char *p, int len);
void dump_ascii(const u_char *p, int len);
const char *get_cdp_type(int type);
void print_cdp_address(u_char *v);
void print_cdp_capabilities(u_char *v);
void print_system_oid(u_char *v);
void dump_prefix(u_char *v, int num_prefix);
void print_power_avail(u_char *v, int vlen);
void print_spare_poe(u_char *v);
void print_ip_prefix(u_char *v, int vlen, int type);
void print_vlan_reply(u_char *v);
void print_hello(u_char *v, int vlen);
void print_cdp_packet(const u_char *p, unsigned int plen, int verbose, bool *more);

#endif
