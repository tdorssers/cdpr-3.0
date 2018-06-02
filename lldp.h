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

#ifndef LLDP_H
#define LLDP_H

/* TLV Types */
#define END_OF_LLDPDU_TLV_TYPE			0x00	/* Mandatory */
#define CHASSIS_ID_TLV_TYPE				0x01	/* Mandatory */
#define PORT_ID_TLV_TYPE				0x02	/* Mandatory */
#define TIME_TO_LIVE_TLV_TYPE			0x03	/* Mandatory */
#define PORT_DESCRIPTION_TLV_TYPE		0x04
#define SYSTEM_NAME_TLV_TYPE			0x05
#define SYSTEM_DESCRIPTION_TLV_TYPE		0x06
#define SYSTEM_CAPABILITIES_TLV_TYPE	0x07
#define MANAGEMENT_ADDR_TLV_TYPE		0x08
#define ORGANIZATION_SPECIFIC_TLV_TYPE	0x7F

/* Masks */
#define TLV_TYPE_MASK		0xFE00
#define TLV_TYPE(value)		(((value) & TLV_TYPE_MASK) >> 9)
#define TLV_INFO_LEN_MASK	0x01FF
#define TLV_INFO_LEN(value)	((value) & TLV_INFO_LEN_MASK)

#define  AFNUM_INET   1 /* IP (IP version 4) */ 
#define  AFNUM_INET6  2 /* IP6 (IP version 6) */ 

#define OUI_CISCO_2         0x000142    /* Cisco */
#define OUI_DCBX            0x001B21    /* Data Center Bridging Capabilities Exchange Protocol */
#define OUI_IEEE_802_3      0x00120F    /* IEEE 802.3 */
#define OUI_MEDIA_ENDPOINT  0x0012BB    /* Media (TIA TR-41 Committee) */
#define OUI_IEEE_802_1      0x0080C2    /* IEEE 802.1 Committee */
#define OUI_IEEE_802_1QBG   0x001B3F    /* IEEE 802.1 Qbg */

/*
* Define constants for the LLDP 802.3 MAC/PHY Configuration/Status
* PMD Auto-Negotiation Advertised Capability field.
*/

#define AUTONEG_OTHER			0x8000
#define AUTONEG_10BASE_T		0x4000
#define AUTONEG_10BASET_FD		0x2000
#define AUTONEG_100BASE_T4		0x1000
#define AUTONEG_100BASE_TX		0x0800
#define AUTONEG_100BASE_TXFD	0x0400
#define AUTONEG_100BASE_T2		0x0200
#define AUTONEG_100BASE_T2FD	0x0100
#define AUTONEG_FDX_PAUSE		0x0080
#define AUTONEG_FDX_APAUSE		0x0040
#define AUTONEG_FDX_SPAUSE		0x0020
#define AUTONEG_FDX_BPAUSE		0x0010
#define AUTONEG_1000BASE_X		0x0008
#define AUTONEG_1000BASE_XFD	0x0004
#define AUTONEG_1000BASE_T		0x0002
#define AUTONEG_1000BASE_TFD	0x0001

/* System Capabilities */
#define SYSTEM_CAPABILITY_OTHER		0x0001
#define SYSTEM_CAPABILITY_REPEATER	0x0002
#define SYSTEM_CAPABILITY_BRIDGE	0x0004
#define SYSTEM_CAPABILITY_WLAN		0x0008
#define SYSTEM_CAPABILITY_ROUTER	0x0010
#define SYSTEM_CAPABILITY_TELEPHONE	0x0020
#define SYSTEM_CAPABILITY_DOCSIS	0x0040
#define SYSTEM_CAPABILITY_STATION	0x0080

/* Media Capabilities */
#define MEDIA_CAPABILITY_LLDP				0x0001
#define MEDIA_CAPABILITY_NETWORK_POLICY		0x0002
#define MEDIA_CAPABILITY_LOCATION_ID		0x0004
#define MEDIA_CAPABILITY_MDI_PSE			0x0008
#define MEDIA_CAPABILITY_MDI_PD				0x0010
#define MEDIA_CAPABILITY_INVENTORY			0x0020

u_int8_t print_location_id(const u_char *value, u_int32_t tlvLen);
void print_lldp_packet(const u_char *p, unsigned int plen, int verbose, bool *more);

#endif
