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

#include "pcap.h"
#include "cdp.h"
#include "lldp.h"

typedef struct _value_string
{
	int value;
	const char *strptr;
} value_string;

static const value_string tlv_types[] = {
	{ END_OF_LLDPDU_TLV_TYPE,			"End of LLDPDU" },
	{ CHASSIS_ID_TLV_TYPE,				"Chassis id" },
	{ PORT_ID_TLV_TYPE,					"Port id" },
	{ TIME_TO_LIVE_TLV_TYPE,			"Time remaining" },
	{ PORT_DESCRIPTION_TLV_TYPE,		"Port Description" },
	{ SYSTEM_NAME_TLV_TYPE,				"System Name" },
	{ SYSTEM_DESCRIPTION_TLV_TYPE,		"System Descr." },
	{ SYSTEM_CAPABILITIES_TLV_TYPE,		"System Cap." },
	{ MANAGEMENT_ADDR_TLV_TYPE,			"Management Addr." },
	{ ORGANIZATION_SPECIFIC_TLV_TYPE,	"Org. Specific" },
	{ 0, NULL }
};

/*
* Define the text strings for the LLDP 802.3 MAC/PHY Configuration/Status
* Operational MAU Type field.
*/

static const value_string operational_mau_type_values[] = {
	{ 1,	"AUI" },
	{ 2,	"10Base5" },
	{ 3,	"Foirl" },
	{ 4,	"10Base2" },
	{ 5,	"10BaseT" },
	{ 6,	"10BaseFP" },
	{ 7,	"10BaseFB" },
	{ 8,	"10BaseFL" },
	{ 9,	"10Broad36" },
	{ 10,	"10BaseT(HD)" },
	{ 11,	"10BaseT(FD)" },
	{ 12,	"10BaseFL(HD)" },
	{ 13,	"10BaseFL(FD)" },
	{ 14,	"10BaseT4" },
	{ 15,	"100BaseTX(HD)" },
	{ 16,	"100BaseTX(FD)" },
	{ 17,	"100BaseFX(HD)" },
	{ 18,	"100BaseFX(FD)" },
	{ 19,	"100BaseT2(HD)" },
	{ 20,	"100BaseT2(FD)" },
	{ 21,	"1000BaseX(HD)" },
	{ 22,	"1000BaseX(FD)" },
	{ 23,	"1000BaseLX(HD)" },
	{ 24,	"1000BaseLX(FD)" },
	{ 25,	"1000BaseSX(HD)" },
	{ 26,	"1000BaseSX(FD)" },
	{ 27,	"1000BaseCX(HD)" },
	{ 28,	"1000BaseCX(FD)" },
	{ 29,	"1000BaseT(HD)" },
	{ 30,	"1000BaseT(FD)" },
	{ 31,	"10GigBaseX" },
	{ 32,	"10GigBaseLX4" },
	{ 33,	"10GigBaseR" },
	{ 34,	"10GigBaseER" },
	{ 35,	"10GigBaseLR" },
	{ 36,	"10GigBaseSR" },
	{ 37,	"10GigBaseW" },
	{ 38,	"10GigBaseEW" },
	{ 39,	"10GigBaseLW" },
	{ 40,	"10GigBaseSW" },
	// new since RFC3636
	{ 41,	"10GigBaseCX4 "},
	{ 42,	"2BaseTL" },
	{ 43,	"10PassTS" },
	{ 44,	"100BaseBX10D" },
	{ 45,	"100BaseBX10U" },
	{ 46,	"100BaseLX10" },
	{ 47,	"1000BaseBX10D" },
	{ 48,	"1000BaseBX10U" },
	{ 49,	"1000BaseLX10" },
	{ 50,	"1000BasePX10D" },
	{ 51,	"1000BasePX10U" },
	{ 52,	"1000BasePX20D" },
	{ 53,	"1000BasePX20U" },
	{ 54,	"10GigBaseT" },
	{ 55,	"10GigBaseLRM" },
	{ 56,	"1000baseKX" },
	{ 57,	"10GigBaseKX4" },
	{ 58,	"10GigBaseKR" },
	{ 59,	"10G/1GbasePRXD1" },
	{ 60,	"10G/1GbasePRXD2" },
	{ 61,	"10G/1GbasePRXD3" },
	{ 62,	"10G/1GbasePRXU1" },
	{ 63,	"10G/1GbasePRXU2" },
	{ 64,	"10G/1GbasePRXU3" },
	{ 65,	"10GigBasePRD1" },
	{ 66,	"10GigBasePRD2" },
	{ 67,	"10GigBasePRD3" },
	{ 68,	"10GigBasePRU1" },
	{ 69,	"10GigBasePRU3" },
	{ 70,	"40GigBaseKR4" },
	{ 71,	"40GigBaseCR4" },
	{ 72,	"40GigBaseSR4" },
	{ 73,	"40GigBaseFR" },
	{ 74,	"40GigBaseLR4" },
	{ 75,	"100GigBaseCR10" },
	{ 76,	"100GigBaseSR10" },
	{ 77,	"100GigBaseLR4" },
	{ 78,	"100GigBaseER4" },
	{ 0, NULL }
};

/* Media Class Values */
static const value_string media_class_values[] = {
	{ 0,	"Type Not Defined" },
	{ 1,	"Endpoint Class I" },
	{ 2,	"Endpoint Class II" },
	{ 3,	"Endpoint Class III" },
	{ 4,	"Network Connectivity" },
	{ 0, NULL }
};

/* Media Subtypes */
static const value_string media_subtypes[] = {
	{ 1,	"Media Cap." },
	{ 2,	"Network Policy" },
	{ 3,	"Location ID" },
	{ 4,	"Power req." },
	{ 5,	"H/W Revision" },
	{ 6,	"F/W Revision" },
	{ 7,	"S/W Revision" },
	{ 8,	"Serial Number" },
	{ 9,	"Manufacturer" },
	{ 10,	"Model Name" },
	{ 11,	"Asset ID" },
	{ 0, NULL }
};

/* Media Application Types */
static const value_string media_application_type[] = {
	{ 0,	"Reserved" },
	{ 1,	"Voice" },
	{ 2,	"Voice Signaling" },
	{ 3,	"Guest Voice" },
	{ 4,	"Guest Voice Signaling" },
	{ 5,	"Softphone Voice" },
	{ 6,	"Video Conferencing" },
	{ 7,	"Streaming Video" },
	{ 8,	"Video Signaling" },
	{ 0, NULL }
};

/* Power Type */
static const value_string media_power_type[] = {
	{ 0,	"PSE Device" },
	{ 1,	"PD Device" },
	{ 2,	"PSE Device" },
	{ 3,	"PD Device" },
	{ 0, NULL }
};

/* Power Priority */
static const value_string media_power_priority[] = {
	{ 0,	"Unknown" },
	{ 1,	"Critical" },
	{ 2,	"High" },
	{ 3,	"Low" },
	{ 0, NULL }
};

/* Power Sources */
static const value_string media_power_pd_device[] = {
	{ 0,	"Unknown" },
	{ 1,	"PSE" },
	{ 2,	"Local" },
	{ 3,	"PSE and Local" },
	{ 0, NULL }
};
static const value_string media_power_pse_device[] = {
	{ 0,	"Unknown" },
	{ 1,	"Primary Power Source" },
	{ 2,	"Backup Power Source" },
	{ 0, NULL }
};

/* Civic Address Type field */
static const value_string civic_address_type_values[] = {
	{ 0,	"Language" },
	{ 1,	"National subdivisions" },
	{ 2,	"County name" },
	{ 3,	"City name" },
	{ 4,	"City division name" },
	{ 5,	"Neighborhood information" },
	{ 6,	"Street group" },
	{ 16,	"Leading street direction" },
	{ 17,	"Trailing street suffix" },
	{ 18,	"Street suffix" },
	{ 19,	"House number" },
	{ 20,	"House number suffix" },
	{ 21,	"Landmark information" },
	{ 22,	"Additional location information" },
	{ 23,	"Resident name" },
	{ 24,	"Postal code" },
	{ 25,	"Building information" },
	{ 26,	"Unit" },
	{ 27,	"Floor number" },
	{ 28,	"Room information" },
	{ 29,	"Place type" },
	{ 30,	"Postal community name" },
	{ 31,	"Post office box" },
	{ 32,	"Additional code" },
	{ 33,	"Seat information" },
	{ 34,	"Primary road name" },
	{ 35,	"Road section" },
	{ 36,	"Branch road name" },
	{ 37,	"Sub-branch road name" },
	{ 38,	"Street name pre-modifier" },
	{ 39,	"Street name post-modifier" },
	{ 128,	"Script" },
	{ 200,  "Administrative Identifier" },
	{ 201,  "Administrative specific location 1" },
	{ 202,  "Administrative specific location 2" },
	{ 203,  "Administrative specific location 3" },
	{ 204,  "Administrative specific location 4" },
	{ 205,  "Administrative specific location 5" },
	{ 206,  "Administrative specific location 6" },
	{ 207,  "Administrative specific location 7" },
	{ 208,  "Administrative specific location 8" },
	{ 209,  "Administrative specific location 9" },
	{ 210,  "Administrative specific location 10" },
	{ 0, NULL }
};

const char *val_to_str_const(int val, const value_string vs[])
{
	int i = 0;
	while (vs[i].strptr) {
		if (vs[i].value == val)
			return(vs[i].strptr);
		i++;
	}
	return NULL;
}

void print_chassis_id(const u_char *v, u_int32_t vlen)
{
	u_int8_t tlvsubType, addr_family;
	
	/* Get tlv subtype */
	tlvsubType = (u_int8_t)*v;
	
	switch (tlvsubType)
	{
	case 4:	/* MAC address */
	{
		dump_hex(v + 1, 6);
		break;
	}
	case 5:	/* Network address */
		printf("\n");
		/* Get network address family */
		addr_family = (u_int8_t)*(v + 1);
		/* Check for IPv4 or IPv6 */
		switch (addr_family) {
		case AFNUM_INET:
			dump_ip(v + 2);
			break;
		case AFNUM_INET6:
			dump_ipv6(v + 2);
			break;
		}
	case 1: /* Chassis component */
	case 2:	/* Interface alias */
	case 3: /* Port component */
	case 6: /* Interface name */
	case 7:	/* Locally assigned */
	default:
		printf("%.*s", vlen - 1, v + 1);
		break;
	}
	printf("\n");
}

void print_port_id(const u_char *v, u_int32_t vlen)
{
	u_int8_t tlvsubType, addr_family;

	/* Get tlv subtype */
	tlvsubType = (u_int8_t)*v;
	
	switch (tlvsubType)
	{
	case 3: /* MAC address */
	{
		dump_hex(v + 1, 6);
		break;
	}
	case 4: /* Network address */
		printf("\n");
		/* Get network address family */
		addr_family = (u_int8_t)*(v + 1);
		/* Check for IPv4 or IPv6 */
		switch (addr_family) {
		case AFNUM_INET:
			dump_ip(v + 2);
			break;
		case AFNUM_INET6:
			dump_ipv6(v + 2);
			break;
		}
	case 1: /* Interface alias */
	case 2: /* Port Component */
	case 5: /* Interface name */
	case 6: /* Agent circuit ID */
	case 7: /* Locally assigned */
	default:
		printf("%.*s", vlen - 1, v + 1);
		break;
	}
	printf("\n");
}

void print_capabilities(const u_char *v)
{
	u_int16_t tempShort = ntohs(get_unaligned((u_int16_t *)v));

	if (tempShort & SYSTEM_CAPABILITY_OTHER) printf("O ");     /* Other */
	if (tempShort & SYSTEM_CAPABILITY_REPEATER) printf("P ");  /* Repeater */
	if (tempShort & SYSTEM_CAPABILITY_BRIDGE) printf("B ");    /* Brdige */
	if (tempShort & SYSTEM_CAPABILITY_WLAN) printf("W ");      /* WLAN Access Point */
	if (tempShort & SYSTEM_CAPABILITY_ROUTER) printf("R ");    /* Router */
	if (tempShort & SYSTEM_CAPABILITY_TELEPHONE) printf("T "); /* Telephone */
	if (tempShort & SYSTEM_CAPABILITY_DOCSIS) printf("C ");    /* DOCSIS Cable Device */
	if (tempShort & SYSTEM_CAPABILITY_STATION) printf("S ");   /* Station */
	printf("\n");
}

void print_management_addr(const u_char *v)
{
	u_int8_t subtypeByte, stringLen = 0;

	/* Get management address string length */
	stringLen = (u_int8_t)*v;

	/* Get management address subtype */
	subtypeByte = (u_int8_t)*(v + 1);

	/* Get address */
	switch (subtypeByte)
	{
	case 1:		/* IPv4 */
		dump_ip(v + 2);
		break;
	case 2:		/* IPv6 */
		dump_ipv6(v + 2);
		break;
	default:
		printf("           Other: ");
		dump_hex(v + 2, stringLen - 1);
	}
	printf("\n");

	// Ignore interface subtype, interface number and OID length and OID string
}

void print_unknown_oui(u_int32_t oui, u_int8_t subType, const u_char *v, u_int32_t vlen)
{
	printf("Unknown OUI\t: %06X\n        Sub Type: %02X\n           Value: ", oui, subType);
	dump_hex(v, vlen);
	printf("\n");

}

u_int8_t print_location_id(const u_char *value, u_int32_t tlvLen)
{
	u_int8_t LCI_Length, offset;
	u_int8_t tempByte;

	switch (*value)
	{
	case 1:	/* Coordinate-based LCI */
	{
		offset = tlvLen;
		printf("    Coordinate-based: ");
		// Not implemented so dump hex
		dump_hex(value + 1, tlvLen - 1);
		printf("\n");
		break;
	}
	case 2: /* Civic Address LCI */
	{
		/* Get LCI length */
		LCI_Length = *(value + 1);
		/* Get what value */
		tempByte = *(value + 2);
		/* Get country code */
		printf("    Country: %.*s\n", 2, value + 3);
		offset = 5;
		while (offset < LCI_Length)
		{
			/* Get CA Type */
			tempByte = *(value + offset);
			printf("    %s: ", val_to_str_const(tempByte, civic_address_type_values));
			offset++;
			/* Get CA Length */
			tempByte = *(value + offset);
			offset++;
			/* Make sure the CA value is within the specified length */
			if (tempByte > LCI_Length)
				return tlvLen;
			/* Get CA Value */
			dump_ascii(value + offset, tempByte);
			offset += tempByte;
			printf("\n");
		}
		break;
	}
	case 3: /* ECS ELIN */
	default:
	{
		offset = tlvLen;
		printf("    ELIN: %.*s\n", tlvLen - 1, value + 1);
		break;
	}
	}
	return offset;
}

void print_organization_specific(const u_char *v, u_int32_t vlen, int verbose, bool *more)
{
	u_int32_t oui;
	u_int8_t subType;
	const u_char *value;
	u_int16_t tlvLen;
	u_int16_t tempShort;
	u_int8_t tempByte;
	u_int32_t tempLong;

	/* Get OUI value */
	oui = ntoh24(get_unaligned((u_int32_t *)v));
	subType = (u_char)*(v + 3);
	value = v + 4;
	tlvLen = vlen - 4;

	switch (oui)
	{
	case OUI_CISCO_2:
		switch (subType)
		{
		case 0x01: /* Four-Wire Power-via-MDI TLV */
			if (verbose > 0) {
				printf("Spare Pair PoE\t: ");
				printf("4-pair PoE %s, ", (*value & 0x01) ? "Supported" : "Not Supported");
				printf("Spare pair Detection/Classification %s, ", (*value & 0x02) ? "required" : "not required");
				printf("PD Spare Pair Desired State %s, ", (*value & 0x04) ? "Enabled" : "Disabled");
				printf("PSE Spare Pair Operational State %s\n", (*value & 0x08) ? "Enabled" : "Disabled");
			}
			break;
		default:
			if (verbose > 1)
				print_unknown_oui(oui, subType, value, tlvLen);
			else
				*more = true;
		}
		break;
	case OUI_IEEE_802_1:
		switch (subType)
		{
		case 0x01:	/* Port VLAN ID */
			printf("VLAN ID\t\t: %d\n", ntohs(get_unaligned((u_int16_t *)value)));
			break;
		default:
			if (verbose > 1)
				print_unknown_oui(oui, subType, value, tlvLen);
			else
				*more = true;
		}
		break;
	case OUI_IEEE_802_3:
		switch (subType)
		{
		case 0x01:	/* MAC/PHY Configuration/Status */
			/* Get auto-negotiation info */
			printf("Auto Negotiation: ");
			printf("%s, ", (*value & 0x01) ? "Supported" : "Not Supported");
			printf("%s\n", (*value & 0x02) ? "Enabled" : "Disabled");
			/* Get pmd auto-negotiation advertised capability */
			tempShort = ntohs(get_unaligned((u_int16_t *)(value + 1)));
			printf("Phys. media cap.: ");
			if (tempShort & AUTONEG_OTHER) printf("Other/unknown ");
			if (tempShort & AUTONEG_10BASE_T) printf("10baseT(HD) ");
			if (tempShort & AUTONEG_10BASET_FD) printf("10baseT(FD) ");
			if (tempShort & AUTONEG_100BASE_T4) printf("100baseT4 ");
			if (tempShort & AUTONEG_100BASE_TX) printf("100baseTX(HD) ");
			if (tempShort & AUTONEG_100BASE_TXFD) printf("100baseTX(FD) ");
			if (tempShort & AUTONEG_100BASE_T2) printf("100baseT2(HD) ");
			if (tempShort & AUTONEG_100BASE_T2FD) printf("100baseT2(FD) ");
			if (tempShort & AUTONEG_FDX_PAUSE) printf("Pause(FD) ");
			if (tempShort & AUTONEG_FDX_APAUSE) printf("Asym Pause(FD) ");
			if (tempShort & AUTONEG_FDX_SPAUSE) printf("Symm Pause(FD) ");
			if (tempShort & AUTONEG_FDX_BPAUSE) printf("Symm, Asymm Pause(FD) ");
			if (tempShort & AUTONEG_1000BASE_X) printf("1000BaseX(HD) ");
			if (tempShort & AUTONEG_1000BASE_XFD) printf("1000BaseX(FD) ");
			if (tempShort & AUTONEG_1000BASE_T) printf("1000BaseT(HD) ");
			if (tempShort & AUTONEG_1000BASE_TFD) printf("1000BaseT(FD) ");
			printf("\n");
			/* Get operational MAU type */
			tempShort = ntohs(get_unaligned((u_int16_t *)(value + 3)));
			printf("MAU type\t: %d (%s)\n", tempShort, val_to_str_const(tempShort, operational_mau_type_values));
			break;
		default:
			if (verbose > 1)
				print_unknown_oui(oui, subType, value, tlvLen);
			else
				*more = true;
		}
		break;
	case OUI_MEDIA_ENDPOINT:
		switch (subType)
		{
		case 1: /* LLDP-MED Capabilities */
			/* Get capabilities */
			tempShort = ntohs(get_unaligned((u_int16_t *)value));
			printf("%s\t: ", val_to_str_const(subType, media_subtypes));
			if (tempShort & MEDIA_CAPABILITY_NETWORK_POLICY) printf("NP ");
			if (tempShort & MEDIA_CAPABILITY_LOCATION_ID) printf("LI ");
			if (tempShort & MEDIA_CAPABILITY_MDI_PSE) printf("PS ");
			if (tempShort & MEDIA_CAPABILITY_MDI_PD) printf("PD ");
			if (tempShort & MEDIA_CAPABILITY_INVENTORY) printf("IN ");
			printf("\n");
			/* Get Class type */
			printf("Device type\t: %s\n", val_to_str_const(*(value + 2), media_class_values));
			break;
		case 2:		/* Network Policy */
		{
			printf("%s\t: %s, ", val_to_str_const(subType, media_subtypes), val_to_str_const(*value, media_application_type));
			tempLong = ntoh24(get_unaligned((u_int32_t *)(value + 1)));
			/* Get flags */
			printf("%s, ", (tempLong & 0x800000) ? "Unknown Policy" : "Known Policy");
			printf("%s, ", (tempLong & 0x400000) ? "Tagged" : "Untagged");
			/* Get vlan id */
			printf("VLAN ID: %u, ", ((tempLong & 0x1ffe00) >> 9));
			/* Get L2 priority */
			printf("L2 priority: %u, ", ((tempLong & 0x1c0) >> 6));
			/* Get DSCP value */
			printf("DSCP: %u\n", (tempLong & 0x3f));
			break;
		}
		case 3:	/* Location Identification */
		{
			printf("%s\t:\n", val_to_str_const(subType, media_subtypes));
			print_location_id(value, tlvLen);
			break;
		}
		case 4: /* Extended Power-via-MDI */
		{
			printf("%s\t: ", val_to_str_const(subType, media_subtypes)); 
			/* Determine power type */
			tempByte = ((*value & 0xC0) >> 6);
			printf("%s, ", val_to_str_const(tempByte, media_power_type));
			/* Determine power source */
			switch (tempByte)
			{
			case 0:
			{
				tempByte = ((*value & 0x30) >> 4);
				printf("Source: %s, ", val_to_str_const(tempByte, media_power_pse_device));
				break;
			}
			case 1:
			{
				tempByte = ((*value & 0x30) >> 4);
				printf("Source: %s, ", val_to_str_const(tempByte, media_power_pd_device));
				break;
			}
			default:
			{
				printf("Source: Unknown, ");
				break;
			}
			}
			/* Determine power priority */
			tempByte = *value & 0xF;
			printf("Power Priority: %s, ", val_to_str_const(tempByte, media_power_priority));
			/* Power Value: 0 to 102.3 Watts (0.1 W increments) */
			tempShort = ntohs(get_unaligned((u_int16_t *)(value + 1)));
			printf("Wattage: %u.%u\n", tempShort / 10, tempShort % 10);
			break;
		}
		case 5:	/* Hardware Revision */
		case 6:	/* Firmware Revision */
		case 7:	/* Software Revision */
		case 8:	/* Serial Number */
		case 9:	/* Manufacturer Name */
		case 10:	/* Model Name */
		case 11:	/* Asset ID */
		{
			printf("%s\t: %.*s\n", val_to_str_const(subType, media_subtypes), tlvLen, value);
			break;
		}
		default:
			if (verbose > 1)
				print_unknown_oui(oui, subType, value, tlvLen);
			else
				*more = true;
		}
		break;
	default:
		if (verbose > 1)
			print_unknown_oui(oui, subType, value, tlvLen);
		else
			*more = true;
	}

}

void print_lldp_packet(const u_char *p, unsigned int plen, int verbose, bool *more)
{
	u_int16_t tempShort;
	u_int8_t tlvType;
	u_int32_t dataLen = 0;
	unsigned int offset = 0;

	/* Get tlv type */
	tempShort = ntohs(get_unaligned((u_int16_t *)p));
	tlvType = TLV_TYPE(tempShort);
	/* Get tlv length */
	dataLen = TLV_INFO_LEN(tempShort);
	offset += sizeof(tempShort);
	/* First TLV must be chassis id */
	if (tlvType != CHASSIS_ID_TLV_TYPE)
		return;
	/* Decode tlv's until end-of-lldpdu is reached */
	while (offset <= plen)
	{
		switch (tlvType)
		{
		case END_OF_LLDPDU_TLV_TYPE:
			printf("%s\n", val_to_str_const(tlvType, tlv_types));
			return;
		case CHASSIS_ID_TLV_TYPE:
			printf("%s\t: ", val_to_str_const(tlvType, tlv_types));
			print_chassis_id(p + offset, dataLen);
			break;
		case PORT_ID_TLV_TYPE:
			printf("%s\t\t: ", val_to_str_const(tlvType, tlv_types)); 
			print_port_id(p + offset, dataLen);
			break;
		case TIME_TO_LIVE_TLV_TYPE:
			tempShort = ntohs(get_unaligned((u_int16_t *)(p + offset)));
			printf("%s\t: %d seconds\n", val_to_str_const(tlvType, tlv_types), tempShort);
			break;
		case PORT_DESCRIPTION_TLV_TYPE:
			printf("%s: %.*s\n", val_to_str_const(tlvType, tlv_types), dataLen, p + offset);
			break;
		case SYSTEM_NAME_TLV_TYPE:
		case SYSTEM_DESCRIPTION_TLV_TYPE:
			printf("%s\t: %.*s\n", val_to_str_const(tlvType, tlv_types), dataLen, p + offset);
			break;
		case SYSTEM_CAPABILITIES_TLV_TYPE:
			printf("%s\t: ", val_to_str_const(tlvType, tlv_types));
			print_capabilities(p + offset);
			printf("Enabled Cap.\t: ");
			print_capabilities(p + offset + 2);
			break;
		case MANAGEMENT_ADDR_TLV_TYPE:
			printf("%s:\n", val_to_str_const(tlvType, tlv_types));
			print_management_addr(p + offset);
			break;
		case ORGANIZATION_SPECIFIC_TLV_TYPE:
			print_organization_specific(p + offset, dataLen, verbose, more);
			break;
		default:
			if (verbose > 1) {
				printf("Unknown TLV\t: %02X\n           Value: ", tlvType);
				dump_hex(p + offset, dataLen);
				printf("\n");
			}
			else
				*more = true;
		}
		offset += dataLen;
		/* Get tlv type */
		tempShort = ntohs(get_unaligned((u_int16_t *)(p + offset)));
		tlvType = TLV_TYPE(tempShort);
		/* Get tlv length */
		dataLen = TLV_INFO_LEN(tempShort);
		offset += sizeof(tempShort);
	}
}
