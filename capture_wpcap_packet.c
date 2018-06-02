/* capture_wpcap_packet.c
 * WinPcap-specific interfaces for low-level information (packet.dll).
 * We load WinPcap at run time, so that we only need one binary
 * for Windows, regardless of whether WinPcap is installed or not.
 *
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * Modified by Tim Dorssers
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#if defined _WIN32

#include <pcap.h>
#include <winsock2.h>    /* Needed here to force a definition of WINVER           */
                         /* for some (all ?) Microsoft compilers newer than vc6.  */
                         /* (If windows.h were used instead, there might be       */
                         /*  issues re winsock.h included before winsock2.h )     */
#include <windowsx.h>
#include <Ntddndis.h>
#include "capture_wpcap_packet.h"

/* packet32.h requires sockaddr_storage
 * whether sockaddr_storage is defined or not depends on the Platform SDK
 * version installed. The only one not defining it is the SDK that comes
 * with MSVC 6.0 (WINVER 0x0400).
 *
 * copied from RFC2553
 * XXX - defined more than once, move this to a header file */
#ifndef WINVER
#error WINVER not defined ....
#endif
#if (WINVER <= 0x0400) && defined(_MSC_VER)
typedef unsigned short eth_sa_family_t;

/*
 * Desired design of maximum size and alignment
 */
#define ETH_SS_MAXSIZE    128  /* Implementation specific max size */
#define ETH_SS_ALIGNSIZE  (sizeof (int64_t))
                         /* Implementation specific desired alignment */
/*
 * Definitions used for sockaddr_storage structure paddings design.
 */
#define ETH_SS_PAD1SIZE   (ETH_SS_ALIGNSIZE - sizeof (eth_sa_family_t))
#define ETH_SS_PAD2SIZE   (ETH_SS_MAXSIZE - (sizeof (eth_sa_family_t) + \
                              ETH_SS_PAD1SIZE + ETH_SS_ALIGNSIZE))

struct sockaddr_storage {
    eth_sa_family_t  __ss_family;     /* address family */
    /* Following fields are implementation specific */
    char      __ss_pad1[ETH_SS_PAD1SIZE];
              /* 6 byte pad, this is to make implementation */
              /* specific pad up to alignment field that */
              /* follows explicit in the data structure */
    int64_t   __ss_align;     /* field to force desired structure */
               /* storage alignment */
    char      __ss_pad2[ETH_SS_PAD2SIZE];
              /* 112 byte pad to achieve desired size, */
              /* _SS_MAXSIZE value minus size of ss_family */
              /* __ss_pad1, __ss_align fields is 112 */
};
/* ... copied from RFC2553 */
#endif /* WINVER */

#include <Packet32.h>

boolean has_wpacket = FALSE;


/******************************************************************************************************************************/
/* stuff to load WinPcap's packet.dll and the functions required from it */

typedef PCHAR(*PPACKETGETVERSION)(void);
typedef LPADAPTER(*PPACKETOPENADAPTER) (LPTSTR);
typedef void(*PPACKETCLOSEADAPTER) (LPADAPTER);
typedef BOOLEAN(*PPACKETREQUEST) (LPADAPTER, int, void *);
typedef BOOLEAN(*PPACKETGETNETINFOEX) (LPTSTR, npf_if_addr *, PLONG);

static PPACKETGETVERSION p_PacketGetVersion;
static PPACKETOPENADAPTER p_PacketOpenAdapter;
static PPACKETCLOSEADAPTER p_PacketCloseAdapter;
static PPACKETREQUEST p_PacketRequest;
static PPACKETGETNETINFOEX p_PacketGetNetInfoEx;

void
wpcap_packet_load(void)
{

	HMODULE wh;
	//char *ptr;

	/* Load packet.dll */
	wh = LoadLibrary(TEXT("packet.dll"));
	if (wh == NULL) {
		/* Load failed */
		return;
	}

	/* These are the symbols I need or want from packet.dll */
	p_PacketGetVersion = (PPACKETGETVERSION)GetProcAddress(wh, "PacketGetVersion");
	if (p_PacketGetVersion == NULL) {
		/*
		* We require this symbol.
		*/
		return;
	}
	p_PacketOpenAdapter = (PPACKETOPENADAPTER)GetProcAddress(wh, "PacketOpenAdapter");
	if (p_PacketOpenAdapter == NULL) {
		/*
		* We require this symbol.
		*/
		return;
	}
	p_PacketCloseAdapter = (PPACKETCLOSEADAPTER)GetProcAddress(wh, "PacketCloseAdapter");
	if (p_PacketCloseAdapter == NULL) {
		/*
		* We require this symbol.
		*/
		return;
	}
	p_PacketRequest = (PPACKETREQUEST)GetProcAddress(wh, "PacketRequest");
	if (p_PacketRequest == NULL) {
		/*
		* We require this symbol.
		*/
		return;
	}
	p_PacketGetNetInfoEx = (PPACKETGETNETINFOEX)GetProcAddress(wh, "PacketGetNetInfoEx");
	if (p_PacketGetNetInfoEx == NULL) {
		/*
		* We require this symbol.
		*/
		return;
	}

    has_wpacket = TRUE;
}



/******************************************************************************************************************************/
/* functions to access the NDIS driver values */

int
wpcap_packet_get_net_info(char *if_name, PULONG netp, PULONG maskp)
{
	npf_if_addr buffer;
	LONG NEntries = 1;

	if (!has_wpacket) {
		return 0;
	}

	if (p_PacketGetNetInfoEx(if_name, &buffer, &NEntries)) {
		memcpy(netp, &((struct sockaddr_in *)&buffer.IPAddress)->sin_addr.s_addr, sizeof(netp));
		memcpy(maskp, &((struct sockaddr_in *)&buffer.IPAddress)->sin_addr.s_addr, sizeof(maskp));
		return 1;
	}
	else
		return 0;
}

/* get dll version */
char *
wpcap_packet_get_version(void)
{
    if(!has_wpacket) {
        return NULL;
    }
    return p_PacketGetVersion();
}


/* open the interface */
void *
wpcap_packet_open(char *if_name)
{
    LPADAPTER   adapter;

	if (!has_wpacket) {
		return NULL;
	}
    adapter = p_PacketOpenAdapter(if_name);

    return adapter;
}


/* close the interface */
void
wpcap_packet_close(void *adapter)
{
	if (!has_wpacket) {
		return;
	}
    p_PacketCloseAdapter(adapter);
}


/* do a packet request call */
int
wpcap_packet_request(void *adapter, ULONG Oid, int set, char *value, unsigned int *length)
{
    BOOLEAN    Status;
    ULONG      IoCtlBufferLength=(sizeof(PACKET_OID_DATA) + (*length) - 1);
    PPACKET_OID_DATA  OidData;

	if (!has_wpacket) {
		return 0;
	}

    if(p_PacketRequest == NULL) {
		fprintf(stderr, "packet_request not available\n");
        return 0;
    }

    /* get a buffer suitable for PacketRequest() */
    OidData=GlobalAllocPtr(GMEM_MOVEABLE | GMEM_ZEROINIT,IoCtlBufferLength);
    if (OidData == NULL) {
		fprintf(stderr, "GlobalAllocPtr failed for %u\n", IoCtlBufferLength);
        return 0;
    }

    OidData->Oid = Oid;
    OidData->Length = *length;
    memcpy(OidData->Data, value, *length);

    Status = p_PacketRequest(adapter, set, OidData);

    if(Status) {
        if(OidData->Length <= *length) {
            /* copy value from driver */
            memcpy(value, OidData->Data, OidData->Length);
            *length = OidData->Length;
        } else {
            /* the driver returned a value that is longer than expected (and longer than the given buffer) */
			fprintf(stderr, "returned oid too long, Oid: 0x%x OidLen:%u MaxLen:%u", Oid, OidData->Length, *length);
            Status = FALSE;
        }
    }

    GlobalFreePtr (OidData);

    if(Status) {
        return 1;
    } else {
        return 0;
    }
}


/* get an UINT value using the packet request call */
int
wpcap_packet_request_uint(void *adapter, ULONG Oid, UINT *value)
{
    BOOLEAN Status;
    unsigned int length = sizeof(UINT);


    Status = wpcap_packet_request(adapter, Oid, FALSE /* !set */, (char *) value, &length);
    if(Status && length == sizeof(UINT)) {
        return 1;
    } else {
        return 0;
    }
}


/* get an ULONG value using the NDIS packet request call */
int
wpcap_packet_request_ulong(void *adapter, ULONG Oid, ULONG *value)
{
    BOOLEAN Status;
    unsigned int length = sizeof(ULONG);


    Status = wpcap_packet_request(adapter, Oid, FALSE /* !set */, (char *) value, &length);
    if(Status && length == sizeof(ULONG)) {
        return 1;
    } else {
        return 0;
    }
}


#endif _WIN32 */
