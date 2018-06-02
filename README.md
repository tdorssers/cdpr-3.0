# cdpr - Cisco Discovery Protocol Reporter
Copyright (c) 2002-2010 MonkeyMental.com

Copyright (c) 2015 Tim Dorssers

The default behaviour is to send a CDP trigger packet on startup (unless -s is
specified) and send a regular CDP packet every minute. After one CDP packet has
been received, the program will quit unless -c is specified. All available
Ethernet interfaces on a host are used for sending and receiving, unless -i or
-d is specified. Use -l to see what adapters are available to specify using -d.
After 300 seconds the program will quit, unless specified otherwise using -t.
Regular TLVs are reported by default and all known TLVs are reported by
specifying -v. Unknown TLVs are also reported by specifying -vv.

libpcap 0.9.1 or later required for pcap_sendpacket support.

cdpr has been compiled and tested on the following Operating Systems:

* Windows 8.1 and 10 using Visual Studio 2015 on [x86]
* Linux 3.10.0 and 3.19.0 using gcc 4.8 on [x86_64]
* Mac OS X 10.11 using gcc 4.2 on [x86_64]
* Oracle Solaris 11.3 using gcc 4.8 on [x86_64]
* FreeBSD 10.2 using gcc 4.8 on [x86_64]
* Linux 2.6.18 using gcc 4.1 on [sparc]
* Linux 3.2.0 using gcc 3.6 on [armv7l] [mips64] [ppc]
* NetBSD 7.0 using gcc 4.8 on [sparc64]

## Command line options

```
-s: Silent mode; do not send CDP packet
-c: Continuous capture; does not stop upon first reception
-i: Interactive mode; lets user pick a device to listen on
-l: Lists devices
-d: Specify device to use (eth0, hme0, etc.)
-h: Print usage
-t: Time in seconds to abort waiting for packets (default is 300)
-v[vv]: Set verbose mode
```

## Compile instructions for Windows

To build it from source download the WinPcap Developers Pack unzip it into the
cdpr source tree. Your directory structure should looks something like this:

```
\cdpr-3.0
 +-WpdPack
  +-docs
  +-Examples
  +-Include
  +-Lib
```

## Version History

3.0.0

* Forked MonkeyMental.com's version 2.4 code 
* Removed the functionality to report CDP data back to a centralized server
* Added all known TLVs and CDP capabilities, supporting Nexus switches
* Added more TLV decoding functionality to the print_cdp_packet routine
* Added the CDP send module to send a VLAN request to a Catalyst switch to
  trigger a CDP advertisement
* Added multiple interface support; send and receive on all Ethernet interfaces
  on a host
* Added friendly interface name support under Win32
* Changed behaviour to quit the application after reception of a CDP packet

3.0.1

* Added IPv6 support to the CDP send module
* Added support for CPU architectures that require memory alignment to the CDP
  send module

3.0.2
* Added IPv6 support to the CDP send module

3.0.3
* Added LLDP reporting support
* Added LLDP to send module to trigger advertisements
