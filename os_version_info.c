/* os_version_info.c
 * Routines to report operating system version information
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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

#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdio.h>
#include <string.h>
#include <errno.h>

#ifndef _WIN32
#include <sys/utsname.h>
#endif

#if defined(__APPLE_CC__) || defined(__APPLE__)
#include <CoreFoundation/CoreFoundation.h>
#endif

#include "os_version_info.h"

#ifdef _WIN32
#include <Windows.h>

typedef void (WINAPI *nativesi_func_ptr)(LPSYSTEM_INFO);
#endif

/*
 * Handles the rather elaborate process of getting OS version information
 * from OS X (we want the OS X version, not the Darwin version, the latter
 * being easy to get with uname()).
 */
#if defined(__APPLE_CC__) || defined(__APPLE__)
 /*
 * Convert a CFString to a UTF-8-encoded C string; the resulting string
 * is allocated with malloc().  Returns NULL if the conversion fails.
 */
char *
CFString_to_C_string(CFStringRef cfstring)
{
	CFIndex string_len;
	char *string;

	string_len = CFStringGetMaximumSizeForEncoding(CFStringGetLength(cfstring),
		kCFStringEncodingUTF8);
	string = (char *)malloc(string_len + 1);
	if (!CFStringGetCString(cfstring, string, string_len + 1,
		kCFStringEncodingUTF8)) {
		free(string);
		return NULL;
	}
	return string;
}

/*
 * Fetch a string, as a UTF-8 C string, from a dictionary, given a key.
 */
static char *
get_string_from_dictionary(CFPropertyListRef dict, CFStringRef key)
{
	CFStringRef cfstring;

	cfstring = (CFStringRef)CFDictionaryGetValue((CFDictionaryRef)dict,
	    (const void *)key);
	if (cfstring == NULL)
		return NULL;
	if (CFGetTypeID(cfstring) != CFStringGetTypeID()) {
		/* It isn't a string.  Punt. */
		return NULL;
	}
	return CFString_to_C_string(cfstring);
}

/*
 * Get the OS X version information, and append it to the char.
 * Return TRUE if we succeed, FALSE if we fail.
 */
static Boolean
get_os_x_version_info(char *str)
{
	static const UInt8 server_version_plist_path[] =
	    "/System/Library/CoreServices/ServerVersion.plist";
	static const UInt8 system_version_plist_path[] =
	    "/System/Library/CoreServices/SystemVersion.plist";
	CFURLRef version_plist_file_url;
	CFReadStreamRef version_plist_stream;
	CFDictionaryRef version_dict;
	char *string;

	/*
	 * On OS X, report the OS X version number as the OS, and put
	 * the Darwin information in parentheses.
	 *
	 * Alas, Gestalt() is deprecated in Mountain Lion, so the build
	 * fails if you treat deprecation warnings as fatal.  I don't
	 * know of any replacement API, so we fall back on reading
	 * /System/Library/CoreServices/ServerVersion.plist if it
	 * exists, otherwise /System/Library/CoreServices/SystemVersion.plist,
	 * and using ProductUserVisibleVersion.  We also get the build
	 * version from ProductBuildVersion and the product name from
	 * ProductName.
	 */
	version_plist_file_url = CFURLCreateFromFileSystemRepresentation(NULL,
	    server_version_plist_path, sizeof server_version_plist_path - 1,
	    false);
	if (version_plist_file_url == NULL)
		return FALSE;
	version_plist_stream = CFReadStreamCreateWithFile(NULL,
	    version_plist_file_url);
	CFRelease(version_plist_file_url);
	if (version_plist_stream == NULL)
		return FALSE;
	if (!CFReadStreamOpen(version_plist_stream)) {
		CFRelease(version_plist_stream);

		/*
		 * Try SystemVersion.plist.
		 */
		version_plist_file_url = CFURLCreateFromFileSystemRepresentation(NULL,
		    system_version_plist_path, sizeof system_version_plist_path - 1,
		    false);
		if (version_plist_file_url == NULL)
			return FALSE;
		version_plist_stream = CFReadStreamCreateWithFile(NULL,
		    version_plist_file_url);
		CFRelease(version_plist_file_url);
		if (version_plist_stream == NULL)
			return FALSE;
		if (!CFReadStreamOpen(version_plist_stream)) {
			CFRelease(version_plist_stream);
			return FALSE;
		}
	}
#ifdef CFPROPERTYLISTCREATEWITHSTREAM
	version_dict = (CFDictionaryRef)CFPropertyListCreateWithStream(NULL,
	    version_plist_stream, 0, kCFPropertyListImmutable,
	    NULL, NULL);
#else
	version_dict = (CFDictionaryRef)CFPropertyListCreateFromStream(NULL,
	    version_plist_stream, 0, kCFPropertyListImmutable,
	    NULL, NULL);
#endif
	if (version_dict == NULL) {
		CFRelease(version_plist_stream);
		return FALSE;
	}
	if (CFGetTypeID(version_dict) != CFDictionaryGetTypeID()) {
		/* This is *supposed* to be a dictionary.  Punt. */
		CFRelease(version_dict);
		CFReadStreamClose(version_plist_stream);
		CFRelease(version_plist_stream);
		return FALSE;
	}
	/* Get the product name string. */
	string = get_string_from_dictionary(version_dict,
	    CFSTR("ProductName"));
	if (string == NULL) {
		CFRelease(version_dict);
		CFReadStreamClose(version_plist_stream);
		CFRelease(version_plist_stream);
		return FALSE;
	}
	sprintf(str + strlen(str), "%s", string);
	free(string);

	/* Get the OS version string. */
	string = get_string_from_dictionary(version_dict,
	    CFSTR("ProductUserVisibleVersion"));
	if (string == NULL) {
		CFRelease(version_dict);
		CFReadStreamClose(version_plist_stream);
		CFRelease(version_plist_stream);
		return FALSE;
	}
	sprintf(str + strlen(str), " %s", string);
	free(string);

	/* Get the build string */
	string = get_string_from_dictionary(version_dict,
	    CFSTR("ProductBuildVersion"));
	if (string == NULL) {
		CFRelease(version_dict);
		CFReadStreamClose(version_plist_stream);
		CFRelease(version_plist_stream);
		return FALSE;
	}
	sprintf(str + strlen(str), ", build %s", string);
	free(string);
	CFRelease(version_dict);
	CFReadStreamClose(version_plist_stream);
	CFRelease(version_plist_stream);
	return TRUE;
}
#endif

/*
 * Get the OS version, and append it to the char
 */
void
get_os_version_info(char *str)
{
#if defined(_WIN32)
	SYSTEM_INFO system_info;
	nativesi_func_ptr nativesi_func;
#else
	struct utsname name;
#endif

#if defined(_WIN32)
	memset(&system_info, '\0', sizeof system_info);
	/* Look for and use the GetNativeSystemInfo() function if available to get the correct processor
	* architecture even when running 32-bit Wireshark in WOW64 (x86 emulation on 64-bit Windows) */
	nativesi_func = (nativesi_func_ptr)GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "GetNativeSystemInfo");
	if (nativesi_func)
		nativesi_func(&system_info);
	else
		GetSystemInfo(&system_info);

	LONG(WINAPI *pfnRtlGetVersion)(RTL_OSVERSIONINFOEXW*);
	(FARPROC)pfnRtlGetVersion = GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "RtlGetVersion");
	if (pfnRtlGetVersion)
	{
		RTL_OSVERSIONINFOEXW ver = { 0 };
		ver.dwOSVersionInfoSize = sizeof(ver);

		if (pfnRtlGetVersion(&ver) == 0)
		{
			if (ver.dwMajorVersion == 5) {
				if (ver.dwMinorVersion == 0)
					sprintf(str, "Microsoft Windows 2000");
				else if (ver.dwMinorVersion == 1)
					sprintf(str, "Microsoft Windows XP");
				else if (ver.dwMinorVersion == 2)
					if (ver.wProductType == VER_NT_WORKSTATION)
						sprintf(str, "Microsoft Windows XP Professional x64 Edition");
					else if (ver.wSuiteMask == VER_SUITE_WH_SERVER)
						sprintf(str, "Microsoft Windows Home Server");
					else
						sprintf(str, "Microsoft Windows Server 2003");
				else
					sprintf(str, "Microsoft Windows");
			}
			else if (ver.dwMajorVersion == 6) {
				if (ver.dwMinorVersion == 0)
					if (ver.wProductType == VER_NT_WORKSTATION)
						sprintf(str, "Microsoft Windows Vista");
					else
						sprintf(str, "Microsoft Windows Server 2008");
				else if (ver.dwMinorVersion == 1)
					if (ver.wProductType == VER_NT_WORKSTATION)
						sprintf(str, "Microsoft Windows 7");
					else
						sprintf(str, "Microsoft Windows Server 2008 R2");
				else if (ver.dwMinorVersion == 2)
					if (ver.wProductType == VER_NT_WORKSTATION)
						sprintf(str, "Microsoft Windows 8");
					else
						sprintf(str, "Microsoft Windows Server 2012");
				else if (ver.dwMinorVersion == 3)
					if (ver.wProductType == VER_NT_WORKSTATION)
						sprintf(str, "Microsoft Windows 8.1");
					else
						sprintf(str, "Microsoft Windows Server 2012 R2");
				else
					sprintf(str, "Microsoft Windows");
				if (system_info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
					sprintf(str + strlen(str), " 64-bit");
				else if (system_info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
					sprintf(str + strlen(str), " 32-bit");
			}
			else if (ver.dwMajorVersion == 10) {
				if (ver.dwMinorVersion == 0)
					if (ver.wProductType == VER_NT_WORKSTATION)
						sprintf(str, "Microsoft Windows 10");
					else
						sprintf(str, "Microsoft Windows Server 2016");
				else
					sprintf(str, "Microsoft Windows");
				if (system_info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
					sprintf(str + strlen(str), " 64-bit");
				else if (system_info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
					sprintf(str + strlen(str), " 32-bit");
			}
			else
				sprintf(str, "Microsoft Windows");
			if (wcslen(ver.szCSDVersion))
				sprintf(str + strlen(str), " %ws", ver.szCSDVersion);
			sprintf(str + strlen(str), " [Version %ld.%ld.%ld]", ver.dwMajorVersion, ver.dwMinorVersion, ver.dwBuildNumber);
		}
	}
#else
	/*
	 * We have <sys/utsname.h>, so we assume we have "uname()".
	 */
	if (uname(&name) < 0) {
		sprintf(str + strlen(str), "unknown OS version (uname failed - %s)",
		    strerror(errno));
		return;
	}

	if (strcmp(name.sysname, "AIX") == 0) {
		/*
		 * Yay, IBM!  Thanks for doing something different
		 * from most of the other UNIXes out there, and
		 * making "name.version" apparently be the major
		 * version number and "name.release" be the minor
		 * version number.
		 */
		sprintf(str + strlen(str), "%s %s.%s", name.sysname, name.version,
		    name.release);
	} else {
		/*
		 * XXX - get "version" on any other platforms?
		 *
		 * On Digital/Tru64 UNIX, it's something unknown.
		 * On Solaris, it's some kind of build information.
		 * On HP-UX, it appears to be some sort of subrevision
		 * thing.
		 * On *BSD and Darwin/OS X, it's a long string giving
		 * a build date, config file name, etc., etc., etc..
		 */
#if defined(__APPLE_CC__) || defined(__APPLE__)
		/*
		 * On Mac OS X, report the Mac OS X version number as
		 * the OS version if we can, and put the Darwin information
		 * in parentheses.
		 */
		if (get_os_x_version_info(str)) {
			/* Success - append the Darwin information. */
			sprintf(str + strlen(str), " (%s %s)", name.sysname, name.release);
		} else {
			/* Failure - just use the Darwin information. */
			sprintf(str + strlen(str), "%s %s", name.sysname, name.release);
		}
#else
		/*
		 * XXX - on Linux, are there any APIs to get the distribution
		 * name and version number?  I think some distributions have
		 * that.
		 *
		 * At least on Linux Standard Base-compliant distributions,
		 * there's an "lsb_release" command.  However:
		 *
		 *	http://forums.fedoraforum.org/showthread.php?t=220885
		 *
		 * seems to suggest that if you don't have the redhat-lsb
		 * package installed, you don't have lsb_release, and that
		 * /etc/fedora-release has the release information on
		 * Fedora.
		 *
		 *	http://linux.die.net/man/1/lsb_release
		 *
		 * suggests that there's an /etc/distrib-release file, but
		 * it doesn't indicate whether "distrib" is literally
		 * "distrib" or is the name for the distribution, and
		 * also speaks of an /etc/debian_version file.
		 *
		 * "lsb_release" apparently parses /etc/lsb-release, which
		 * has shell-style assignments, assigning to, among other
		 * values, DISTRIB_ID (distributor/distribution name),
		 * DISTRIB_RELEASE (release number of the distribution),
		 * DISTRIB_DESCRIPTION (*might* be name followed by version,
		 * but the manpage for lsb_release seems to indicate that's
		 * not guaranteed), and DISTRIB_CODENAME (code name, e.g.
		 * "licentious" for the Ubuntu Licentious Lemur release).
		 * the lsb_release man page also speaks of the distrib-release
		 * file, but Debian doesn't have one, and Ubuntu 7's
		 * lsb_release command doesn't look for one.
		 *
		 * I've seen references to /etc/redhat-release as well.
		 *
		 * At least on my Ubuntu 7 system, /etc/debian_version
		 * doesn't contain anything interesting (just some Debian
		 * codenames).
		 *
		 * See also
		 *
		 *	http://bugs.python.org/issue1322
		 *
		 *	http://www.novell.com/coolsolutions/feature/11251.html
		 *
		 *	http://linuxmafia.com/faq/Admin/release-files.html
		 *
		 * and the Lib/Platform.py file in recent Python 2.x
		 * releases.
		 */
		sprintf(str + strlen(str), "%s %s", name.sysname, name.release);
#endif
	}
#endif
}

