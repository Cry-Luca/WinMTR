#pragma once

#define VC_EXTRALEAN

#include <intsafe.h>
#include <tchar.h>
#include <process.h>

#include <WinSock2.h>
#include <Ws2tcpip.h>
#include <Iphlpapi.h> //ICMP_ECHO_REPLY

#define WINMTR_VERSION	"1.0"
#define WINMTR_LICENSE	"GPLv2 - GNU General Public License, version 2"
#define WINMTR_HOMEPAGE	"https://github.com/White-Tiger/WinMTR"

#define DEFAULT_PING_SIZE	64
#define DEFAULT_INTERVAL	1.0
#define DEFAULT_MAX_LRU		128
#define DEFAULT_DNS			TRUE
#define DEFAULT_MAX_PING	10

#define SAVED_PINGS 100
#define MaxHost 256
//#define MaxSequence 65536
#define MaxSequence 32767
//#define MaxSequence 5

#define MAXPACKET 4096
#define MINPACKET 64

#define MaxTransit 4

#define ICMP_ECHO		8
#define ICMP_ECHOREPLY		0

#define ICMP_TSTAMP		13
#define ICMP_TSTAMPREPLY	14

#define ICMP_TIME_EXCEEDED	11

#define ICMP_HOST_UNREACHABLE 3

#define MAX_UNKNOWN_HOSTS 10

#define IP_HEADER_LENGTH   20

void TRACE_MSG(const char* format, ...);
void NotifyError(const char* text);

