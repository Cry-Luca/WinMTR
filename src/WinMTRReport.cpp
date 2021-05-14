#include <cstdlib>
#include <cstdio>
#include <cstdarg>
#include <functional>

#include <intsafe.h>
#include <WinSock2.h>
#include <Ws2tcpip.h>
#include <Iphlpapi.h> //ICMP_ECHO_REPLY

#ifndef NDEBUG
const char* test_hostname = "capi1-lv-lw-wc.huntshowdown.com";
const char* localhost = "FRWP1LUCA";
#endif

constexpr int RET_FAIL = EXIT_FAILURE;
constexpr int RET_OK = EXIT_SUCCESS;

// mtr equivalent: -c, --report-cycles COUNT  set the number of pings sent
constexpr size_t DEFAULT_REPORT_CYCLES = 10; // default: 10
// from mtr: max stats fields to display
constexpr size_t MAXFLD = 7;

//#include "WinMTRGlobal.h"
constexpr size_t MaxHost = 256;
constexpr WORD DEFAULT_PING_SIZE = 64;
constexpr double DEFAULT_INTERVAL = 1.0;

void LogVerboseV(const char* format, va_list args)
{
	vfprintf(stdout, format, args);
	fprintf(stdout, "\n");
}

void LogErrorV(const char* format, va_list args)
{
	vfprintf(stderr, format, args);
	fprintf(stderr, "\n");
}

void LogError(const char* format, ...)
{
	va_list args;
	va_start(args, format);
	LogErrorV(format, args);
	va_end(args);
}

void LogVerbose(const char* format, ...)
{
	va_list args;
	va_start(args, format);
	LogVerboseV(format, args);
	va_end(args);
}

void Log(const char* format, ...)
{
	va_list args;
	va_start(args, format);
	vfprintf(stdout, format, args);
	fprintf(stdout, "\n");
	va_end(args);
}

// Copied from WinMTRNet.h

class WinMTRNet;

typedef IP_OPTION_INFORMATION IPINFO, * PIPINFO, FAR* LPIPINFO;
#ifdef _WIN64
typedef ICMP_ECHO_REPLY32 ICMPECHO, * PICMPECHO, FAR* LPICMPECHO;
#else
typedef ICMP_ECHO_REPLY ICMPECHO, * PICMPECHO, FAR* LPICMPECHO;
#endif // _WIN64

#define ECHO_REPLY_TIMEOUT 5000

struct s_nethost {
	sockaddr_in addr;
	int xmit;			// number of PING packets sent
	int returned;		// number of ICMP echo replies received
	unsigned long total;	// total time
	int last;				// last time
	int best;				// best time
	int worst;			// worst time
	char name[255];
};

// Based on trace_thread from WinMTRNet.cpp
struct trace_thread
{
	WinMTRNet* winmtr;
	in_addr		address;
	int			ttl;
};

// Based on dns_resolver_thread from WinMTRNet.cpp
struct dns_resolver_thread {
	WinMTRNet* winmtr;
	int			index;
};

// From WinMTRNet.cpp
constexpr unsigned char IPFLAG_DONT_FRAGMENT = 0x02;
constexpr int MAX_HOPS = 30;

class WinMTRNet
{
	typedef FARPROC PIO_APC_ROUTINE;//not the best way to do it, but works ;) (we do not use it anyway)

	typedef HANDLE(WINAPI* LPFNICMPCREATEFILE)(VOID);
	typedef BOOL(WINAPI* LPFNICMPCLOSEHANDLE)(HANDLE);
	typedef DWORD(WINAPI* LPFNICMPSENDECHO2)(HANDLE IcmpHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, in_addr DestinationAddress, LPVOID RequestData, WORD RequestSize, PIP_OPTION_INFORMATION RequestOptions, LPVOID ReplyBuffer, DWORD ReplySize, DWORD Timeout);

public:


	WinMTRNet()
	{
		ghMutex = CreateMutex(NULL, FALSE, NULL);
		//tracing = false;
		initialized = false;

		WSADATA wsaData;

		if (WSAStartup(MAKEWORD(2, 2), &wsaData)) {
			LogError("Failed initializing windows sockets library!");
			return;
		}
		OSVERSIONINFOEX osvi = { 0 };
		osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
		if (!GetVersionEx((OSVERSIONINFO*)&osvi)) {
			LogError("Failed to get Windows version!");
			return;
		}
		if (osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 0) { //w2k
			hICMP_DLL = LoadLibrary("ICMP.DLL");
			if (!hICMP_DLL) {
				LogError("Failed: Unable to locate ICMP.DLL!");
				return;
			}
		}
		else {
			hICMP_DLL = LoadLibrary("Iphlpapi.dll");
			if (!hICMP_DLL) {
				LogError("Failed: Unable to locate Iphlpapi.dll!");
				return;
			}
		}

		/*
		 * Get pointers to ICMP.DLL functions
		 */
		 //IPv4
		lpfnIcmpCreateFile = (LPFNICMPCREATEFILE)GetProcAddress(hICMP_DLL, "IcmpCreateFile");
		lpfnIcmpCloseHandle = (LPFNICMPCLOSEHANDLE)GetProcAddress(hICMP_DLL, "IcmpCloseHandle");
		lpfnIcmpSendEcho2 = (LPFNICMPSENDECHO2)GetProcAddress(hICMP_DLL, "IcmpSendEcho2");
		if (!lpfnIcmpCreateFile || !lpfnIcmpCloseHandle || !lpfnIcmpSendEcho2) {
			LogError("Wrong ICMP system library !");
			return;
		}

		/*
		 * IcmpCreateFile() - Open the ping service
		 */
		hICMP = (HANDLE)lpfnIcmpCreateFile();
		if (hICMP == INVALID_HANDLE_VALUE) {
			LogError("Error in ICMP module!");
			return;
		}

		ResetHops();

		initialized = true;
		return;
	}

	~WinMTRNet()
	{
		if (initialized) {
			/*
			 * IcmpCloseHandle - Close the ICMP handle
			 */
			lpfnIcmpCloseHandle(hICMP);

			// Shut down...
			FreeLibrary(hICMP_DLL);

			WSACleanup();

			CloseHandle(ghMutex);
		}
	}

	void	DoTrace(sockaddr* sockaddr);
	void	ResetHops();
	void	StopTrace();

	sockaddr* GetAddr(int at);
	int		GetName(int at, char* n);
	int		GetBest(int at);
	int		GetWorst(int at);
	int		GetAvg(int at);
	int		GetPercent(int at);
	int		GetLast(int at);
	int		GetReturned(int at);
	int		GetXmit(int at);
	int		GetMax();
	void	SetAddr(int at, u_long addr);
	void	SetAddr6(int at, IPV6_ADDRESS_EX addrex);
	void	SetName(int at, char* n);
	void	SetErrorName(int at, DWORD errnum);
	void	UpdateRTT(int at, int rtt);
	void	AddReturned(int at);
	void	AddXmit(int at);

	in_addr last_remote_addr;
	static constexpr bool			hasIPv6 = false;
	static constexpr unsigned char	useIPv6 = 0;
	//bool					tracing;
	bool					initialized;
	HANDLE					hICMP;

	LPFNICMPCREATEFILE lpfnIcmpCreateFile;
	LPFNICMPCLOSEHANDLE lpfnIcmpCloseHandle;
	LPFNICMPSENDECHO2 lpfnIcmpSendEcho2;

	HINSTANCE			hICMP_DLL;

	struct s_nethost	host[MaxHost];
	HANDLE				ghMutex;

	// From WinMTRDialog
	int Ping(const char* hostname);

	// From WinMTRNet.cpp
	void DnsResolver(dns_resolver_thread* dnt);

	double				interval = DEFAULT_INTERVAL;
	WORD				pingsize = DEFAULT_PING_SIZE;
};

// Based on TraceThread(void* p) from WinMTRNet.cpp
void TraceThread(const trace_thread* current)
{
	LogVerbose("Thread with TTL=%d started", current->ttl);
	WinMTRNet* wmtrnet = current->winmtr;

	IPINFO			stIPInfo, * lpstIPInfo;
	char			achReqData[8192];
	WORD			nDataLen = wmtrnet->pingsize;
	union {
		ICMP_ECHO_REPLY icmp_echo_reply;
		char achRepData[sizeof(ICMPECHO) + 8192];
	};

	lpstIPInfo = &stIPInfo;
	stIPInfo.Ttl = (UCHAR)current->ttl;
	stIPInfo.Tos = 0;
	stIPInfo.Flags = IPFLAG_DONT_FRAGMENT;
	stIPInfo.OptionsSize = 0;
	stIPInfo.OptionsData = NULL;
	
	for (int i = 0; i < nDataLen; ++i) achReqData[i] = 32; //whitespaces
	
	for (size_t cycle = 0; cycle < DEFAULT_REPORT_CYCLES; cycle++)
	{
		// For some strange reason, ICMP API is not filling the TTL for icmp echo reply
		// Check if the current thread should be closed
		if (current->ttl > wmtrnet->GetMax()) break;
		// NOTE: some servers does not respond back everytime, if TTL expires in transit; e.g. :
		// ping -n 20 -w 5000 -l 64 -i 7 www.chinapost.com.tw  -> less that half of the replies are coming back from 219.80.240.93
		// but if we are pinging ping -n 20 -w 5000 -l 64 219.80.240.93  we have 0% loss
		// A resolution would be:
		// - as soon as we get a hop, we start pinging directly that hop, with a greater TTL
		// - a drawback would be that, some servers are configured to reply for TTL transit expire, but not to ping requests, so,
		// for these servers we'll have 100% loss
		DWORD dwReplyCount = wmtrnet->lpfnIcmpSendEcho2(wmtrnet->hICMP, 0, NULL, NULL, current->address, achReqData, nDataLen, lpstIPInfo, achRepData, sizeof(achRepData), ECHO_REPLY_TIMEOUT);
		wmtrnet->AddXmit(current->ttl - 1);
		if (dwReplyCount) {
			LogVerbose("TTL %d reply TTL %d Status %d Reply count %d", current->ttl, icmp_echo_reply.Options.Ttl, icmp_echo_reply.Status, dwReplyCount);
			switch (icmp_echo_reply.Status) {
			case IP_SUCCESS:
			case IP_TTL_EXPIRED_TRANSIT:
				wmtrnet->UpdateRTT(current->ttl - 1, icmp_echo_reply.RoundTripTime);
				wmtrnet->AddReturned(current->ttl - 1);
				wmtrnet->SetAddr(current->ttl - 1, icmp_echo_reply.Address);
				break;
			default:
				wmtrnet->SetErrorName(current->ttl - 1, icmp_echo_reply.Status);
			}
			if ((DWORD)(wmtrnet->interval * 1000) > icmp_echo_reply.RoundTripTime)
				Sleep((DWORD)(wmtrnet->interval * 1000) - icmp_echo_reply.RoundTripTime);
		}
		else {
			DWORD err = GetLastError();
			wmtrnet->SetErrorName(current->ttl - 1, err);
			switch (err) {
			case IP_REQ_TIMED_OUT: break;
			default:
				Sleep((DWORD)(wmtrnet->interval * 1000));
			}
		}
	}//end loop
	LogVerbose("Thread with TTL=%d stopped.", current->ttl);
}

void WinMTRNet::DoTrace(sockaddr* sockaddr)
{
	unsigned char hops = 0;
	ResetHops();
	
	host[0].addr.sin_family = AF_INET;
	last_remote_addr = ((sockaddr_in*)sockaddr)->sin_addr;
	for (; hops < MAX_HOPS;) 
	{
		trace_thread current;
		current.address = ((sockaddr_in*)sockaddr)->sin_addr;
		current.winmtr = this;
		current.ttl = hops + 1;
		TraceThread(&current);
		if (++hops > this->GetMax()) break;
	}
}

void WinMTRNet::ResetHops()
{
	memset(host, 0, sizeof(host));
}

sockaddr* WinMTRNet::GetAddr(int at)
{
	return (sockaddr*)&host[at].addr;
}

void WinMTRNet::SetAddr(int at, u_long addr)
{
	WaitForSingleObject(ghMutex, INFINITE);
	if (host[at].addr.sin_addr.s_addr == 0) {
		LogVerbose("Start DnsResolverThread for new address %lu. Old addr value was %lu", addr, host[at].addr.sin_addr.s_addr);
		host[at].addr.sin_family = AF_INET;
		host[at].addr.sin_addr.s_addr = addr;
		dns_resolver_thread dnt;
		dnt.index = at;
		dnt.winmtr = this;
		DnsResolver(&dnt);
	}
	ReleaseMutex(ghMutex);
}

void WinMTRNet::SetName(int at, char* n)
{
	WaitForSingleObject(ghMutex, INFINITE);
	strcpy(host[at].name, n);
	ReleaseMutex(ghMutex);
}

void WinMTRNet::SetErrorName(int at, DWORD errnum)
{
	const char* name;
	switch (errnum) {
	case IP_BUF_TOO_SMALL:
		name = "Reply buffer too small."; break;
	case IP_DEST_NET_UNREACHABLE:
		name = "Destination network unreachable."; break;
	case IP_DEST_HOST_UNREACHABLE:
		name = "Destination host unreachable."; break;
	case IP_DEST_PROT_UNREACHABLE:
		name = "Destination protocol unreachable."; break;
	case IP_DEST_PORT_UNREACHABLE:
		name = "Destination port unreachable."; break;
	case IP_NO_RESOURCES:
		name = "Insufficient IP resources were available."; break;
	case IP_BAD_OPTION:
		name = "Bad IP option was specified."; break;
	case IP_HW_ERROR:
		name = "Hardware error occurred."; break;
	case IP_PACKET_TOO_BIG:
		name = "Packet was too big."; break;
	case IP_REQ_TIMED_OUT:
		name = "Request timed out."; break;
	case IP_BAD_REQ:
		name = "Bad request."; break;
	case IP_BAD_ROUTE:
		name = "Bad route."; break;
	case IP_TTL_EXPIRED_REASSEM:
		name = "The time to live expired during fragment reassembly."; break;
	case IP_PARAM_PROBLEM:
		name = "Parameter problem."; break;
	case IP_SOURCE_QUENCH:
		name = "Datagrams are arriving too fast to be processed and datagrams may have been discarded."; break;
	case IP_OPTION_TOO_BIG:
		name = "An IP option was too big."; break;
	case IP_BAD_DESTINATION:
		name = "Bad destination."; break;
	case IP_GENERAL_FAILURE:
		name = "General failure."; break;
	default:
		LogVerbose("==UNKNOWN ERROR== %d", errnum);
		name = "Unknown error! (please report)"; break;
	}
	WaitForSingleObject(ghMutex, INFINITE);
	if (!*host[at].name)
		strcpy(host[at].name, name);
	ReleaseMutex(ghMutex);
}

void WinMTRNet::UpdateRTT(int at, int rtt)
{
	WaitForSingleObject(ghMutex, INFINITE);
	host[at].last = rtt;
	host[at].total += rtt;
	if (host[at].best > rtt || host[at].xmit == 1)
		host[at].best = rtt;
	if (host[at].worst < rtt)
		host[at].worst = rtt;
	ReleaseMutex(ghMutex);
}

void WinMTRNet::AddReturned(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	++host[at].returned;
	ReleaseMutex(ghMutex);
}

void WinMTRNet::AddXmit(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	++host[at].xmit;
	ReleaseMutex(ghMutex);
}

int WinMTRNet::GetBest(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	int ret = host[at].best;
	ReleaseMutex(ghMutex);
	return ret;
}

int WinMTRNet::GetWorst(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	int ret = host[at].worst;
	ReleaseMutex(ghMutex);
	return ret;
}

int WinMTRNet::GetAvg(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	int ret = host[at].returned == 0 ? 0 : host[at].total / host[at].returned;
	ReleaseMutex(ghMutex);
	return ret;
}

int WinMTRNet::GetPercent(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	int ret = (host[at].xmit == 0) ? 0 : (100 - (100 * host[at].returned / host[at].xmit));
	ReleaseMutex(ghMutex);
	return ret;
}

int WinMTRNet::GetLast(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	int ret = host[at].last;
	ReleaseMutex(ghMutex);
	return ret;
}

int WinMTRNet::GetReturned(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	int ret = host[at].returned;
	ReleaseMutex(ghMutex);
	return ret;
}

int WinMTRNet::GetXmit(int at)
{
	WaitForSingleObject(ghMutex, INFINITE);
	int ret = host[at].xmit;
	ReleaseMutex(ghMutex);
	return ret;
}

int WinMTRNet::GetMax()
{
	// @todo : improve this (last hop guess)
	WaitForSingleObject(ghMutex, INFINITE);
	int max = 0;//first try to find target, if not found, find best guess (doesn't work actually :P)

	for (; max < MAX_HOPS && host[max++].addr.sin_addr.s_addr != last_remote_addr.s_addr;);
	if (max == MAX_HOPS) {
		while (max > 1 && host[max - 1].addr.sin_addr.s_addr == host[max - 2].addr.sin_addr.s_addr && host[max - 1].addr.sin_addr.s_addr) --max;
	}

	ReleaseMutex(ghMutex);
	return max;
}

// Based on PingThread(void* p) from WinMTRDialog.cpp
int WinMTRNet::Ping(const char* hostname)
{
	addrinfo nfofilter = {};
	addrinfo* anfo = nullptr;

	if (hasIPv6) 
	{
		switch (useIPv6) 
		{
		case 0:
			nfofilter.ai_family = AF_INET; break;
		case 1:
			nfofilter.ai_family = AF_INET6; break;
		default:
			nfofilter.ai_family = AF_UNSPEC;
		}
	}

	nfofilter.ai_socktype = SOCK_RAW;
	nfofilter.ai_flags = AI_NUMERICSERV | AI_ADDRCONFIG;//|AI_V4MAPPED;
	
	if (getaddrinfo(hostname, NULL, &nfofilter, &anfo) || !anfo) 
	{ //we use first address returned
		LogError("Unable to resolve hostname. (again)");
		return RET_FAIL;
	}

	DoTrace(anfo->ai_addr);
	freeaddrinfo(anfo);

	return RET_OK;
}

// Based on DnsResolverThread(void* p) from WinMTRNet.cpp
void WinMTRNet::DnsResolver(dns_resolver_thread* dnt)
{
	WinMTRNet* wn = dnt->winmtr;
	char hostname[NI_MAXHOST];
	if (!getnameinfo(wn->GetAddr(dnt->index), sizeof(sockaddr_in6), hostname, NI_MAXHOST, NULL, 0, NI_NUMERICHOST)) 
	{
		wn->SetName(dnt->index, hostname);
	}

	if (!getnameinfo(wn->GetAddr(dnt->index), sizeof(sockaddr_in6), hostname, NI_MAXHOST, NULL, 0, 0)) 
	{
		wn->SetName(dnt->index, hostname);
	}
}

// From mtr
struct fields {
	const char* title;
	const char* format;
	const int length;
	std::function<int(WinMTRNet*, size_t)> net_xxx;
};

// From mtr
const fields data_fields[MAXFLD] =
{
	{ "Loss%", " %4.1f%%", 6, [](WinMTRNet* wmtrnet, size_t at) { return wmtrnet->GetPercent((int)at); }},
	{ "Snt", " %5d", 6, [](WinMTRNet* wmtrnet, size_t at) { return wmtrnet->GetXmit((int)at); }},
	{ "Last", " %5.1f", 6, [](WinMTRNet* wmtrnet, size_t at) { return wmtrnet->GetLast((int)at); }},
	{ "Avg", " %5.1f", 6, [](WinMTRNet* wmtrnet, size_t at) { return wmtrnet->GetAvg((int)at); }},
	{ "Best", " %5.1f", 6, [](WinMTRNet* wmtrnet, size_t at) { return wmtrnet->GetBest((int)at); }},
	{ "Wrst", " %5.1f", 6, [](WinMTRNet* wmtrnet, size_t at) { return wmtrnet->GetWorst((int)at); }},
	{ "StDev", " %5.1f", 6, {} } // Not supported yet. Print N/A for now.
};

// From mtr
// ctime() replacement that will reteturn ISO-8601 timestamp string such as:
// 2016-08-29T19:25:02+01:00
const char* iso_time(const time_t* t)
{
	static char s[32];
	tm tm;

	localtime_s(&tm, t);
	strftime(s, sizeof(s), "%Y-%m-%dT%H:%M:%S%z", &tm);
	return s;
}

// From mtr
void report_open()
{
	const time_t now = time(NULL);
	const char* t = iso_time(&now);

	Log("Start: %s", t);
}

// From mtr
void report_close(WinMTRNet* winmtr)
{
	constexpr size_t MAX_FORMAT_STR = 81;

	char buf[1024];
	char fmt[16];

	size_t len_hosts = strlen(localhost);

	for (size_t hi = 0; hi < MaxHost; ++hi)
	{
		const size_t nlen = strlen(winmtr->host[hi].name);
		if (nlen == 0)
			break;
		if (nlen > len_hosts)
			len_hosts = nlen;
	}

	snprintf(fmt, sizeof(fmt), "HOST: %%-%zus", len_hosts);
	snprintf(buf, sizeof(buf), fmt, localhost);
	
	size_t len = strlen(buf);
	
	for (size_t i = 0; i < MAXFLD; i++) 
	{
		snprintf(fmt, sizeof(fmt), "%%%ds", data_fields[i].length);
		snprintf(buf + len, sizeof(buf), fmt, data_fields[i].title);
		len += data_fields[i].length;
	}

	Log("%s", buf);

	for (size_t hi = 0; hi < MaxHost; ++hi)
	{
		if (strlen(winmtr->host[hi].name) == 0)
			break;

		snprintf(fmt, sizeof(fmt), " %%2d.|-- %%-%zus", len_hosts);
		snprintf(buf, sizeof(buf), fmt, hi + 1, winmtr->host[hi].name);
		len = strlen(buf);
		for (size_t i = 0; i < MAXFLD; i++) 
		{
			if (data_fields[i].net_xxx)
			{
				const int field_value = data_fields[i].net_xxx(winmtr, hi);
				if (strchr(data_fields[i].format, 'f')) 
				{
					snprintf(buf + len, sizeof(buf), data_fields[i].format, float(field_value));
				}
				else 
				{
					snprintf(buf + len, sizeof(buf), data_fields[i].format, field_value);
				}
			}
			else
			{
				snprintf(buf + len, sizeof(buf), " %s", "N/A");
			}
			len += data_fields[i].length;
		}

		Log("%s", buf);
	}
}

int main(int argc, char* argv[])
{
	report_open();

	WinMTRNet wmtr;
	const int ret = wmtr.Ping(test_hostname);
	report_close(&wmtr);

	return ret;
}
