// Copyright 2021 Crytek GmbH / Crytek Group. All rights reserved.
//
// Contains modified portions of code from mtr 0.94 (https://github.com/traviscross/mtr)
/*
	mtr  --  a network diagnostic tool
	Copyright (C) 1997,1998  Matt Kimball

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License version 2 as
	published by the Free Software Foundation.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License along
	with this program; if not, write to the Free Software Foundation, Inc.,
	51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/
//
// Includes code from WinMTR Redux 1.0 (https://github.com/White-Tiger/WinMTR)
/*
	WinMTR Redux, extended fork of Appnor's WinMTR with IPv6 support and other enhancements
	Copyright (C) 2010-2010 Appnor MSP S.A. - http://www.appnor.com
	Copyright (C) 2014 René Schümann

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License along
	with this program; if not, write to the Free Software Foundation, Inc.,
	51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "WinMTRNet.h"

#include <cstdlib>
#include <cstdio>
#include <cstdarg>
#include <functional>
#include <ctime>
#include <memory>

//
//void ErrorMsg()
//{
//	const DWORD dw = GetLastError();
//
//	LPVOID lpMsgBuf = NULL;
//
//	FormatMessage(
//		FORMAT_MESSAGE_ALLOCATE_BUFFER |
//		FORMAT_MESSAGE_FROM_SYSTEM |
//		FORMAT_MESSAGE_IGNORE_INSERTS,
//		NULL,
//		dw,
//		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
//		(LPTSTR)&lpMsgBuf,
//		0, NULL);
//
//	// Display the error message and exit the process
//
//	TCHAR* lpDisplayBuf = (TCHAR*)LocalAlloc(LMEM_ZEROINIT, (lstrlen((LPCTSTR)lpMsgBuf) + 40) * sizeof(TCHAR));
//
//	sprintf(lpDisplayBuf, "Failed with error %d: %s", dw, lpMsgBuf);
//
//	MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK);
//
//	LocalFree(lpMsgBuf);
//	LocalFree(lpDisplayBuf);
//}

bool verbose = false;

constexpr int RET_FAIL = EXIT_FAILURE;
constexpr int RET_OK = EXIT_SUCCESS;

void NotifyError(const char* text)
{
	fprintf(stderr, "%s\n", text);
}

void TRACE_MSG(const char* format, ...)
{
#ifdef NDEBUG
	if (verbose)
#endif
	{
		va_list args;
		va_start(args, format);
		vfprintf(stdout, format, args);
		fprintf(stdout, "\n");
		va_end(args);
	}
}

void Log(const char* format, ...)
{
	va_list args;
	va_start(args, format);
	vfprintf(stdout, format, args);
	fprintf(stdout, "\n");
	va_end(args);
}

// 
// (Modified) mtr 0.94 code
// 

constexpr size_t MAXFLD = 7; // max stats fields to display

struct fields 
{
	const char* title;
	const char* format;
	const int length;
	std::function<int(WinMTRNet*, size_t)> net_xxx;
};

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

void report_open()
{
	const time_t now = time(NULL);
	const char* t = iso_time(&now);

	Log("Start: %s", t);
}

void report_close(WinMTRNet* winmtr)
{
	constexpr size_t MAX_FORMAT_STR = 81;

	char name[sizeof(s_nethost::name)];
	// If a buffer of 256 bytes is passed in the name parameter and the namelen parameter is set to 256, the buffer size will always be adequate
	// (https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-gethostname)
	char localhost[256];
	char buf[1024];
	char fmt[16];
	const size_t host_count = winmtr->GetMax();

	gethostname(localhost, sizeof(localhost));

	size_t len_hosts = strlen(localhost);

	for (size_t hi = 0; hi < host_count; ++hi)
	{
		winmtr->GetName(static_cast<int>(hi), name);
		const size_t nlen = strlen(name);

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

	for (size_t hi = 0; hi < host_count; ++hi)
	{
		snprintf(fmt, sizeof(fmt), " %%2d.|-- %%-%zus", len_hosts);
		winmtr->GetName(static_cast<int>(hi), name);
		snprintf(buf, sizeof(buf), fmt, hi + 1, name);
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

//
//~ (Modified) mtr 0.94 code
//

void Usage()
{
	Log("\nUsage:");
	Log(" WinMTR-Report [options] hostname\n");
	Log(" -c, --report-cycles COUNT  set the number of pings sent");
	Log(" -v, --verbose              print verbose output");
	Log(" -h, --help                 display this help and exit");
}

int main(int argc, char* argv[])
{
	s_trace trace;
	trace.hostname = nullptr;
	trace.max_ping = 10;

	for (int ai = 1; ai < argc;)
	{
		const char* opt = argv[ai];
		if (strcmp("-c", opt) == 0 || strcmp("--report-cycles", opt) == 0)
		{
			if ((ai + 1) < argc)
			{
				trace.max_ping = atoi(argv[ai + 1]);
				ai += 2;
			}
			else
			{
				NotifyError("No value supplied to -c/--report-cycles option.");
				Usage();
				return RET_FAIL;
			}
			
		}
		else if (strcmp("-v", opt) == 0 || strcmp("--verbose", opt) == 0)
		{
			verbose = true;
			ai++;
		}
		else if (strcmp("-h", opt) == 0 || strcmp("--help", opt) == 0)
		{
			Usage();
			return RET_OK;
		}
		else if((ai + 1) == argc)
		{
			trace.hostname = argv[ai];
			ai++;
		}
		else
		{
			NotifyError("Unexpected arguments.");
			Usage();
			return RET_FAIL;
		}
	}

	if (trace.hostname == nullptr || strlen(trace.hostname) == 0)
	{
		NotifyError("No hostname provided. Unable to proceed.");
		Usage();
		return RET_FAIL;
	}

	TRACE_MSG("Starting trace with hostname='%s' max_ping=%d", trace.hostname, trace.max_ping);

	report_open();

	std::unique_ptr<WinMTRNet> wmtr = std::make_unique<WinMTRNet>();
	wmtr->DoTrace(trace);

	report_close(wmtr.get());

	wmtr.reset();

	return RET_OK;
}
