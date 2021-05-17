//*****************************************************************************
// FILE:            WinMTRGlobal.cpp
//
//
//*****************************************************************************

#include "WinMTRGlobal.h"

//*****************************************************************************
// gettimeofday
//
// win32 port of unix gettimeofday
//*****************************************************************************
/*
int gettimeofday(struct timeval* tv, struct timezone* / *tz* /)
{
   if(!tv)
      return -1;
   struct _timeb timebuffer;
   
   _ftime(&timebuffer);

   tv->tv_sec = (long)timebuffer.time;
   tv->tv_usec = timebuffer.millitm * 1000 + 500;
   return 0;
}// */

void TRACE_MSG(const char* format, ...)
{
#ifdef _DEBUG
	va_list args;
	va_start(args, format);

	const int buf_size = vsnprintf(nullptr, 0, format, args) + 2;
	char* buffer = new char[buf_size];

	vsnprintf_s(buffer, buf_size, _TRUNCATE, format, args);
	strcat_s(buffer, buf_size, "\n");

	OutputDebugString(buffer);

	va_end(args);
#endif
}

void NotifyError(const char* text)
{
	AfxMessageBox(text);
}
