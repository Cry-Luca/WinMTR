//*****************************************************************************
// FILE:            WinMTRGlobal.h
//
//
// DESCRIPTION:
//
//
// NOTES:
//
//
//*****************************************************************************

#ifndef GLOBAL_H_
#define GLOBAL_H_

#ifndef  _WIN64
#define  _USE_32BIT_TIME_T
#endif

#define VC_EXTRALEAN

#include <afxwin.h>
#include <afxext.h>
#include <afxdisp.h>
#include <afxdtctl.h>

#ifndef _AFX_NO_AFXCMN_SUPPORT
#include <afxcmn.h>
#endif
#include <afxsock.h>

#include "resource.h"

#include "WinMTRDefs.h"

#define MTR_NR_COLS 9

const char MTR_COLS[ MTR_NR_COLS ][10] = {
	"Hostname",
	"Nr",
	"Loss %",
	"Sent",
	"Recv",
	"Best",
	"Avrg",
	"Worst",
	"Last"
};

const int MTR_COL_LENGTH[ MTR_NR_COLS ] = {
	249, 30, 50, 40, 40, 50, 50, 50, 50
};

int gettimeofday(struct timeval* tv, struct timezone* tz);

#endif // ifndef GLOBAL_H_
