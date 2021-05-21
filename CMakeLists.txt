cmake_minimum_required(VERSION 3.12.4)

set(CMAKE_CONFIGURATION_TYPES Debug Release)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

project(WinMTR LANGUAGES CXX)

add_executable(WinMTR 
	WIN32 
	"src/Resource.h"
	"src/WinMTR.ico"
	"src/WinMTR.rc"
	"src/WinMTRLicense.cpp"
	"src/WinMTRStatusBar.cpp"
	"src/WinMTRDialog.cpp"
	"src/WinMTRGlobal.cpp"
	"src/WinMTRHelp.cpp"
	"src/WinMTRMain.cpp"
	"src/WinMTRNet.cpp"
	"src/WinMTROptions.cpp"
	"src/WinMTRProperties.cpp"
	"src/WinMTRLicense.h"
	"src/WinMTRStatusBar.h"
	"src/WinMTRDefs.h"
	"src/WinMTRDialog.h"
	"src/WinMTRGlobal.h"
	"src/WinMTRHelp.h"
	"src/WinMTRMain.h"
	"src/WinMTRNet.h"
	"src/WinMTROptions.h"
	"src/WinMTRProperties.h"
)

target_compile_definitions(WinMTR PRIVATE
	_AFXDLL # AFX dynamic
	_CRT_SECURE_NO_WARNINGS 
	_WIN32_WINNT=_WIN32_WINNT_WIN7
)

add_executable(WinMTR-Report
	"src/Resource.h"
	"src/WinMTR.ico"
	"src/WinMTR.rc"
	"src/WinMTRNet.cpp"
	"src/WinMTRReport.cpp"
	"src/WinMTRNet.h"
)

target_compile_definitions(WinMTR-Report PRIVATE NOMINMAX)

target_compile_options(WinMTR-Report PRIVATE /W4)

target_link_libraries(WinMTR-Report PRIVATE Ws2_32)
