cmake_minimum_required(VERSION 3.12.4)

project(WinMTR LANGUAGES CXX)

add_compile_definitions(
	_AFXDLL # AFX dynamic
	_CRT_SECURE_NO_WARNINGS 
	_WIN32_WINNT=_WIN32_WINNT_WIN7
)

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
	"src/WinMTRDialog.h"
	"src/WinMTRGlobal.h"
	"src/WinMTRHelp.h"
	"src/WinMTRMain.h"
	"src/WinMTRNet.h"
	"src/WinMTROptions.h"
	"src/WinMTRProperties.h"
)

#start_sources()
#sources_platform(ALL)
#add_sources("NoUberFile"
#	PROJECTS PhysDebugger
#	SOURCE_GROUP "Stubs"
#		"CryCore/Platform/CryEndian.h"
#		"CryCore/Platform/platform.h"
#		"CryCore/Platform/platform_impl.inl"
#		"CryMath/Cry_Geo.h"
#		"CryMath/GeomQuery.h"
#		"CryMemory/CrySizer.h"
#		"CryNetwork/ISerialize.h"
#		"CrySystem/IEngineModule.h"
#		"CrySystem/ILog.h"
#		"CrySystem/ISystem.h"
#		"CryThreading/CryThread.h"
#		"CryThreading/IThreadManager.h"
#		"DummyEditor.h"
#	SOURCE_GROUP "Resource Files"
#		"PhysDebugger.rc"
#		"Resource.h"
#	SOURCE_GROUP "Editor"
#		"../../Sandbox/EditorQt/PhysTool.cpp"
#		"../../Sandbox/EditorQt/PhysTool.h"
#	SOURCE_GROUP "Root"
#		"PhysDebugger.cpp"
#		"physics.cpp"
#)
#set_source_files_properties("../../Sandbox/EditorQt/PhysTool.cpp" PROPERTIES COMPILE_FLAGS "/FIDummyEditor.h")
#end_sources()
#
#CryWindowsApplication(PhysDebugger SOLUTION_FOLDER "PhysDebugger")
#target_include_directories(${THIS_PROJECT} BEFORE PRIVATE .)
#target_compile_options(${THIS_PROJECT} PRIVATE $<$<CONFIG:Profile>:/GL /O2 /Ot> $<$<CONFIG:Release>:/GL /O2 /Ot> $<$<CONFIG:Debug>:/RTCu> )
#target_link_libraries(${THIS_PROJECT} PRIVATE CryPhysicsLib opengl32 glu32 Shlwapi)
#set_property(TARGET ${THIS_PROJECT} APPEND_STRING PROPERTY LINK_FLAGS_PROFILE " /LTCG:incremental")
#set_property(TARGET ${THIS_PROJECT} APPEND_STRING PROPERTY LINK_FLAGS_RELEASE " /LTCG:incremental")