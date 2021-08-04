// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include "ReflectivePick.h"
#include "ReflectiveLoader.h"
#include <stdio.h>

extern HINSTANCE hAppInstance;

BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved )
{
	BOOL bReturnValue = TRUE;
	switch (dwReason)
	{
	case DLL_QUERY_HMODULE:
		if( lpReserved != NULL )
			*(HMODULE *)lpReserved = hAppInstance;
		break;
	case DLL_PROCESS_ATTACH:
		hAppInstance = hinstDLL;
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return bReturnValue;
}

