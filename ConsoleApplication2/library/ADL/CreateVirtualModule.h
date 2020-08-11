#ifndef _CREATE_VIRTUAL_MODULE_H
#define _CREATE_VIRTUAL_MODULE_H

typedef struct MODULE_INFO
{
	LPBYTE DllBase;
	IMAGE_NT_HEADERS NtHeader;
}MODULE_INFO;

MODULE_INFO CreateVirtualModule(const char *DllName);
void FreeVirtualModule(MODULE_INFO info);

#include "CreateVirtualModule.c"

#endif