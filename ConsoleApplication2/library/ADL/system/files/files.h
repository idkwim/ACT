#ifndef _FILEIO_H
#define _FILEIO_H

#include <windows.h>

#define COPY_FULL 0

typedef struct _FILE_DATA
{
    LPBYTE PointerToRawData;
    DWORD SizeOfRawData;
}FILE_DATA;

FILE_DATA CopyFileData(const TCHAR *Path, DWORD CopySize);
#define FreeFileData(x) GlobalFree(x.PointerToRawData);

#endif