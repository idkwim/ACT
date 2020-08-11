#ifndef _PEFILE_H
#define _PEFILE_H

#include <windows.h>

//copy image dos header
IMAGE_DOS_HEADER CopyDOS(LPBYTE PointerToRawData);

//get offset of dos header to nt header
LONG DOStoNT(LPBYTE PointerToRawData);

//copy nt 32
IMAGE_NT_HEADERS32 CopyNT32(LPBYTE PointerToRawData);
//copy nt 64
IMAGE_NT_HEADERS64 CopyNT64(LPBYTE PointerToRawData);

//copy section headers to dynamic array
IMAGE_SECTION_HEADER *CopySectionHeaders(LPBYTE PointerToRawData);

//get section pointer to section header
LPBYTE GetSection(LPBYTE PointerToRawData, IMAGE_SECTION_HEADER SectionHeader);

//free macro
#define FreeSectionHeaders(x) GlobalFree(x);
#define GetPaddingArea(x, y) (y + (x - y % x))

#endif
