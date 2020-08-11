#include "pefiles.h"

IMAGE_DOS_HEADER CopyDOS(LPBYTE PointerToRawData)
{
    IMAGE_DOS_HEADER header;
    memcpy(&header, PointerToRawData, sizeof(header));

    return header;
}

LONG DOStoNT(LPBYTE PointerToRawData)
{
    IMAGE_DOS_HEADER DOS;
    memcpy(&DOS, PointerToRawData, sizeof(DOS));

    return DOS.e_lfanew;
}

IMAGE_NT_HEADERS32 CopyNT32(LPBYTE PointerToRawData)
{
    PointerToRawData += DOStoNT(PointerToRawData);

    IMAGE_NT_HEADERS32 NT32;
    memcpy(&NT32, PointerToRawData, sizeof(NT32));

    return NT32;
}

IMAGE_NT_HEADERS64 CopyNT64(LPBYTE PointerToRawData)
{
    PointerToRawData += DOStoNT(PointerToRawData);

    IMAGE_NT_HEADERS64 NT64;
    memcpy(&NT64, PointerToRawData, sizeof(NT64));

    return NT64;
}

IMAGE_SECTION_HEADER *CopySectionHeaders(LPBYTE PointerToRawData)
{
    IMAGE_NT_HEADERS32 NT32 = CopyNT32(PointerToRawData);
    PointerToRawData += (DOStoNT(PointerToRawData) + ((LONG)sizeof(IMAGE_NT_HEADERS32)));

    IMAGE_SECTION_HEADER *Headers = NULL;
    Headers = (IMAGE_SECTION_HEADER *)GlobalAlloc(GMEM_FIXED, NT32.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
    if(Headers == NULL) return Headers; 

    for(int i = 0; i != NT32.FileHeader.NumberOfSections; i++)
    {
        memcpy(&Headers[i], PointerToRawData, sizeof(IMAGE_SECTION_HEADER));
        PointerToRawData += sizeof(IMAGE_SECTION_HEADER);
    }

    return Headers;
}

LPBYTE GetSection(LPBYTE PointerToRawData, IMAGE_SECTION_HEADER SectionHeader)
{
    return PointerToRawData + SectionHeader.PointerToRawData;
}