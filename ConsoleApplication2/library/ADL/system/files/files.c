#include "files.h"

FILE_DATA CopyFileData(const TCHAR *Path, DWORD CopySize)
{
    FILE_DATA ReturnValue;
    ReturnValue.PointerToRawData = NULL;
    ReturnValue.SizeOfRawData = 0;

    //open
    HANDLE File = CreateFile(Path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(File == INVALID_HANDLE_VALUE) return ReturnValue;

    //check arguent
    if(CopySize == 0)
    {
        CopySize = GetFileSize(File, NULL);
    }

    //memory allocation
    ReturnValue.PointerToRawData = (LPBYTE)GlobalAlloc(GMEM_FIXED, CopySize);
    if(ReturnValue.PointerToRawData == NULL)
    {
        return ReturnValue;
    }
    
    //read
    ReadFile(File, ReturnValue.PointerToRawData, CopySize, &ReturnValue.SizeOfRawData, NULL);
    
    //close
    CloseHandle(File);
    
    return ReturnValue;
}
