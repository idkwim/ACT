#ifndef COMPARE_H
#define COMPARE_H

#include <windows.h>

int wacmp(const WCHAR *lpWideString, const char *lpAsciiString)
{
    if(lpWideString == NULL) return 1;
    if(lpAsciiString == NULL) return 1;

    int AsciiStringLength = 0;
    for(; lpAsciiString[AsciiStringLength] != 0; AsciiStringLength++);

    int j = 0;
    for(int i = 0; i != AsciiStringLength; i++)
    {
        char word1 = ((char*)(lpWideString))[j];
        char word2 = lpAsciiString[i];

        if(word1 >= 'A' && word1 <= 'Z') word1 += 32;
        if(word2 >= 'A' && word2 <= 'Z') word2 += 32;

        if(word1 != word2) return 1;

        j += 2;
    }

    return 0;
}

#endif