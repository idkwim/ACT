#ifndef ROOT_H
#define ROOT_H

#include <windows.h>
#include "memio.h"

#define LPFN(NAME) lpfn_##NAME

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

#ifdef _WIN64
#define ADDRESS INT64
#else
#define ADDRESS INT32
#endif  

#endif