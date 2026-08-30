#ifndef EKKO_EKKO_H
#define EKKO_EKKO_H

#include <windows.h>

typedef struct
{
    DWORD	Length;
    DWORD	MaximumLength;
    PVOID	Buffer;
} USTRING ;

VOID EkkoObf( DWORD SleepTime );

#endif
