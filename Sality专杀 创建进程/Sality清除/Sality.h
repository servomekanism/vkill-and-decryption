#include "stdio.h" 
#include "windows.h"


char tmppath[MAX_PATH] = { 0, };
struct MyStruct
{
	DWORD SizeOfOep;
	DWORD SizeOfimage;
	BYTE oldOEP[0x500];
	BYTE lastsec[0x28];
} PEstruct;

DWORD retprocessID = 0;
DWORD Fixexe(char *lpPath2);
DWORD copy(char *FilePath);
DWORD WINAPI parenFunc(LPSTR lpPath);
DWORD AddressConvert(PIMAGE_DOS_HEADER lpBase, DWORD dwAddr, BOOL bFile2RVA);
