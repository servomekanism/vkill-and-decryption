//////////////////////////////////////////////////////////////////////////
//sality专杀，文件修复未做，但是核心已经完成                          //////
//思路：通过加载被感染的文件到内存，一个进程执行恶意代码另一个检测是否解密完成，解密完成就关闭恶意代码
//////////////////////////////////////////////////////////////////////////

#include "loadPe.h"

VOID RunMalCode(LPBYTE lpBuff);
LPBYTE AddRetOpcode(LPBYTE lpBuff);
LPBYTE Check(LPBYTE lpBreakPointAddr, LPBYTE lpBuff);
LPSTR WriteToFile(LPBYTE base1116);

LPCSTR lpMalPath = "C:\\Users\\sam\\Desktop\\1.exe";

int main()
{
	LPBYTE lpBuff = NULL; 
	lpBuff = Loader(lpMalPath);

	LPBYTE lpMalret = AddRetOpcode(lpBuff);

	HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)RunMalCode, lpBuff, 0, NULL);

	if (hThread == INVALID_HANDLE_VALUE)
	{
		printf("Create thread Fail [%x] ", GetLastError());
		return -1;
	}

	LPBYTE lpDecodeBytes = Check(lpMalret, lpBuff);

	TerminateThread(hThread, 0);
	CloseHandle(hThread);
	
	printf("Get Decrypt Start Addr = [0x%x]!\n", lpDecodeBytes);

	//下面就可以修复文件了
	LPSTR lpNewFile = WriteToFile(lpDecodeBytes);

	MyFreeBuff(lpBuff);
	return 0;

}

VOID RunMalCode(LPBYTE lpBuff)
{
	//执行恶意解密代码
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBuff;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(lpBuff + pDosHeader->e_lfanew);
	
	LPBYTE lpEntryPoint = lpBuff + pNtHeader->OptionalHeader.AddressOfEntryPoint;
	__asm
	{
		mov eax, lpEntryPoint;
		jmp eax;
	}
}

LPBYTE AddRetOpcode(LPBYTE lpBuff)
{
	//在内存中找到特征代码，修改为ret，返回值为该地址
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBuff;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(lpBuff + pDosHeader->e_lfanew);
	LPBYTE dwSizehigh = lpBuff + pNtHeader->OptionalHeader.SizeOfImage;

	PIMAGE_SECTION_HEADER pSecHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)pDosHeader + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));

	LPBYTE SearchBase = lpBuff + pSecHeader[pNtHeader->FileHeader.NumberOfSections - 1].VirtualAddress;

	for(; SearchBase < dwSizehigh; SearchBase++)
	{
		//特征值：81F9E2FE00000F8C????FFFFC3
		//修改为：81F9E2FE00000F8C????FFFFEBFE
		if (*(SearchBase) == 0x0f && *(SearchBase + 1) == 0x8c && *(SearchBase + 4) == 0xff && *(SearchBase + 5) == 0xff && *(SearchBase + 6) == 0xc3)
		{
			*(SearchBase + 6) = 0xEB;
			*(SearchBase + 7) = 0xFE;  //JMP 自身，死循环
			printf("find point opcode");
			break;
		}
	}
	return SearchBase + 6;
}

LPBYTE Check(LPBYTE lpBreakPointAddr, LPBYTE lpBuff)
{
	//////////////////////////////////////////////////////////////////////////
	////检查是否已经解密完成///////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBuff;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(lpBuff + pDosHeader->e_lfanew);
	LPBYTE lpImageOver = lpBuff + pNtHeader->OptionalHeader.SizeOfImage;
	//检查是否解密完成
	while (TRUE)
	{
		for (LPBYTE i = lpBreakPointAddr; i < (lpImageOver-5); i++)
		{
			if (*(LPDWORD)i == 0x000000E8)
			{
				printf("decrypt finished![0x%x]\n", i);
				return i;
			}
		}
	}
	

}

LPSTR WriteToFile(LPBYTE base1116)
{
	//现在完全可以修复文件，然后保存

	LPSTR NewFileName = "c:\\NewFile.exe";

	//后面拿到base1116的偏移后，可以根据下面的偏移取出文件原始信息
	//SizeOfOep = base1116 + 0x13fb			   原始OEP大小
	//oldOEP = base1116 + 0x13ff			   原始OEP起始位置
	//base1116 + 0x1407 + PEstruct.SizeOfOep   原始文件大小
	//base1116 + 0x139f 大小0x28			       原始文件最后一个节的大小


// 	ReadProcessMemory((HANDLE)pi.hProcess, (LPDWORD)(base1116 + 0x13fb), &PEstruct.SizeOfOep, 4, NULL);
// 	printf("OEP Size =>%x\n", PEstruct.SizeOfOep);
// 
// 	//保存原始OEP数据
// 	ReadProcessMemory((HANDLE)pi.hProcess, (LPBYTE)(base1116 + 0x13ff), PEstruct.oldOEP, PEstruct.SizeOfOep, NULL);
// 
// 	//保存原始文件大小
// 	ReadProcessMemory((HANDLE)pi.hProcess, (LPDWORD)(base1116 + 0x1407 + PEstruct.SizeOfOep), &PEstruct.SizeOfimage, 4, NULL);
// 
// 	//读取最后一个节的属性 
// 	ReadProcessMemory((HANDLE)pi.hProcess, (LPBYTE)(base1116 + 0x139f), PEstruct.lastsec, 0x28, NULL);
	
	return NewFileName;
}
