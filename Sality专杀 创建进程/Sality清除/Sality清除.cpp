
//目前已经能够自动化修复单个文件，原理是通过创建新进程运行，效率有点低


#include "stdafx.h"
#include "Sality.h"

char *Path = "C:\\Users\\sam\\Desktop\\7zFM.vvv";

int _tmain(int argc, _TCHAR* argv[])
{

	
	copy(Path);//保存副本
	
	printf("11111");
	getchar();
	HANDLE hthread = CreateThread(NULL,
		0,
		(LPTHREAD_START_ROUTINE)parenFunc,
		tmppath,
		0,
		NULL);
	if (hthread == NULL)
	{
		printf("创建线程失败！%x", GetLastError());
	}
	WaitForSingleObject(hthread, INFINITE);
	CloseHandle(hthread);
	printf("已关闭线程");

	Fixexe(Path);

	return 0;
}

DWORD WINAPI parenFunc(LPSTR lpPath)
{
	STARTUPINFOA si = { sizeof(STARTUPINFOA), };
	PROCESS_INFORMATION pi = { 0, };
	DEBUG_EVENT DebugEvent;
	DWORD ProcessId = 0;
	DWORD ExceptCode = 0;
	DWORD ExceptAddr = 0;
	LPDWORD regESP = nullptr;
	CONTEXT ctx;
	DWORD base1116 = 0;
	DWORD resESPvalue = 0;
	
	LPDWORD lpSizeOldOEP = nullptr;
	
	int i = 0;
	char szMyPass[20] = { 0, };
	getchar(); 
	if (!CreateProcessA(
		NULL,
		lpPath,
		NULL,
		NULL,
		FALSE,
		DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS,
		NULL,
		NULL,
		&si,
		&pi))//创建调试子进程
	{
		printf("CreateProcess() failed! [%x]\n", GetLastError());
		return 0;
	}
	
	while (TRUE)
	{
		ZeroMemory(&DebugEvent, sizeof(DebugEvent));

		if (!WaitForDebugEvent(&DebugEvent, INFINITE))
		{
			printf("WaitForDebugEvent error => %x \n", GetLastError());
			break;
		}
		if (DebugEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
		{
			ProcessId = DebugEvent.dwProcessId;
			ExceptCode = DebugEvent.u.Exception.ExceptionRecord.ExceptionCode;
			ExceptAddr = (DWORD)DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress;
			if (ExceptCode == EXCEPTION_BREAKPOINT)//如果是int 3 断点
			{
				ctx.ContextFlags = CONTEXT_FULL;
				GetThreadContext(pi.hThread, &ctx);
				if (ExceptAddr>0x70000000)
				{
					ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DBG_CONTINUE);
					continue;
				}
				printf("in => ProcessId => %x | ExceptCode=>%x | ExceptAddr => 0x%08x\n", ProcessId, ExceptCode, ExceptAddr);
				regESP =LPDWORD(ctx.Esp);

				ReadProcessMemory((HANDLE)pi.hProcess, regESP, &base1116, 4, NULL);//读esp寄存器的值
				printf("ESP=>0x%x,ESPValue=>%x\n", regESP, base1116);

				

				//保存原始OEP大小
				ReadProcessMemory((HANDLE)pi.hProcess, (LPDWORD)(base1116 + 0x13fb), &PEstruct.SizeOfOep, 4, NULL);
				printf("OEP Size =>%x\n", PEstruct.SizeOfOep);

				//保存原始OEP数据
				ReadProcessMemory((HANDLE)pi.hProcess, (LPBYTE)(base1116 + 0x13ff), PEstruct.oldOEP, PEstruct.SizeOfOep, NULL);

				//保存原始文件大小
				ReadProcessMemory((HANDLE)pi.hProcess, (LPDWORD)(base1116 + 0x1407 + PEstruct.SizeOfOep), &PEstruct.SizeOfimage, 4, NULL);

				//读取最后一个节的属性 
				ReadProcessMemory((HANDLE)pi.hProcess, (LPBYTE)(base1116 + 0x139f), PEstruct.lastsec, 0x28, NULL);

				return 0;
			}
		}
		ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DBG_CONTINUE);
	}
	return 0;
}

DWORD AddressConvert(PIMAGE_DOS_HEADER lpBase, DWORD dwAddr, BOOL bFile2RVA)
{
	/*
	Purpose:PE文件的内存偏移与文件偏移相互转换,不考虑系统为对齐填充偏移转换
	szFileName:文件名
	dwAddr:需要转换的偏移值
	bFile2RVA:是否是文件偏移到内存偏移的转换，1 - dwAddr代表的是文件偏移，此函数返回内存偏移
	0 - dwAddr代表的是内存偏移，此函数返回文件偏移
	返回值：相对应的偏移值,失败返回-1
	*/
	DWORD dwRet = -1;

	//2.读取该文件的信息（文件内存对齐方式以及区块数量，并将区块表指针指向区块表第一个区块头）  
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBase;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((unsigned long)lpBase + pDosHeader->e_lfanew);

	DWORD dwMemAlign = pNtHeader->OptionalHeader.SectionAlignment;
	DWORD dwFileAlign = pNtHeader->OptionalHeader.FileAlignment;
	int dwSecNum = pNtHeader->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER pSecHeader = (PIMAGE_SECTION_HEADER)((char *)lpBase + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));
	DWORD dwHeaderSize = 0;

	if (!bFile2RVA)  // 内存偏移转换为文件偏移  
	{
		//看需要转移的偏移是否在PE头内，如果在则两个偏移相同  
		dwHeaderSize = pNtHeader->OptionalHeader.SizeOfHeaders;
		if (dwAddr <= dwHeaderSize)
		{
			delete lpBase;
			lpBase = NULL;
			return dwAddr;
		}
		else //不再PE头里，查看该地址在哪个区块中  
		{
			for (int i = 0; i < dwSecNum; i++)
			{
				DWORD dwSecSize = pSecHeader[i].Misc.VirtualSize;
				if ((dwAddr >= pSecHeader[i].VirtualAddress) && (dwAddr <= pSecHeader[i].VirtualAddress + dwSecSize))
				{
					//3.找到该该偏移，则文件偏移 = 该区块的文件偏移 + （该偏移 - 该区块的内存偏移）  
					dwRet = pSecHeader[i].PointerToRawData + dwAddr - pSecHeader[i].VirtualAddress;
				}
			}
		}
	}
	else // 文件偏移转换为内存偏移  
	{
		dwHeaderSize = pNtHeader->OptionalHeader.SizeOfHeaders;
		//看需要转移的偏移是否在PE头内，如果在则两个偏移相同  
		if (dwAddr <= dwHeaderSize)
		{
			delete lpBase;
			lpBase = NULL;
			return dwAddr;
		}
		else//不再PE头里，查看该地址在哪个区块中  
		{
			for (int i = 0; i < dwSecNum; i++)
			{
				DWORD dwSecSize = pSecHeader[i].Misc.VirtualSize;
				if ((dwAddr >= pSecHeader[i].PointerToRawData) && (dwAddr <= pSecHeader[i].PointerToRawData + dwSecSize))
				{
					//3.找到该该偏移，则内存偏移 = 该区块的内存偏移 + （该偏移 - 该区块的文件偏移）  
					dwRet = pSecHeader[i].VirtualAddress + dwAddr - pSecHeader[i].PointerToRawData;
				}
			}
		}
	}
	return dwRet;
}

DWORD Fixexe(char *lpPath2)
{
	//打开文件
	printf("打开修复文件 %s\n", lpPath2);
	HANDLE hFile = CreateFileA(lpPath2, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("\n打开文件句柄错误：%x", GetLastError());
		CloseHandle(hFile);
		getchar();
		return 0;
	}
	//映射到内存中
	HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
	if (hMapping == NULL)
	{
		printf("文件映射错误：%x", GetLastError());
		CloseHandle(hMapping);
		return 0;
	}
	PVOID pbFile = MapViewOfFile(hMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	if (pbFile == NULL)
	{
		printf("MapViewOfFile错误：%x", GetLastError());
		UnmapViewOfFile(pbFile);
		return 0;
	}

	/*获得DOS头*/
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pbFile;

	//获得NT头
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pbFile + pDosHeader->e_lfanew);

	printf("%x,%x", pNtHeader->OptionalHeader.AddressOfEntryPoint, pNtHeader->OptionalHeader.ImageBase);
	
	DWORD retva = AddressConvert(pDosHeader, pNtHeader->OptionalHeader.AddressOfEntryPoint, 0);
	printf("文件偏移%x\n", retva);

	memcpy( (LPVOID)((DWORD)pDosHeader + retva), PEstruct.oldOEP, PEstruct.SizeOfOep);

	pNtHeader->OptionalHeader.SizeOfImage = PEstruct.SizeOfimage;

	pNtHeader->FileHeader.NumberOfSections;

	PIMAGE_SECTION_HEADER pSecHeader = (PIMAGE_SECTION_HEADER)((char *)pDosHeader + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));
	memcpy(&(pSecHeader[(pNtHeader->FileHeader.NumberOfSections) - 1].Name), PEstruct.lastsec, 0x28);
	
	UnmapViewOfFile(pbFile);
	CloseHandle(hMapping);

	SetFilePointer(hFile, PEstruct.SizeOfimage, NULL, FILE_BEGIN);
	SetEndOfFile(hFile);

	if (hFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFile);
	}
	if (hMapping != NULL)
	{
		CloseHandle(hMapping);
	}
	if (pbFile != NULL)
	{
		UnmapViewOfFile(pbFile);
	}

}

DWORD copy(char *FilePath)
{
	char c;
	
	int len = 0;
	while (FilePath[len] != '\0') {
		len++;
	}
	memcpy(tmppath, FilePath, len);
	FILE *fp1, *fp2;
	if ((fopen_s(&fp1, FilePath, "rb")))
	{
		printf("%x\n", GetLastError());
		return -1;
	}

	strcat_s(&tmppath[len], 10, ".malaa");

	if ((fopen_s(&fp2, tmppath, "wb")) )
		return -1;
	while (!feof(fp1))
	{
		c = fgetc(fp1);
		fputc(c, fp2);
	}
	fclose(fp1);
	fclose(fp2);
	return 1;
}