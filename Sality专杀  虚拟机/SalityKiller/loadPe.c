#include <stdio.h>
#include <windows.h>

LPBYTE LoadFileToMem(LPCSTR lpFilePath);
LPBYTE Extension(LPBYTE lpFileBuffer);
FARPROC InitEnv(LPBYTE lpMemBuffer);
BOOL ReRloc(LPBYTE lpMemBuffer);
BOOL InitIAT(LPBYTE lpMemBuffer);
LPBYTE Loader(LPCSTR lpFilePath);


LPBYTE Loader(LPCSTR lpFilePath)
{
	//////////////////////////////////////////////////////////////////////////
	////传入一个文件名，返回在内存中展开后的数据    ////////////////////////////
	//////////////////////////////////////////////////////////////////////////
	LPBYTE lpBuf = NULL;
	FARPROC lpEntryPoint = NULL;
	//LPCSTR lpFilePath = "D:\\Project\\CUI\\日常代码\\Release\\MassageBox调试专用.exe";
	lpBuf = LoadFileToMem(lpFilePath);
	lpBuf = Extension(lpBuf);
	ReRloc(lpBuf);
	InitIAT(lpBuf);
	lpEntryPoint = InitEnv(lpBuf);

	//lpEntryPoint();

	/*
	__asm
	{
	mov eax, lpEntryPoint;
	jmp eax;
	}
	*/

	//由于内存不能被释放，有内存泄漏的可能

	return lpBuf;
}

FARPROC InitEnv(LPBYTE lpMemBuffer)
{
	//////////////////////////////////////////////////////////////////////////
	////修改ImageBase，返回入口点                                           ///
	//////////////////////////////////////////////////////////////////////////
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)lpMemBuffer;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(lpMemBuffer + pDos->e_lfanew);
	pNt->OptionalHeader.ImageBase = lpMemBuffer;

	return lpMemBuffer + pNt->OptionalHeader.AddressOfEntryPoint;
}

BOOL InitIAT(LPBYTE lpMemBuffer)
{
	//////////////////////////////////////////////////////////////////////////
	////修复IAT                                                            
	//////////////////////////////////////////////////////////////////////////
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)lpMemBuffer;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(lpMemBuffer + pDos->e_lfanew);
	PIMAGE_IMPORT_DESCRIPTOR pImportTalbe = (PIMAGE_IMPORT_DESCRIPTOR)(lpMemBuffer + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	LPCSTR szDllname = NULL;
	PIMAGE_THUNK_DATA lpOrgNameArry = NULL;
	PIMAGE_THUNK_DATA lpFirNameArry = NULL;
	PIMAGE_IMPORT_BY_NAME lpImportByNameTable = NULL;
	HMODULE hMou;
	FARPROC Funaddr;
	int i = 0;

	while (pImportTalbe->OriginalFirstThunk)
	{
		szDllname = lpMemBuffer + pImportTalbe->Name;
		hMou = GetModuleHandleA(szDllname);
		if (hMou == NULL)
		{
			hMou = LoadLibraryA(szDllname);
			if (hMou == NULL)
			{
				printf("加载%s失败！[%x]\n ", szDllname, GetLastError());
				return FALSE;
			}
		}

		//dll加载成功，开始导入需要的函数
		lpOrgNameArry = (PIMAGE_THUNK_DATA)(lpMemBuffer + pImportTalbe->OriginalFirstThunk);

		lpFirNameArry = (PIMAGE_THUNK_DATA)(lpMemBuffer + pImportTalbe->FirstThunk);

		i = 0;

		while (lpOrgNameArry[i].u1.AddressOfData)
		{
			lpImportByNameTable = (PIMAGE_IMPORT_BY_NAME)(lpMemBuffer + lpOrgNameArry[i].u1.AddressOfData);

			if (lpOrgNameArry[i].u1.Ordinal & 0x80000000)
			{
				//序号导入
				Funaddr = GetProcAddress(hMou, (LPSTR)(lpOrgNameArry[i].u1.Ordinal & 0xFFFF));
			}
			else
			{
				//名称导入
				Funaddr = GetProcAddress(hMou, lpImportByNameTable->Name);
			}

			lpFirNameArry[i].u1.Function = Funaddr;
			i++;
		}
		pImportTalbe++;
	}
	return TRUE;
}

BOOL ReRloc(LPBYTE lpMemBuffer)
{
	//////////////////////////////////////////////////////////////////////////
	////修复重定位表                                                        ///
	////原理：遍历重定位表，计算需要重定位数据的地址：重定位后的地址 = 需要重定位的地址 - 默认加载基址 + 当前加载基址
	//////////////////////////////////////////////////////////////////////////
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)lpMemBuffer;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(lpMemBuffer + pDos->e_lfanew);
	//获得重定位表
	PIMAGE_BASE_RELOCATION pReloca = (PIMAGE_BASE_RELOCATION)(lpMemBuffer + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	//如果重定位表为空，上述表达式为pDos+0
	if ((LPBYTE)pReloca == lpMemBuffer)
	{
		printf("没有重定位表！\n");
		return TRUE;
	}

	while (pReloca->VirtualAddress != 0 && pReloca->SizeOfBlock != 0)
	{
		LPWORD pRelData = (LPBYTE)pReloca + sizeof(IMAGE_BASE_RELOCATION);
		int nNumRel = (pReloca->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		for (int i = 0; i < nNumRel; i++)
		{
			// 每个WORD由两部分组成。高4位指出了重定位的类型，WINNT.H中的一系列IMAGE_REL_BASED_xxx定义了重定位类型的取值。
			// 低12位是相对于VirtualAddress域的偏移，指出了必须进行重定位的位置。

			if ((WORD)(pRelData[i] & 0xF000) == 0x3000) //这是一个需要修正的地址
			{
				//pReloca->VirtualAddress存的是页基质，(一个页4K，所以是0xFFF，刚好12位)
				LPDWORD pAddress = (LPDWORD)(lpMemBuffer + pReloca->VirtualAddress + (pRelData[i] & 0x0FFF));


				*pAddress = *pAddress - pNt->OptionalHeader.ImageBase + (DWORD)pDos;

				printf("Check!");
				//DWORD dwDelta = (DWORD)pDos - pNt->OptionalHeader.ImageBase;
				//*pAddress += dwDelta;
			}
		}
		pReloca = (LPBYTE)pReloca + pReloca->SizeOfBlock;
	}
	printf("重定位表修复完成！\n");
	return TRUE;
}

LPBYTE Extension(LPBYTE lpFileBuffer)
{
	//////////////////////////////////////////////////////////////////////////
	////将文件在内存中展开                                                  ///
	//////////////////////////////////////////////////////////////////////////
	int i = 0;
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)lpFileBuffer;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(lpFileBuffer + pDos->e_lfanew);
	PIMAGE_SECTION_HEADER pSec = (PIMAGE_SECTION_HEADER)((LPBYTE)pNt + sizeof(IMAGE_NT_HEADERS));

	DWORD ImageSize = pNt->OptionalHeader.SizeOfImage;

	//LPBYTE lpMemBuffer = (LPBYTE)malloc(ImageSize);
	LPVOID lpMemBuffer = VirtualAlloc(NULL, ImageSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	VirtualProtect(lpMemBuffer, ImageSize, PAGE_EXECUTE_READWRITE, NULL);

	ZeroMemory(lpMemBuffer, ImageSize);

	//文件头的大小
	DWORD dwSizeOfHeader = pNt->OptionalHeader.SizeOfHeaders;

	//将头部拷贝过去
	CopyMemory(lpMemBuffer, lpFileBuffer, dwSizeOfHeader);


	for (; i < pNt->FileHeader.NumberOfSections; i++)
	{
		if (pSec->VirtualAddress == 0 || pSec->PointerToRawData == 0)
		{
			pSec++;
			continue;
		}
		CopyMemory((LPBYTE)lpMemBuffer + pSec->VirtualAddress, lpFileBuffer + pSec->PointerToRawData, pSec->SizeOfRawData);
		pSec++;
	}

	//已经完全映射，可以把之前的内存释放掉了
	free(lpFileBuffer);
	return lpMemBuffer;
}

LPBYTE LoadFileToMem(LPCSTR lpFilePath)
{
	//////////////////////////////////////////////////////////////////////////
	////将源文件读到内存中                                                  ///
	//////////////////////////////////////////////////////////////////////////
	DWORD FileSize = 0;
	LPBYTE Buff = NULL;

	HANDLE hFile = CreateFileA(lpFilePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("打开文件句柄错误！[%x]", GetLastError());
		return -1;
	}

	FileSize = GetFileSize(hFile, NULL);

	Buff = (LPBYTE)malloc(FileSize);
	if (Buff == NULL)
	{
		printf("空间申请失败![%x]", GetLastError());
		return -1;
	}

	if (!ReadFile(hFile, Buff, FileSize, &FileSize, NULL))
	{
		printf("ReadFile![%x]", GetLastError());
		return -1;
	}
	return Buff;
}


BOOL MyFreeBuff(LPBYTE lpBuffer)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)lpBuffer;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(lpBuffer + pDos->e_lfanew);
	SIZE_T BuffrSize = pNt->OptionalHeader.SizeOfImage;
	//VirtualFree参数问题
	if (!VirtualFree(lpBuffer, 0, MEM_RELEASE))
	{
		printf("空间释放失败！[0x%x]\n", GetLastError());
		return -1;
	}
	return 0;
}