#include <stdafx.h>
#include <windows.h>
#include <tchar.h> 
#include <stdio.h>
#include <strsafe.h>
#include <Shlwapi.h>
#pragma  comment(lib,"Shlwapi.lib")
#pragma comment(lib, "User32.lib")

//遍历文件，递归找到exe dll htm html 
int decrypt(STRSAFE_LPWSTR Mainpath);
//清理exe 和 dll文件
int clearexeFile(WCHAR * MalwarePath);
//清理html 和htm 文件  
int clearhtmlFile(WCHAR * MalwarePath);
//修复启动项
void ClearAutoRun();
//获取文件大小
DWORD GetFileSize(WCHAR* filename);

WCHAR* MalSoftPath;
DWORD MalSoftSize;

//删除恶意代码
int MySetEndOfFile(LPCTSTR MalPath, int MalCodeSize, DWORD Filemethod);

int _tmain(int argc, TCHAR *argv[])
{
	printf("目前功能：删除启动项，遍历整个C盘，完全还原exe和html,重启后再删一次效果更好\n按任意键开始清除 \n");
	getchar();

	STRSAFE_LPWSTR Mainpath = L"C:";
	ClearAutoRun();
 	decrypt(Mainpath);

// 	clearexeFile(argv[1]);
// 	clearexeFile(L"C:\\Users\\sam\\Desktop\\1.exe");
//	clearhtmlFile(L"C:\\Users\\sam\\Desktop\\1.txt");
// 	MalSoftPath = FindAutoRun();
// 	MalSoftSize = GetFileSize(MalSoftPath);

}

int MySetEndOfFile(LPCTSTR MalPath, int MalCodeSize,DWORD Filemethod)
{
	//LPCSTR Malpath= "C:\\Users\\Administrator\\Desktop\\1.txt";
	
	HANDLE hFile = CreateFile(MalPath,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hFile == NULL)
	{
		//_tprintf(L"Fail in CreateFile\n");
		return 0;
	}

	LARGE_INTEGER liFileSize;

	GetFileSizeEx(hFile, &liFileSize);
	SetFilePointer(hFile, MalCodeSize, NULL, Filemethod);
	SetEndOfFile(hFile);
	CloseHandle(hFile);
	_tprintf(L"清理完毕:%s\n", MalPath);
}
DWORD GetFileSize(WCHAR* filename)
{
	FILE* fp;

	_wfopen_s(&fp,filename, L"r");
	if (!fp) return -1;
	fseek(fp, 0L, SEEK_END);
	DWORD size = ftell(fp);
	fclose(fp);

	return size;
}
int decrypt(STRSAFE_LPWSTR Mainpath)
{
	WIN32_FIND_DATA ffd;
	LARGE_INTEGER filesize;
	TCHAR szDir[MAX_PATH];
	size_t length_of_arg;
	HANDLE hFind = INVALID_HANDLE_VALUE;
	DWORD dwError = 0;
	WCHAR path_buffer[_MAX_PATH];
	WCHAR drive[_MAX_DRIVE];
	WCHAR dir[_MAX_DIR];
	WCHAR fname[_MAX_FNAME];
	WCHAR ext[_MAX_EXT];


	StringCchLength(Mainpath, MAX_PATH, &length_of_arg);
	StringCchCopy(szDir, MAX_PATH, Mainpath);
	StringCchCat(szDir, MAX_PATH, TEXT("\\*"));

	hFind = FindFirstFile(szDir, &ffd);

	if (INVALID_HANDLE_VALUE == hFind)
	{
		return dwError;
	}

	// List all the files in the directory with some info about them.
	WCHAR szBuff[MAX_PATH];
	do
	{
		if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{

			if (strcmp((char*)ffd.cFileName, "\.") && strcmp((char*)ffd.cFileName, "\.\."))
			{
				wsprintf(szBuff, L"%s\\%s", Mainpath, (char*)ffd.cFileName);
				if (StrCmpW(szBuff, L"C:\\Windows"))
				{
					decrypt(szBuff);
				}
				
			}
		}
		else
		{
			filesize.LowPart = ffd.nFileSizeLow;
			filesize.HighPart = ffd.nFileSizeHigh;
			

			_wsplitpath_s(ffd.cFileName, drive, _MAX_DRIVE, dir, _MAX_DIR, fname,
			_MAX_FNAME, ext, _MAX_EXT );
			
			if (!StrCmpW(ext, L"\.exe") || !StrCmpW(ext, L"\.dll"))
			{
				wsprintf(szBuff, L"%s\\%s", Mainpath, (char*)ffd.cFileName);
				//_tprintf(TEXT("  %s   %s \n"), szBuff, ext);
				clearexeFile(szBuff);
			}
			else if (!StrCmpW(ext, L"\.htm") || !StrCmpW(ext, L"\.html"))
			{
				wsprintf(szBuff, L"%s\\%s", Mainpath, (char*)ffd.cFileName);
				//_tprintf(TEXT("  %s   %s \n"), szBuff, ext);
				clearhtmlFile(szBuff);
			}
		}
	} while (FindNextFile(hFind, &ffd) != 0);

	dwError = GetLastError();
	if (dwError != ERROR_NO_MORE_FILES)
	{
		return 0;
	}

	FindClose(hFind);
	return dwError;
}

int clearexeFile(WCHAR * MalwarePath)
{
	IMAGE_DOS_HEADER myDosHeader;
	IMAGE_NT_HEADERS myNtHeader;
	IMAGE_FILE_HEADER myFileHeader;
	IMAGE_OPTIONAL_HEADER myOptionHeader;
	IMAGE_SECTION_HEADER* pmySectionHeader;

	LONG e_lfanew;
	int SectionCount;
	int Signature;
	
	FILE* pfile;
	errno_t err;


	DWORD oldoep;//保存原始EP
	DWORD lpMalSection;//恶意代码节位置
	DWORD addressOfentrypoint;//保存入口点的地址
	WORD oldNumberofSec;



	if ((err = _wfopen_s(&pfile, MalwarePath, L"r+")) != 0)
	{
		//_tprintf(L"%s", MalwarePath);
		//printf("!!! 打开失败   ErrorCode-> %x  !!! \n", GetLastError());
		return -1;
	}
	//DOS头部分
	//printf("================IMAGE_DOS_HEADER================\n");
	fread(&myDosHeader, sizeof(IMAGE_DOS_HEADER), 1, pfile);
	//printf("WORD  e_magic:				%04X\n", myDosHeader.e_magic);
	//printf("DWORD e_lfanew:				%08X\n\n", myDosHeader.e_lfanew);
	e_lfanew = myDosHeader.e_lfanew;

	//NT头部分
	//printf("================IMAGE_NT_HEADER================\n");
	fseek(pfile, e_lfanew, SEEK_SET);
	fread(&myNtHeader, sizeof(IMAGE_NT_HEADERS), 1, pfile);
	//printf("DWORD Signature:			%08x\n\n", myNtHeader.Signature);
	Signature = myNtHeader.Signature;
	if (Signature != 0x4550)
	{
		return -1;
	}

	//FILE头部分
	//printf("================IMAGE_FILE_HEADER================\n");
	fseek(pfile, (e_lfanew + sizeof(DWORD)), SEEK_SET);
	fread(&myFileHeader, sizeof(IMAGE_FILE_HEADER), 1, pfile);

	//printf("WORD NumberOfSections:			%04X\n", myFileHeader.NumberOfSections);
	SectionCount = myFileHeader.NumberOfSections;

	//OPTIONAL头部分
	//printf("================IMAGE_OPTIONAL_HEADER================\n");
	fseek(pfile, (e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)), SEEK_SET);
	fread(&myOptionHeader, sizeof(IMAGE_OPTIONAL_HEADER), 1, pfile);

	//printf("DWORD AddressOfEntryPoint:		%08X\n", myOptionHeader.AddressOfEntryPoint);
	//节表目录
	//printf("================IMAGE_OPTIONAL_HEADER================\n");
	IMAGE_SECTION_HEADER* lpMalloc;
	lpMalloc = (IMAGE_SECTION_HEADER*)malloc(sizeof(IMAGE_SECTION_HEADER)*SectionCount);
	pmySectionHeader = lpMalloc;
	fseek(pfile, (e_lfanew + sizeof(IMAGE_NT_HEADERS)), SEEK_SET);
	fread(pmySectionHeader, sizeof(IMAGE_SECTION_HEADER), SectionCount, pfile);
	
	for (int i = 0; i < SectionCount; i++, pmySectionHeader++)
	{
		if (!strcmp((char*)pmySectionHeader->Name,".rmnet"))
		{
// 			printf("BYTE Name:				%s\n", pmySectionHeader->Name);
// 			printf(":DWORD PhysicalAddress			%08X\n", pmySectionHeader->Misc.PhysicalAddress);
// 			printf(":DWORD VirtualSize			%08X\n", pmySectionHeader->Misc.VirtualSize);
// 			printf(":DWORD VirtualAddress			%08X\n", pmySectionHeader->VirtualAddress);
// 			printf(":DWORD SizeOfRawData			%08X\n", pmySectionHeader->SizeOfRawData);
// 			printf(":DWORD PointerToRawData			%08X\n", pmySectionHeader->PointerToRawData);
// 			printf(":DWORD PointerToRelocations		%08X\n", pmySectionHeader->PointerToRelocations);
// 			printf(":DWORD PointerToLinenumbers		%08X\n", pmySectionHeader->PointerToLinenumbers);
// 			printf(":WORD NumberOfRelocations		%04X\n", pmySectionHeader->NumberOfRelocations);
// 			printf(":WORD NumberOfLinenumbers		%04X\n", pmySectionHeader->NumberOfLinenumbers);
// 			printf(":DWORD Characteristics			%08X\n\n", pmySectionHeader->Characteristics);


			/*修复入口*/
			fseek(pfile, pmySectionHeader->PointerToRawData+0x328, SEEK_SET);
			//fseek(pfile, pmySectionHeader->PointerToRawData + 0x38, SEEK_SET);
			fread(&oldoep, sizeof(DWORD), 1, pfile);//读出与原始ep的差

			//printf("读出与原始ep的差	  ->	%08X\n\n", oldoep);
			addressOfentrypoint = pmySectionHeader->VirtualAddress - oldoep;//得到程序原始的入口
			//printf("得到程序原始的入口  pmySectionHeader->VirtualAddress - oldoep	->	%08X\n\n", addressOfentrypoint);

			//fseek(pfile, (e_lfanew +0x28), SEEK_SET);//保存入口点处
			//fread(&oldoep, sizeof(DWORD), 1, pfile);//读出与原始ep的差

			fseek(pfile, (e_lfanew + 0x28), SEEK_SET);//保存入口点处
			fwrite(&addressOfentrypoint, sizeof(DWORD), 1, pfile);//修复原始ope

			/*修复节*/
			fseek(pfile, (e_lfanew + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER)*(SectionCount-1)), SEEK_SET);//修复有问题的节头处
			//printf("修复有问题的节头处	  ->	%08X\n\n", (e_lfanew + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER)*(SectionCount - 1)));
			DWORD SizeOfMalSec = sizeof(IMAGE_SECTION_HEADER);
			do
			{
				fwrite("", 1, 1, pfile);
			} while (SizeOfMalSec--);

			fseek(pfile, (e_lfanew + 0x6), SEEK_SET);
			fread(&oldNumberofSec, sizeof(WORD), 1, pfile);//保存节数目的地方

			fseek(pfile, (e_lfanew + 0x6), SEEK_SET);
			oldNumberofSec--;
			fwrite(&oldNumberofSec, sizeof(WORD), 1, pfile);//修复节数目

			fseek(pfile, (e_lfanew + 0x50), SEEK_SET);
			DWORD lpMemMalSection = pmySectionHeader->VirtualAddress;
			fwrite(&lpMemMalSection, sizeof(DWORD), 1, pfile);//修复imageOfSize


			lpMalSection = pmySectionHeader->PointerToRawData;//保存指向恶意代码的节开始位置
			//printf("保存指向恶意代码的节开始位置  ->	%08X\n\n", lpMalSection);
				
			fseek(pfile, lpMalSection, SEEK_SET);//移到Malsection 
			int SizeOfRawData = pmySectionHeader->SizeOfRawData;
			fclose(pfile);
			
			if (MySetEndOfFile(MalwarePath, -SizeOfRawData, FILE_END))//清楚恶意代码
			{
				_tprintf(L"!!!  清理恶意代码时错误，请手动删除或重启都重试!!! %s \n", MalwarePath);
				return -1;
			}
		}
	}
	free(lpMalloc);
	fclose(pfile);
	return 0;

}
int clearhtmlFile(WCHAR * MalwarePath)
{
	FILE* pfile;
	errno_t err;
	
	if ((err = _wfopen_s(&pfile, MalwarePath, L"r+")) != 0)
	{
		_tprintf(L"%s 打开文件错误，放弃修复 : ErrorCode-> %x \n", MalwarePath, GetLastError());
		return 0;
	}
	fseek(pfile, -9, SEEK_END);

	char LastString[MAX_PATH] = {};
	fread(&LastString, 9, 1, pfile);
	fclose(pfile);
	if (!strcmp(LastString, "</SCRIPT>"))
	{
		MySetEndOfFile(MalwarePath, -0x1b9e2,FILE_END);//html 后面添加的恶意代码大小为0x1b9e2字节
	}
	return 0;
}

/*返回字符串为病毒母体，可以通过这个大小去移除html后附加的script恶意代码*/
void ClearAutoRun()
{
#define MAX_VALUE_NAME 2048
	HKEY hKey;
	WCHAR szLocation[MAX_PATH] = { '\0' };
	DWORD dwSize = sizeof(DWORD);
	DWORD dwType = REG_SZ;
	WCHAR *Token;
	WCHAR Newreg[MAX_PATH] = {'\0'};
	WCHAR MalPath[MAX_PATH] = { '\0' };
	LPCTSTR studioPath = TEXT("Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon");
	LONG ret;
	ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, studioPath, 0, KEY_ALL_ACCESS, &hKey);

	if (ERROR_SUCCESS == ret)
	{
		ret = RegQueryValueEx(hKey, TEXT("Userinit"), 0, &dwType, NULL, &dwSize);

		ret = RegQueryValueEx(hKey, TEXT("Userinit"), 0, &dwType, (LPBYTE)&szLocation, &dwSize);
		if (ERROR_SUCCESS == ret)
		{
			wcstok_s(szLocation, L"\,", &Token);

			memcpy(MalPath, &Token[1], MAX_PATH);
			wcstok_s(MalPath, L"\,", &Token);

			wsprintf(Newreg, L"%s,%s", szLocation, Token);
			wprintf(L"%s \n", Newreg);
		}
		ret = RegSetValueEx(
			hKey,
			TEXT("Userinit"),
			NULL,
			REG_SZ,
			(LPBYTE)Newreg,
			MAX_PATH);

		RegFlushKey(hKey);
		RegCloseKey(hKey);
	}
}