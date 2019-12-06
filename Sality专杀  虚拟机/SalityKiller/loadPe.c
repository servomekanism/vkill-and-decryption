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
	////����һ���ļ������������ڴ���չ���������    ////////////////////////////
	//////////////////////////////////////////////////////////////////////////
	LPBYTE lpBuf = NULL;
	FARPROC lpEntryPoint = NULL;
	//LPCSTR lpFilePath = "D:\\Project\\CUI\\�ճ�����\\Release\\MassageBox����ר��.exe";
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

	//�����ڴ治�ܱ��ͷţ����ڴ�й©�Ŀ���

	return lpBuf;
}

FARPROC InitEnv(LPBYTE lpMemBuffer)
{
	//////////////////////////////////////////////////////////////////////////
	////�޸�ImageBase��������ڵ�                                           ///
	//////////////////////////////////////////////////////////////////////////
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)lpMemBuffer;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(lpMemBuffer + pDos->e_lfanew);
	pNt->OptionalHeader.ImageBase = lpMemBuffer;

	return lpMemBuffer + pNt->OptionalHeader.AddressOfEntryPoint;
}

BOOL InitIAT(LPBYTE lpMemBuffer)
{
	//////////////////////////////////////////////////////////////////////////
	////�޸�IAT                                                            
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
				printf("����%sʧ�ܣ�[%x]\n ", szDllname, GetLastError());
				return FALSE;
			}
		}

		//dll���سɹ�����ʼ������Ҫ�ĺ���
		lpOrgNameArry = (PIMAGE_THUNK_DATA)(lpMemBuffer + pImportTalbe->OriginalFirstThunk);

		lpFirNameArry = (PIMAGE_THUNK_DATA)(lpMemBuffer + pImportTalbe->FirstThunk);

		i = 0;

		while (lpOrgNameArry[i].u1.AddressOfData)
		{
			lpImportByNameTable = (PIMAGE_IMPORT_BY_NAME)(lpMemBuffer + lpOrgNameArry[i].u1.AddressOfData);

			if (lpOrgNameArry[i].u1.Ordinal & 0x80000000)
			{
				//��ŵ���
				Funaddr = GetProcAddress(hMou, (LPSTR)(lpOrgNameArry[i].u1.Ordinal & 0xFFFF));
			}
			else
			{
				//���Ƶ���
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
	////�޸��ض�λ��                                                        ///
	////ԭ�������ض�λ��������Ҫ�ض�λ���ݵĵ�ַ���ض�λ��ĵ�ַ = ��Ҫ�ض�λ�ĵ�ַ - Ĭ�ϼ��ػ�ַ + ��ǰ���ػ�ַ
	//////////////////////////////////////////////////////////////////////////
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)lpMemBuffer;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(lpMemBuffer + pDos->e_lfanew);
	//����ض�λ��
	PIMAGE_BASE_RELOCATION pReloca = (PIMAGE_BASE_RELOCATION)(lpMemBuffer + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	//����ض�λ��Ϊ�գ��������ʽΪpDos+0
	if ((LPBYTE)pReloca == lpMemBuffer)
	{
		printf("û���ض�λ��\n");
		return TRUE;
	}

	while (pReloca->VirtualAddress != 0 && pReloca->SizeOfBlock != 0)
	{
		LPWORD pRelData = (LPBYTE)pReloca + sizeof(IMAGE_BASE_RELOCATION);
		int nNumRel = (pReloca->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		for (int i = 0; i < nNumRel; i++)
		{
			// ÿ��WORD����������ɡ���4λָ�����ض�λ�����ͣ�WINNT.H�е�һϵ��IMAGE_REL_BASED_xxx�������ض�λ���͵�ȡֵ��
			// ��12λ�������VirtualAddress���ƫ�ƣ�ָ���˱�������ض�λ��λ�á�

			if ((WORD)(pRelData[i] & 0xF000) == 0x3000) //����һ����Ҫ�����ĵ�ַ
			{
				//pReloca->VirtualAddress�����ҳ���ʣ�(һ��ҳ4K��������0xFFF���պ�12λ)
				LPDWORD pAddress = (LPDWORD)(lpMemBuffer + pReloca->VirtualAddress + (pRelData[i] & 0x0FFF));


				*pAddress = *pAddress - pNt->OptionalHeader.ImageBase + (DWORD)pDos;

				printf("Check!");
				//DWORD dwDelta = (DWORD)pDos - pNt->OptionalHeader.ImageBase;
				//*pAddress += dwDelta;
			}
		}
		pReloca = (LPBYTE)pReloca + pReloca->SizeOfBlock;
	}
	printf("�ض�λ���޸���ɣ�\n");
	return TRUE;
}

LPBYTE Extension(LPBYTE lpFileBuffer)
{
	//////////////////////////////////////////////////////////////////////////
	////���ļ����ڴ���չ��                                                  ///
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

	//�ļ�ͷ�Ĵ�С
	DWORD dwSizeOfHeader = pNt->OptionalHeader.SizeOfHeaders;

	//��ͷ��������ȥ
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

	//�Ѿ���ȫӳ�䣬���԰�֮ǰ���ڴ��ͷŵ���
	free(lpFileBuffer);
	return lpMemBuffer;
}

LPBYTE LoadFileToMem(LPCSTR lpFilePath)
{
	//////////////////////////////////////////////////////////////////////////
	////��Դ�ļ������ڴ���                                                  ///
	//////////////////////////////////////////////////////////////////////////
	DWORD FileSize = 0;
	LPBYTE Buff = NULL;

	HANDLE hFile = CreateFileA(lpFilePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("���ļ��������[%x]", GetLastError());
		return -1;
	}

	FileSize = GetFileSize(hFile, NULL);

	Buff = (LPBYTE)malloc(FileSize);
	if (Buff == NULL)
	{
		printf("�ռ�����ʧ��![%x]", GetLastError());
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
	//VirtualFree��������
	if (!VirtualFree(lpBuffer, 0, MEM_RELEASE))
	{
		printf("�ռ��ͷ�ʧ�ܣ�[0x%x]\n", GetLastError());
		return -1;
	}
	return 0;
}