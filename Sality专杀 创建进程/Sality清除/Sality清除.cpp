
//Ŀǰ�Ѿ��ܹ��Զ����޸������ļ���ԭ����ͨ�������½������У�Ч���е��


#include "stdafx.h"
#include "Sality.h"

char *Path = "C:\\Users\\sam\\Desktop\\7zFM.vvv";

int _tmain(int argc, _TCHAR* argv[])
{

	
	copy(Path);//���渱��
	
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
		printf("�����߳�ʧ�ܣ�%x", GetLastError());
	}
	WaitForSingleObject(hthread, INFINITE);
	CloseHandle(hthread);
	printf("�ѹر��߳�");

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
		&pi))//���������ӽ���
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
			if (ExceptCode == EXCEPTION_BREAKPOINT)//�����int 3 �ϵ�
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

				ReadProcessMemory((HANDLE)pi.hProcess, regESP, &base1116, 4, NULL);//��esp�Ĵ�����ֵ
				printf("ESP=>0x%x,ESPValue=>%x\n", regESP, base1116);

				

				//����ԭʼOEP��С
				ReadProcessMemory((HANDLE)pi.hProcess, (LPDWORD)(base1116 + 0x13fb), &PEstruct.SizeOfOep, 4, NULL);
				printf("OEP Size =>%x\n", PEstruct.SizeOfOep);

				//����ԭʼOEP����
				ReadProcessMemory((HANDLE)pi.hProcess, (LPBYTE)(base1116 + 0x13ff), PEstruct.oldOEP, PEstruct.SizeOfOep, NULL);

				//����ԭʼ�ļ���С
				ReadProcessMemory((HANDLE)pi.hProcess, (LPDWORD)(base1116 + 0x1407 + PEstruct.SizeOfOep), &PEstruct.SizeOfimage, 4, NULL);

				//��ȡ���һ���ڵ����� 
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
	Purpose:PE�ļ����ڴ�ƫ�����ļ�ƫ���໥ת��,������ϵͳΪ�������ƫ��ת��
	szFileName:�ļ���
	dwAddr:��Ҫת����ƫ��ֵ
	bFile2RVA:�Ƿ����ļ�ƫ�Ƶ��ڴ�ƫ�Ƶ�ת����1 - dwAddr��������ļ�ƫ�ƣ��˺��������ڴ�ƫ��
	0 - dwAddr��������ڴ�ƫ�ƣ��˺��������ļ�ƫ��
	����ֵ�����Ӧ��ƫ��ֵ,ʧ�ܷ���-1
	*/
	DWORD dwRet = -1;

	//2.��ȡ���ļ�����Ϣ���ļ��ڴ���뷽ʽ�Լ��������������������ָ��ָ��������һ������ͷ��  
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBase;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((unsigned long)lpBase + pDosHeader->e_lfanew);

	DWORD dwMemAlign = pNtHeader->OptionalHeader.SectionAlignment;
	DWORD dwFileAlign = pNtHeader->OptionalHeader.FileAlignment;
	int dwSecNum = pNtHeader->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER pSecHeader = (PIMAGE_SECTION_HEADER)((char *)lpBase + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));
	DWORD dwHeaderSize = 0;

	if (!bFile2RVA)  // �ڴ�ƫ��ת��Ϊ�ļ�ƫ��  
	{
		//����Ҫת�Ƶ�ƫ���Ƿ���PEͷ�ڣ������������ƫ����ͬ  
		dwHeaderSize = pNtHeader->OptionalHeader.SizeOfHeaders;
		if (dwAddr <= dwHeaderSize)
		{
			delete lpBase;
			lpBase = NULL;
			return dwAddr;
		}
		else //����PEͷ��鿴�õ�ַ���ĸ�������  
		{
			for (int i = 0; i < dwSecNum; i++)
			{
				DWORD dwSecSize = pSecHeader[i].Misc.VirtualSize;
				if ((dwAddr >= pSecHeader[i].VirtualAddress) && (dwAddr <= pSecHeader[i].VirtualAddress + dwSecSize))
				{
					//3.�ҵ��ø�ƫ�ƣ����ļ�ƫ�� = ��������ļ�ƫ�� + ����ƫ�� - ��������ڴ�ƫ�ƣ�  
					dwRet = pSecHeader[i].PointerToRawData + dwAddr - pSecHeader[i].VirtualAddress;
				}
			}
		}
	}
	else // �ļ�ƫ��ת��Ϊ�ڴ�ƫ��  
	{
		dwHeaderSize = pNtHeader->OptionalHeader.SizeOfHeaders;
		//����Ҫת�Ƶ�ƫ���Ƿ���PEͷ�ڣ������������ƫ����ͬ  
		if (dwAddr <= dwHeaderSize)
		{
			delete lpBase;
			lpBase = NULL;
			return dwAddr;
		}
		else//����PEͷ��鿴�õ�ַ���ĸ�������  
		{
			for (int i = 0; i < dwSecNum; i++)
			{
				DWORD dwSecSize = pSecHeader[i].Misc.VirtualSize;
				if ((dwAddr >= pSecHeader[i].PointerToRawData) && (dwAddr <= pSecHeader[i].PointerToRawData + dwSecSize))
				{
					//3.�ҵ��ø�ƫ�ƣ����ڴ�ƫ�� = ��������ڴ�ƫ�� + ����ƫ�� - ��������ļ�ƫ�ƣ�  
					dwRet = pSecHeader[i].VirtualAddress + dwAddr - pSecHeader[i].PointerToRawData;
				}
			}
		}
	}
	return dwRet;
}

DWORD Fixexe(char *lpPath2)
{
	//���ļ�
	printf("���޸��ļ� %s\n", lpPath2);
	HANDLE hFile = CreateFileA(lpPath2, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("\n���ļ��������%x", GetLastError());
		CloseHandle(hFile);
		getchar();
		return 0;
	}
	//ӳ�䵽�ڴ���
	HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
	if (hMapping == NULL)
	{
		printf("�ļ�ӳ�����%x", GetLastError());
		CloseHandle(hMapping);
		return 0;
	}
	PVOID pbFile = MapViewOfFile(hMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	if (pbFile == NULL)
	{
		printf("MapViewOfFile����%x", GetLastError());
		UnmapViewOfFile(pbFile);
		return 0;
	}

	/*���DOSͷ*/
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pbFile;

	//���NTͷ
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pbFile + pDosHeader->e_lfanew);

	printf("%x,%x", pNtHeader->OptionalHeader.AddressOfEntryPoint, pNtHeader->OptionalHeader.ImageBase);
	
	DWORD retva = AddressConvert(pDosHeader, pNtHeader->OptionalHeader.AddressOfEntryPoint, 0);
	printf("�ļ�ƫ��%x\n", retva);

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