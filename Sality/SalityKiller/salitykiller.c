//////////////////////////////////////////////////////////////////////////
//salityרɱ���ļ��޸�δ�������Ǻ����Ѿ����                          //////
//˼·��ͨ�����ر���Ⱦ���ļ����ڴ棬һ������ִ�ж��������һ������Ƿ������ɣ�������ɾ͹رն������
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

	//����Ϳ����޸��ļ���
	LPSTR lpNewFile = WriteToFile(lpDecodeBytes);

	MyFreeBuff(lpBuff);
	return 0;

}

VOID RunMalCode(LPBYTE lpBuff)
{
	//ִ�ж�����ܴ���
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
	//���ڴ����ҵ��������룬�޸�Ϊret������ֵΪ�õ�ַ
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBuff;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(lpBuff + pDosHeader->e_lfanew);
	LPBYTE dwSizehigh = lpBuff + pNtHeader->OptionalHeader.SizeOfImage;

	PIMAGE_SECTION_HEADER pSecHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)pDosHeader + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));

	LPBYTE SearchBase = lpBuff + pSecHeader[pNtHeader->FileHeader.NumberOfSections - 1].VirtualAddress;

	for(; SearchBase < dwSizehigh; SearchBase++)
	{
		//����ֵ��81F9E2FE00000F8C????FFFFC3
		//�޸�Ϊ��81F9E2FE00000F8C????FFFFEBFE
		if (*(SearchBase) == 0x0f && *(SearchBase + 1) == 0x8c && *(SearchBase + 4) == 0xff && *(SearchBase + 5) == 0xff && *(SearchBase + 6) == 0xc3)
		{
			*(SearchBase + 6) = 0xEB;
			*(SearchBase + 7) = 0xFE;  //JMP ������ѭ��
			printf("find point opcode");
			break;
		}
	}
	return SearchBase + 6;
}

LPBYTE Check(LPBYTE lpBreakPointAddr, LPBYTE lpBuff)
{
	//////////////////////////////////////////////////////////////////////////
	////����Ƿ��Ѿ��������///////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBuff;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(lpBuff + pDosHeader->e_lfanew);
	LPBYTE lpImageOver = lpBuff + pNtHeader->OptionalHeader.SizeOfImage;
	//����Ƿ�������
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
	//������ȫ�����޸��ļ���Ȼ�󱣴�

	LPSTR NewFileName = "c:\\NewFile.exe";

	//�����õ�base1116��ƫ�ƺ󣬿��Ը��������ƫ��ȡ���ļ�ԭʼ��Ϣ
	//SizeOfOep = base1116 + 0x13fb			   ԭʼOEP��С
	//oldOEP = base1116 + 0x13ff			   ԭʼOEP��ʼλ��
	//base1116 + 0x1407 + PEstruct.SizeOfOep   ԭʼ�ļ���С
	//base1116 + 0x139f ��С0x28			       ԭʼ�ļ����һ���ڵĴ�С


// 	ReadProcessMemory((HANDLE)pi.hProcess, (LPDWORD)(base1116 + 0x13fb), &PEstruct.SizeOfOep, 4, NULL);
// 	printf("OEP Size =>%x\n", PEstruct.SizeOfOep);
// 
// 	//����ԭʼOEP����
// 	ReadProcessMemory((HANDLE)pi.hProcess, (LPBYTE)(base1116 + 0x13ff), PEstruct.oldOEP, PEstruct.SizeOfOep, NULL);
// 
// 	//����ԭʼ�ļ���С
// 	ReadProcessMemory((HANDLE)pi.hProcess, (LPDWORD)(base1116 + 0x1407 + PEstruct.SizeOfOep), &PEstruct.SizeOfimage, 4, NULL);
// 
// 	//��ȡ���һ���ڵ����� 
// 	ReadProcessMemory((HANDLE)pi.hProcess, (LPBYTE)(base1116 + 0x139f), PEstruct.lastsec, 0x28, NULL);
	
	return NewFileName;
}
