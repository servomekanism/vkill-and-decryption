#include "stdafx.h"
#include "GetInstctLen.h"
#include <stdio.h> 

//基本指令没问题，jcc跳转待完善，动态修改还需要处理

BYTE szKey[32] = { 0, };
BOOL decrypt(LPBYTE Buffer, DWORD KeyAddrBase);
DWORD AddressConvert(PIMAGE_DOS_HEADER lpBase, DWORD dwAddr, BOOL bFile2RVA);

char * filepath = "C:\\Users\\Sam\\Desktop\\111.exe";

BYTE *OpCode2Asm()
{
	signed int v0;
	unsigned int Sec1t5;

	DWORD v16;
	DWORD *v17;
	void **v18;
	void *v19;
	unsigned int v20;
	int v21;
	int v22;
	char *v23;
	int v29;
	int v30;
	int v31;
	int v33;
	int v34;
	int v35;


	v29 = 0;
	v30 = 0;
	v31 = 0;
	v33 = 0;
	v34 = 0;
	v35 = 0;
	v0 = 0x90;

	DWORD Tmp1 = 0;
	DWORD Tmp2 = 0;
	DWORD eflags = 0;
	//cf = eflags & 0x1
	//zf = eflags & 0x40
	//sf = eflags & 0x80

	int Sec6t8;
	int Sec1t2;
	int Sec3t5;
	unsigned int v26 = 0;
	int szStackValue[0x500] = { 0 };
	DWORD szRegValue[8] = { 0 };
	DWORD szRegMmx[8] = { 0, };
	unsigned int stackPoint = 0x300;//栈大小初始状态为0x30大小，总大小为0x100
	BOOL Zflag = FALSE; //zf标志位
	unsigned int InstructiLen;
	int RegValue;
	unsigned int Base2NextInstructtOffset;
	signed int FirInstruct;
	unsigned __int8 Sectinstructioncode;
	DWORD KeyAddrBase = 0;
	DWORD FileKeyAddrBase = 0;
	DWORD KeyOffset = 0;
	DWORD aa = 0;
	size_t len;

	PIMAGE_DOS_HEADER MemImageBase = (PIMAGE_DOS_HEADER)RepairFile(filepath, len);
	if (MemImageBase == nullptr)
	{
		printf("malloc error!");
		return nullptr;
	}
	PIMAGE_NT_HEADERS Ntheader = (PIMAGE_NT_HEADERS)(MemImageBase->e_lfanew + (DWORD)MemImageBase);
	KeyAddrBase = (DWORD)MemImageBase;

	Base2NextInstructtOffset = AddressConvert(MemImageBase, Ntheader->OptionalHeader.AddressOfEntryPoint, 0);

	while (1)
	{

		InstructiLen = (unsigned int)aninstructionlen_414BA0((unsigned char*)MemImageBase + Base2NextInstructtOffset);//返回当前指令长度
		if (InstructiLen == -1)
			return 0;

		FirInstruct = *((unsigned __int8 *)MemImageBase + Base2NextInstructtOffset);
		Sec6t8 = 0;
		Sec1t2 = 0;
		Sec3t5 = 0;

		if (InstructiLen > 1)
		{
			Sectinstructioncode = *((BYTE *)MemImageBase + Base2NextInstructtOffset + 1);// 如果 Sectincode = 1111 1111
			Sec1t5 = (unsigned int)Sectinstructioncode >> 3;// v7 = 1111 1000 取前5位值 下面同理
			Sec1t2 = *((BYTE *)MemImageBase + Base2NextInstructtOffset + 1) >> 6;// v4 = 1100 0000
			Sec6t8 = Sectinstructioncode & 7;         // v7   =       0000 0111
			Sec3t5 = Sec1t5 & 7;                      // v5   =       0011 1000 

		}
		switch (FirInstruct)
		{
		case 3:
			*(szRegValue + Sec3t5) += *(szRegValue + Sec6t8);// 简单的两个寄存器的加法
			goto defautCase;
		case 5:
			*szRegValue += *(DWORD *)((char *)MemImageBase + Base2NextInstructtOffset + 1);// 直接加一个立即数
			goto defautCase;
		case 0xB:
			*(szRegValue + Sec3t5) |= *(szRegValue + Sec6t8);// 异或两个寄存器
			goto defautCase;
		case 0xD:
			*szRegValue |= *(DWORD *)((char *)MemImageBase + Base2NextInstructtOffset + 1);// 异或一个立即数
			goto defautCase;
		case 0xF:                                 // 交换并相加
			if (*((BYTE *)MemImageBase + Base2NextInstructtOffset + 1) == 0xC1u //xadd
				&& (*(BYTE *)(Base2NextInstructtOffset + (BYTE*)MemImageBase + 2) & 0xC0) == 0xC0u)// (BYTE*)MemImageBase + 2 = 0x46C3E8 + 2
			{


				v20 = ((unsigned int)*(unsigned __int8 *)(Base2NextInstructtOffset + (BYTE*)MemImageBase + 2) >> 3) & 7;
				v21 = *(szRegValue + v20);           // 寄存器2的值
				v22 = *(BYTE *)(Base2NextInstructtOffset + (BYTE*)MemImageBase + 2) & 7;
				v23 = (char *)*(szRegValue + v22);   // 寄存器1的值
				*(szRegValue + v20) = (DWORD)v23;
				*(szRegValue + v22) = (DWORD)&v23[v21];
			}
			if (*((BYTE *)MemImageBase + Base2NextInstructtOffset + 1) == 0x6Eu)//movd
			{
				// 寄存器1
				v20 = ((unsigned int)*(unsigned __int8 *)(Base2NextInstructtOffset + (BYTE*)MemImageBase + 2) >> 3) & 7;
				v22 = *(BYTE *)(Base2NextInstructtOffset + (BYTE*)MemImageBase + 2) & 7;
				v23 = (char *)*(szRegValue + v22);   // 寄存器2的值
				*(szRegMmx + v20) = (DWORD)v23;
			}
			if (*((BYTE *)MemImageBase + Base2NextInstructtOffset + 1) == 0x7Eu)//movd
			{
				// 寄存器2
				v20 = ((unsigned int)*(unsigned __int8 *)(Base2NextInstructtOffset + (BYTE*)MemImageBase + 2) >> 3) & 7;
				v23 = (char *)*(szRegMmx + v20);
				v22 = *(BYTE *)(Base2NextInstructtOffset + (BYTE*)MemImageBase + 2) & 7;
				// 寄存器1的值
				*(szRegValue + v22) = (DWORD)v23;
			}


			if (Sectinstructioncode >> 4 == 8)//跳转成立
			{
				if ((Sectinstructioncode & 0xf) == 2)
				{
					if ((eflags & 0x1) == 1)
					{
						Base2NextInstructtOffset += *(int *)(Base2NextInstructtOffset + (BYTE*)MemImageBase + 2);//jb 跳转
						goto defautCase;
					}
				}
			}

			goto defautCase;
		case 0x23:
			*(szRegValue + Sec3t5) &= *(szRegValue + Sec6t8);// 两寄存器相and
			goto defautCase;
		case 0x25:
			*szRegValue &= *(DWORD *)((char *)MemImageBase + Base2NextInstructtOffset + 1);// 立即数与寄存器相and
			goto defautCase;
		case 0x26:
		case 0x2E:
		case 0x36:
		case 0x3E:
		case 0x64:
		case 0x65:
		case 0xF2:
		case 0xF3:                                // 这种指令认为是一字节的无用指令 直接将混淆代码的指针往后移动一字节
			InstructiLen = 1;
			goto defautCase;
		case 0x2B:
			*(szRegValue + Sec3t5) -= *(szRegValue + Sec6t8);// 寄存器间的相减
			goto defautCase;
		case 0x2D:                                // 直接减立即数
			*szRegValue -= *(DWORD *)((char *)MemImageBase + Base2NextInstructtOffset + 1);
			goto defautCase;
		case 0x33:
			*(szRegValue + Sec3t5) ^= *(szRegValue + Sec6t8);// 寄存器间的异或
			goto defautCase;
		case 0x35:
			*szRegValue ^= *(DWORD *)((char *)MemImageBase + Base2NextInstructtOffset + 1);// 寄存器与立即数间的异或
			goto defautCase;
		case 0x50:                                // push eax
		case 0x51:                                // push ecx
		case 0x52:                                // push edx
		case 0x53:                                // push ebx
		case 0x54:                                // push esp
		case 0x55:                                // push ebp
		case 0x56:                                // push esi
		case 0x57:                                // push edi
			printf("push at:%x push value:%x \n", AddressConvert(MemImageBase, Base2NextInstructtOffset, 1) + Ntheader->OptionalHeader.ImageBase, *(szRegValue + (FirInstruct & 7)));

			if (KeyAddrBase + 0xfff > *(szRegValue + (FirInstruct & 7)) && *(szRegValue + (FirInstruct & 7)) > KeyAddrBase)
			{
				for (KeyOffset = KeyAddrBase; KeyOffset < (KeyAddrBase + 0x30); KeyOffset++)//Break Key1
				{
					aa = (DWORD)AddressConvert(MemImageBase, *(szRegValue + (FirInstruct & 7)) - Ntheader->OptionalHeader.ImageBase, 0);//FOV
					//aa = (DWORD)AddressConvert(MemImageBase, KeyOffset - Ntheader->OptionalHeader.ImageBase, 0);//FOV

					memcpy(szKey, (LPBYTE)MemImageBase + aa, 32);

					FileKeyAddrBase = AddressConvert(MemImageBase, (KeyAddrBase & 0xFFFFFF00) + 0x1116 - Ntheader->OptionalHeader.ImageBase, 0);

					decrypt((LPBYTE)MemImageBase, FileKeyAddrBase);
				}

				printf("break!\n");
			}
			getchar();
			stackPoint -= 4;                        // 减小栈帧4字节
			RegValue = *(szRegValue + (FirInstruct & 7));
			goto pushlab;
		case 0x58:                                // pop eax
		case 0x59:
		case 0x5A:
		case 0x5B:                                // 和push 顺序一样
		case 0x5C:
		case 0x5D:
		case 0x5E:
		case 0x5F:                                // pop edi
			printf("pop at:%x  value = %x\n", AddressConvert(MemImageBase, Base2NextInstructtOffset, 1) + Ntheader->OptionalHeader.ImageBase, szStackValue[stackPoint / 4]);
			*(szRegValue + (FirInstruct & 7)) = szStackValue[stackPoint / 4];

			stackPoint += 4;

			goto defautCase;
		case 0x68:                                // push Dword 立即数
			//v15 = stackPoint - 4;
			stackPoint -= 4;

			*(int *)((char *)szStackValue + stackPoint) = *(DWORD *)((char *)MemImageBase + Base2NextInstructtOffset + 1);
			goto defautCase;
		case 0x69:                                // 有符号乘法
			*(szRegValue + Sec3t5) = *(DWORD *)(Base2NextInstructtOffset + (BYTE*)MemImageBase + 2) * *(szRegValue + Sec6t8);
			goto defautCase;
		case 0x6A:
			stackPoint -= 4;

			RegValue = *((unsigned __int8 *)MemImageBase + Base2NextInstructtOffset + 1);// push bit立即数
		pushlab:
			*(int *)((char *)szStackValue + stackPoint) = RegValue;
			goto defautCase;
		case 0x6B:
			*(szRegValue + Sec3t5) = *(szRegValue + Sec6t8) * *(unsigned __int8 *)(Base2NextInstructtOffset + (BYTE*)MemImageBase + 2);// 也是乘法
			goto defautCase;
		case 0x73:
			if ((eflags & 1) == 1)
			{
				printf("cmp addr:%x \n", AddressConvert(MemImageBase, Base2NextInstructtOffset, 1));


				Base2NextInstructtOffset = Base2NextInstructtOffset + *(BYTE *)((char *)MemImageBase + Base2NextInstructtOffset + 1);
				goto defautCase;
			}
		case 0x81:                                // + - & | ^  cmp
			if (Sec1t2 == 3)
			{
				switch (Sec3t5)
				{
				case 0:
					*(szRegValue + Sec6t8) += *(DWORD *)(Base2NextInstructtOffset + (BYTE*)MemImageBase + 2);
					break;
				case 1:
					*(szRegValue + Sec6t8) |= *(DWORD *)(Base2NextInstructtOffset + (BYTE*)MemImageBase + 2);
					break;
				case 4:
					*(szRegValue + Sec6t8) &= *(DWORD *)(Base2NextInstructtOffset + (BYTE*)MemImageBase + 2);
					break;
				case 5:
					*(szRegValue + Sec6t8) -= *(DWORD *)(Base2NextInstructtOffset + (BYTE*)MemImageBase + 2);
					break;
				case 6:
					*(szRegValue + Sec6t8) ^= *(DWORD *)(Base2NextInstructtOffset + (BYTE*)MemImageBase + 2);// *(_DWORD *)(v1 + (BYTE*)MemImageBase + 2);实际取后边的参数
					// 81 f0 20212223 xor eax,0x23222120
					break;
				case 7:   //cmp eax,0x11bba;
					Tmp1 = *(szRegValue + Sec6t8);
					Tmp2 = *(DWORD *)(Base2NextInstructtOffset + (BYTE*)MemImageBase + 2);
					__asm
					{
						mov edx, Tmp1;
						cmp edx, Tmp2;
						pushfd;
						pop eflags;
					}
					break;
				default:
					goto defautCase;
				}
			}
			goto defautCase;
		case 0x83:                                // 低2位的异或加减操作
			if (Sec1t2 == 3)
			{
				switch (Sec3t5)
				{
				case 0:
					*(szRegValue + Sec6t8) += *(unsigned __int8 *)(Base2NextInstructtOffset + (BYTE*)MemImageBase + 2);
					break;
				case 1:
					*(szRegValue + Sec6t8) |= *(unsigned __int8 *)(Base2NextInstructtOffset + (BYTE*)MemImageBase + 2);
					break;
				case 4:
					*(szRegValue + Sec6t8) &= *(unsigned __int8 *)(Base2NextInstructtOffset + (BYTE*)MemImageBase + 2);
					break;
				case 5:
					*(szRegValue + Sec6t8) -= *(unsigned __int8 *)(Base2NextInstructtOffset + (BYTE*)MemImageBase + 2);
					break;
				case 6:
					*(szRegValue + Sec6t8) ^= *(unsigned __int8 *)(Base2NextInstructtOffset + (BYTE*)MemImageBase + 2);
					break;
				default:
					goto defautCase;
				}
			}
			goto defautCase;
		case 0x87:                                // 交换两个寄存器的值
			v18 = (void **)(szRegValue + Sec3t5);
			v19 = *v18;
			*v18 = (void *)*(szRegValue + Sec6t8);
			*(szRegValue + Sec6t8) = (DWORD)v19;
			goto defautCase;
		case 0x8B:                                // mov 两个寄存器
			if (Sec1t2 == 3)
				*(szRegValue + (((unsigned int)*((unsigned __int8 *)MemImageBase + Base2NextInstructtOffset + 1) >> 3) & 7)) = *(szRegValue + (*((BYTE *)MemImageBase + Base2NextInstructtOffset + 1) & 7));
			if (Sec1t2 == 0)
			{
				//printf("mov reg ,[reg] at:0x%x,reg value %x", AddressConvert(MemImageBase, Base2NextInstructtOffset, 1), *(szRegValue + Sec6t8));

			}
			goto defautCase;
		case 0x8D:                                // lea
			if (Sec1t2)
			{
				if (Sec1t2 == 1 && InstructiLen == 3)
					*(szRegValue + Sec3t5) = *(szRegValue + Sec6t8);/*+ *(unsigned __int8 *)(Base2NextInstructtOffset + 4637674)*/
			}
			else if (InstructiLen == 2)
			{
				*(szRegValue + Sec3t5) = *(szRegValue + Sec6t8);
			}
			else if (InstructiLen == 6)
			{
				*(szRegValue + Sec3t5) = *(DWORD *)(Base2NextInstructtOffset + (BYTE*)MemImageBase + 2);// lea eax,0x12345 =>eax = 0x12345
			}
			//printf("lea %x at:0x%x \n", *(szRegValue + Sec3t5), AddressConvert(MemImageBase, Base2NextInstructtOffset, 1));
			goto defautCase;
		case 0x91:                                // xchg eax,Xreg
		case 0x92:
		case 0x93:
		case 0x94:
		case 0x95:
		case 0x96:
		case 0x97:
			v16 = *szRegValue;
			v17 = szRegValue + (FirInstruct & 7);
			*szRegValue = *v17;
			*v17 = v16;
			goto defautCase;
		case 0xB8:                                // mov eax
		case 0xB9:
		case 0xBA:
		case 0xBB:
		case 0xBC:
		case 0xBD:
		case 0xBE:
		case 0xBF:                                // mov edi
			*(szRegValue + (FirInstruct & 7)) = *(DWORD *)((char *)MemImageBase + Base2NextInstructtOffset + 1);// mov X,value
			goto defautCase;
		case 0xC3:                                // ret  返回值是堆底得绝对值

			printf("ret 目的地址：0x%x\n", szStackValue[stackPoint / 4]);
			KeyAddrBase = szStackValue[stackPoint / 4];

			Base2NextInstructtOffset = AddressConvert(MemImageBase, szStackValue[stackPoint / 4] - Ntheader->OptionalHeader.ImageBase, 0); //- (BYTE*)MemImageBase - 1;

			printf("ret 文件偏移为:0x%x\n", Base2NextInstructtOffset);

			szStackValue[stackPoint / 4] = 0;
			stackPoint += 4;


			/*for (KeyOffset = KeyAddrBase; KeyOffset < (KeyAddrBase + 0x30); KeyOffset++)
			{
			printf("keyOneOffset = %d\n", KeyOffset);
			//aa = (DWORD)AddressConvert(MemImageBase, *(szRegValue + (FirInstruct & 7)) - Ntheader->OptionalHeader.ImageBase, 0);//FOV
			aa = (DWORD)AddressConvert(MemImageBase, KeyOffset - Ntheader->OptionalHeader.ImageBase, 0);//FOV

			memcpy(szKey, (LPBYTE)MemImageBase + aa, 32);

			FileKeyAddrBase = AddressConvert(MemImageBase, (KeyAddrBase & 0xFFFFFF00) + 0x1116 - Ntheader->OptionalHeader.ImageBase, 0);

			decrypt((LPBYTE)MemImageBase, FileKeyAddrBase);
			}*/



			getchar();
			goto defautCase;

		case 0xE8:                                // call xxxx = push ret jmp xxxxx
			printf("call addr:%x \n", AddressConvert(MemImageBase, Base2NextInstructtOffset, 1));
			stackPoint -= 4;

			*(int *)((char *)szStackValue + stackPoint) = Ntheader->OptionalHeader.ImageBase + AddressConvert(MemImageBase, (DWORD)((BYTE*)Base2NextInstructtOffset + InstructiLen), 1);//保存返回地址

			Base2NextInstructtOffset = Base2NextInstructtOffset + *(DWORD *)((char *)MemImageBase + Base2NextInstructtOffset + 1);//jmp到call目的地址

			goto defautCase;

		case 0xE9:                                // 大跳
			Base2NextInstructtOffset = Base2NextInstructtOffset + *(DWORD *)((char *)MemImageBase + Base2NextInstructtOffset + 1);
			goto defautCase;

		case 0xEB:                                // 小跳（0-ff）
			Base2NextInstructtOffset += *((char *)MemImageBase + Base2NextInstructtOffset + 1);
			goto defautCase;
		case 0xFF:
			//0xFF 较为复杂，参考https://www.cnblogs.com/scu-cjx/p/6879041.html
			if (Sec1t2 != 3)
			{
				if (!Sec1t2
					&& Sec3t5 == 2
					&& *(DWORD *)(Base2NextInstructtOffset + (BYTE*)MemImageBase + 2) - Ntheader->OptionalHeader.ImageBase < Ntheader->OptionalHeader.SizeOfImage)
				{
					stackPoint += 4;
				}
			}
			if (Sec3t5 != 4)
				goto defautCase;
			//printf("call 类返回");
			//return (*(szRegValue + Sec6t8) - Ntheader->OptionalHeader.ImageBase);//call eax 这类
		default:
			goto defautCase;

		defautCase:
			Base2NextInstructtOffset += InstructiLen;
			v0 = FirInstruct;
			continue;
		}
	}
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

	//5.释放内存  
	// 	delete lpBase;
	// 	lpBase = NULL;
	return dwRet;
}

BOOL decrypt(LPBYTE Buffer, DWORD KeyAddrBase)
{
	LPBYTE CryptData = (LPBYTE)malloc(0xF);
	DWORD indexKey2 = 0;

	memcpy(CryptData, Buffer + KeyAddrBase, 0xF);

	for (indexKey2 = 0xffff; indexKey2 >= 0; indexKey2--)
	{
		unsigned *data = (unsigned *)CryptData;
		unsigned *nkey = (unsigned *)szKey;
		for (unsigned i = 0; i < 0xF / 8; i++) {
			for (unsigned j = 63; (int)j >= 0; --j) {
				unsigned *d, *s;
				s = (j & 1) ? &data[i * 2 + 1] : &data[i * 2];
				d = (j & 1) ? &data[i * 2] : &data[i * 2 + 1];
				*d -= *s + ((*s << 6) ^ (*s >> 8)) + (i * 8 + j) + indexKey2 + nkey[j & 7];
			}
		}
	}

	if (*CryptData == 0xE8 && *(CryptData + 1) == 0)
	{
		printf("Get!");
		getchar();
	}
	free(CryptData);
	return 1;
}

int _tmain(int argc, _TCHAR* argv[])
{
	OpCode2Asm();
	return 0;
}








