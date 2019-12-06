#include "stdafx.h"
#include "GetInstctLen.h"

LPBYTE RepairFile(LPSTR FilePath, size_t &len)
{
	//打开文件
	HANDLE hFile = CreateFileA(FilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);

	//映射到内存中
	//HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
	//PVOID pbFile = MapViewOfFile(hMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);

	len = GetFileSize(hFile, NULL);
	LPBYTE buffer = nullptr;
	buffer = (BYTE*)malloc(len);
	if (!ReadFile(hFile, buffer, len, (DWORD*)&len, NULL))
	{
		free(buffer);
		buffer = nullptr;
	}

	CloseHandle(hFile);
	return buffer;

}

unsigned __int8 *__cdecl aninstructionlen_414BA0(unsigned __int8 *a1)
{
	// 传入opcode，返回第一条汇编的长度
	unsigned int thispos; // edx
	int v2; // ebx
	int v3; // ecx
	signed int v4; // edi
	unsigned __int8 *nextpos; // esi
	signed int v6; // eax
	int v7; // eax
	unsigned __int8 v8; // al
	int v9; // ecx
	int v10; // edx
	int v11; // eax
	char v12; // al
	unsigned __int8 *result; // eax
	int v14; // [esp+10h] [ebp-8h]
	signed int v15; // [esp+14h] [ebp-4h]

	thispos = *a1;
	v2 = 0;
	v3 = 0;
	v4 = 4;
	v14 = 0;
	v15 = 4;
	nextpos = a1 + 1;
	v6 = 1;
	while (2)
	{
		switch (thispos)
		{
		case 0u:
		case 1u:
		case 2u:
		case 3u:
		case 8u:
		case 9u:
		case 0xAu:
		case 0xBu:
		case 0x10u:
		case 0x11u:
		case 0x12u:
		case 0x13u:
		case 0x18u:
		case 0x19u:
		case 0x1Au:
		case 0x1Bu:
		case 0x20u:
		case 0x21u:
		case 0x22u:
		case 0x23u:
		case 0x28u:
		case 0x29u:
		case 0x2Au:
		case 0x2Bu:
		case 0x30u:
		case 0x31u:
		case 0x32u:
		case 0x33u:
		case 0x38u:
		case 0x39u:
		case 0x3Au:
		case 0x3Bu:
		case 0x62u:
		case 0x63u:
		case 0x84u:
		case 0x85u:
		case 0x86u:
		case 0x87u:
		case 0x88u:
		case 0x89u:
		case 0x8Au:
		case 0x8Bu:
		case 0x8Cu:
		case 0x8Du:
		case 0x8Eu:
		case 0x8Fu:
		case 0xC4u:
		case 0xC5u:
		case 0xD0u:
		case 0xD1u:
		case 0xD2u:
		case 0xD3u:
		case 0xD8u:
		case 0xD9u:
		case 0xDAu:
		case 0xDBu:
		case 0xDCu:
		case 0xDDu:
		case 0xDEu:
		case 0xDFu:
		case 0xFEu:
		case 0xFFu:
			goto LABEL_23;
		case 4u:
		case 5u:
		case 0xCu:
		case 0xDu:
		case 0x14u:
		case 0x15u:
		case 0x1Cu:
		case 0x1Du:
		case 0x24u:
		case 0x25u:
		case 0x2Cu:
		case 0x2Du:
		case 0x34u:
		case 0x35u:
		case 0x3Cu:
		case 0x3Du:
			goto LABEL_13;
		case 0xFu:
			v7 = *nextpos++;
			switch (v7)
			{
			case 0:
			case 1:
			case 2:
			case 3:
			case 0xD:
			case 0x10:
			case 0x11:
			case 0x12:
			case 0x13:
			case 0x14:
			case 0x15:
			case 0x16:
			case 0x17:
			case 0x18:
			case 0x19:
			case 0x1A:
			case 0x1B:
			case 0x1C:
			case 0x1D:
			case 0x1E:
			case 0x1F:
			case 0x20:
			case 0x21:
			case 0x22:
			case 0x23:
			case 0x28:
			case 0x29:
			case 0x2A:
			case 0x2B:
			case 0x2C:
			case 0x2D:
			case 0x2E:
			case 0x2F:
			case 0x40:
			case 0x41:
			case 0x42:
			case 0x43:
			case 0x44:
			case 0x45:
			case 0x46:
			case 0x47:
			case 0x48:
			case 0x49:
			case 0x4A:
			case 0x4B:
			case 0x4C:
			case 0x4D:
			case 0x4E:
			case 0x4F:
			case 0x51:
			case 0x52:
			case 0x53:
			case 0x54:
			case 0x55:
			case 0x56:
			case 0x57:
			case 0x58:
			case 0x59:
			case 0x5A:
			case 0x5B:
			case 0x5C:
			case 0x5D:
			case 0x5E:
			case 0x5F:
			case 0x60:
			case 0x61:
			case 0x62:
			case 0x63:
			case 0x64:
			case 0x65:
			case 0x66:
			case 0x67:
			case 0x68:
			case 0x69:
			case 0x6A:
			case 0x6B:
			case 0x6E:
			case 0x6F:
			case 0x74:
			case 0x75:
			case 0x76:
			case 0x78:
			case 0x79:
			case 0x7E:
			case 0x7F:
			case 0x90:
			case 0x91:
			case 0x92:
			case 0x93:
			case 0x94:
			case 0x95:
			case 0x96:
			case 0x97:
			case 0x98:
			case 0x99:
			case 0x9A:
			case 0x9B:
			case 0x9C:
			case 0x9D:
			case 0x9E:
			case 0x9F:
			case 0xA3:
			case 0xA5:
			case 0xAB:
			case 0xAD:
			case 0xAE:
			case 0xAF:
			case 0xB0:
			case 0xB1:
			case 0xB2:
			case 0xB3:
			case 0xB4:
			case 0xB5:
			case 0xB6:
			case 0xB7:
			case 0xBB:
			case 0xBC:
			case 0xBD:
			case 0xBE:
			case 0xBF:
			case 0xC0:
			case 0xC1:
			case 0xC6:
			case 0xC7:
			case 0xD1:
			case 0xD2:
			case 0xD3:
			case 0xD5:
			case 0xD7:
			case 0xD8:
			case 0xD9:
			case 0xDA:
			case 0xDB:
			case 0xDC:
			case 0xDD:
			case 0xDE:
			case 0xDF:
			case 0xE0:
			case 0xE1:
			case 0xE2:
			case 0xE3:
			case 0xE4:
			case 0xE5:
			case 0xE7:
			case 0xE8:
			case 0xE9:
			case 0xEA:
			case 0xEB:
			case 0xEC:
			case 0xED:
			case 0xEE:
			case 0xEF:
			case 0xF1:
			case 0xF2:
			case 0xF3:
			case 0xF5:
			case 0xF6:
			case 0xF7:
			case 0xF8:
			case 0xF9:
			case 0xFA:
			case 0xFC:
			case 0xFD:
			case 0xFE:
				goto LABEL_23;
			case 4:
			case 6:
			case 8:
			case 9:
			case 0xA:
			case 0xB:
			case 0x30:
			case 0x31:
			case 0x32:
			case 0x33:
			case 0x34:
			case 0x35:
			case 0x50:
			case 0x77:
			case 0xA0:
			case 0xA1:
			case 0xA2:
			case 0xA8:
			case 0xA9:
			case 0xAA:
			case 0xC8:
			case 0xC9:
			case 0xCA:
			case 0xCB:
			case 0xCC:
			case 0xCD:
			case 0xCE:
			case 0xCF:
				goto LABEL_24;
			case 0x70:
			case 0xA4:
			case 0xAC:
			case 0xBA:
			case 0xC2:
			case 0xC4:
			case 0xC5:
				goto LABEL_22;
			case 0x71:
			case 0x72:
			case 0x73:
				goto LABEL_21;
			case 0x80:
			case 0x81:
			case 0x82:
			case 0x83:
			case 0x84:
			case 0x85:
			case 0x86:
			case 0x87:
			case 0x88:
			case 0x89:
			case 0x8A:
			case 0x8B:
			case 0x8C:
			case 0x8D:
			case 0x8E:
			case 0x8F:
				goto LABEL_14;
			default:
				return (unsigned __int8 *)-1;
			}
			return (unsigned __int8 *)-1;
		case 0x26u:
		case 0x2Eu:
		case 0x36u:
		case 0x3Eu:
		case 0x64u:
		case 0x65u:
			v3 |= 0x10u;
			goto LABEL_8;
		case 0x66u:
			v3 |= 1u;
			v4 = 2;
			goto LABEL_8;
		case 0x67u:
			v3 |= 2u;
			v15 = 2;
			goto LABEL_8;
		case 0x68u:
		case 0xA9u:
		case 0xB8u:
		case 0xB9u:
		case 0xBAu:
		case 0xBBu:
		case 0xBCu:
		case 0xBDu:
		case 0xBEu:
		case 0xBFu:
		case 0xE8u:
		case 0xE9u:
			goto LABEL_14;
		case 0x69u:
		case 0x81u:
		case 0xC7u:
			v2 = v4;
			goto LABEL_23;
		case 0x6Au:
		case 0x70u:
		case 0x71u:
		case 0x72u:
		case 0x73u:
		case 0x74u:
		case 0x75u:
		case 0x76u:
		case 0x77u:
		case 0x78u:
		case 0x79u:
		case 0x7Au:
		case 0x7Bu:
		case 0x7Cu:
		case 0x7Du:
		case 0x7Eu:
		case 0x7Fu:
		case 0xA8u:
		case 0xB0u:
		case 0xB1u:
		case 0xB2u:
		case 0xB3u:
		case 0xB4u:
		case 0xB5u:
		case 0xB6u:
		case 0xB7u:
		case 0xD4u:
		case 0xD5u:
		case 0xE0u:
		case 0xE1u:
		case 0xE2u:
		case 0xE3u:
		case 0xE4u:
		case 0xE5u:
		case 0xE6u:
		case 0xE7u:
		case 0xEBu:
			goto LABEL_21;
		case 0x6Bu:
		case 0x80u:
		case 0x82u:
		case 0x83u:
		case 0xC0u:
		case 0xC1u:
		case 0xC6u:
		LABEL_22 :
			v2 = 1;
			 LABEL_23:
				 v3 = v3 | 0x40;
				 break;
		case 0x9Au:
		case 0xEAu:
			v2 = v4 + 2;
			break;
		case 0xA0u:
		case 0xA1u:
		case 0xA2u:
		case 0xA3u:
			v14 = v15;
			break;
		case 0xC2u:
		case 0xCAu:
			v2 = 2;
			break;
		case 0xC8u:
			v2 = 3;
			break;
		case 0xCDu:
			v2 = 4 * (*nextpos == 32) + 1;
			break;
		case 0xF0u:
			v3 |= 4u;
			goto LABEL_8;
		case 0xF2u:
		case 0xF3u:
			v3 |= 8u;
		LABEL_8:
			if (v6 >= 15)
				return (unsigned __int8 *)-1;
			thispos = *nextpos++;
			++v6;
			if (thispos > 0xFF)
				break;
			continue;
		case 0xF6u:
		case 0xF7u:
			v3 = v3 | 0x40;
			if (!(*nextpos & 0x38))
			{
			LABEL_13:
				if (thispos & 1)
				LABEL_14 :
						 v2 = v4;
				else
				LABEL_21 :
						 v2 = 1;
			}
			break;
		default:
			goto LABEL_24;
		}
		break;
	}
LABEL_24:
	if (v3 & 0x40 && (v8 = *nextpos, v9 = *nextpos & 0xC0, ++nextpos, v9 != 0xC0))// thispos>0x40 && nextpoint<0xc0
	{
		v10 = v14;
		if (v9 == 64)
		{
			v10 = v14 + 1;
		}
		else if (v9 == 128)
		{
			v10 = v15 + v14;
		}
		v11 = v8 & 7;
		if (v15 == 2)
		{
			if (!v9 && v11 == 6)
				v10 += 2;
		}
		else
		{
			if (v11 == 4)
			{
				v12 = *nextpos++;
				v11 = v12 & 7;
			}
			if (v11 == 5 && !v9)
				v10 += 4;
		}
	}
	else
	{
		v10 = v14;
	}
	result = &nextpos[v2 + v10 - (DWORD)a1];
	if ((unsigned int)result > 0xF)
		return (unsigned __int8 *)-1;
	return result;
}

int StringToHex(char *str, unsigned char *out, unsigned int *outlen)
{
	char *p = str;
	char high = 0, low = 0;
	int tmplen = strlen(p), cnt = 0;
	tmplen = strlen(p);
	while (cnt < (tmplen / 2))
	{
		high = ((*p > '9') && ((*p <= 'F') || (*p <= 'f'))) ? *p - 48 - 7 : *p - 48;
		low = (*(++p) > '9' && ((*p <= 'F') || (*p <= 'f'))) ? *(p)-48 - 7 : *(p)-48;
		out[cnt] = ((high & 0x0f) << 4 | (low & 0x0f));
		p++;
		cnt++;
	}
	if (tmplen % 2 != 0) out[cnt] = ((*p > '9') && ((*p <= 'F') || (*p <= 'f'))) ? *p - 48 - 7 : *p - 48;

	if (outlen != NULL) *outlen = tmplen / 2 + tmplen % 2;
	return tmplen / 2 + tmplen % 2;
}
