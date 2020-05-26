#include "util.h"

static WCHAR alphabet[] = L"abcdef012345789";

LPWSTR GetKeyPath(HKEY key)
{
	static WCHAR buffer[1024] = { 0 };
	DWORD size = sizeof(buffer);
	memset(buffer, 0, sizeof(buffer));
	NtQueryKey(key, 3, buffer, size, &size);
	return buffer + 3;
}

BOOL GetKeyValue(HKEY key, LPCWSTR value, LPBYTE buffer, DWORD *size)
{
	if (ERROR_SUCCESS == RegQueryValueEx(key, value, 0, 0, buffer, size)) return TRUE;
	else
	{
		printf("[-] 读取失败   %ws  %ws\n", GetKeyPath(key), value);
		return FALSE;
	}
}

VOID OutSpoofUnique(LPWSTR buffer)
{
	for (DWORD i = 0; i < wcslen(buffer); ++i)
	{
		if (iswxdigit(buffer[i]))
		{
			buffer[i] = alphabet[rand() % wcslen(alphabet)];
		}
	}
}

VOID KeySpoofOutGUID(HKEY key, LPCWSTR value, LPWSTR buffer, DWORD size)
{
	if (!GetKeyValue(key, value, (LPBYTE)buffer, &size))  return;

	printf("[+] %ws %ws -> ", GetKeyPath(key), buffer);
	OutSpoofUnique(buffer);
	RegSetValueEx(key, value, 0, REG_SZ, (PBYTE)buffer, size);
	printf("%ws \n", buffer);
}

VOID KeySpoofUnique(HKEY key, LPCWSTR value)
{
	WCHAR buffer[MAX_PATH] = { 0 };
	KeySpoofOutGUID(key, value, buffer, sizeof(buffer));
}

VOID SpoofUnique(HKEY key, LPCWSTR subkey, LPCWSTR value)
{
	OpenThen(key, subkey,
		{
		KeySpoofUnique(key, value);
		});
}

VOID SpoofUniques(HKEY key, LPCWSTR subkey, LPCWSTR value)
{
	OpenThen(key, subkey,
		{
		WCHAR buffer[0xFFF] = { 0 };
		DWORD size = sizeof(buffer);
		if (!GetKeyValue(key, value, (LPBYTE)buffer, &size))
		{
			RegCloseKey(key);
			return;
		}

		for (DWORD i = 0; i < size; ++i)
		{
			if (iswxdigit(buffer[i]))
				buffer[i] = alphabet[rand() % (wcslen(alphabet) - 1)];
		}

		RegSetValueEx(key, value, 0, REG_MULTI_SZ, (PBYTE)buffer, size);
		printf("[+] 写入数据 %ws  %ws  %d \n", GetKeyPath(key), value, size);
		});
}

VOID SpoofDWORD(HKEY key, LPCWSTR subkey, LPCWSTR value)
{
	OpenThen(key, subkey,
		{
		DWORD data = rand();
		if (ERROR_SUCCESS == RegSetValueEx(key, value, 0, REG_QWORD, (PBYTE)&data, sizeof(data)))
			printf("[+] 写入dword成功 %ws  %ws %d \n", GetKeyPath(key), value, data);
		else
			printf("[-] 写入dword失败 %ws  %ws", GetKeyPath(key), value);
		});
}

VOID SpoofQWORD(HKEY key, LPCWSTR subkey, LPCWSTR value)
{
	OpenThen(key, subkey,
		{
		LARGE_INTEGER data = { 0 };
		data.LowPart = rand();
		data.HighPart = rand();
		if (ERROR_SUCCESS == RegSetValueEx(key, value, 0, REG_QWORD, (PBYTE)&data, sizeof(data)))
			printf("[+] 设置QWORD成功  %ws  %ws \n", GetKeyPath(key), value);
		else
			printf("[-] 写入QWORD失败 %ws  %ws  \n", GetKeyPath(key), value);
		});
}

VOID SpoofBinary(HKEY key, LPCWSTR subkey, LPCWSTR value)
{
	OpenThen(key, subkey,
		{
		DWORD size = 0;
		if (ERROR_SUCCESS != RegQueryValueEx(key, value, 0, 0, 0, &size))
		{
			printf("[-] 读取失败 %ws  %ws \n", GetKeyPath(key), value);
			RegCloseKey(key);
			return;
		}

		BYTE *buffer = (BYTE *)malloc(size);
		if (!buffer)
		{
			printf("[-] 内存空间申请失败 \n");
			RegCloseKey(key);
			return;
		}

		printf("[+] 写入数据 %ws  %ws \n", GetKeyPath(key), value);

		for (DWORD i = 0; i < size; ++i)
			buffer[i] = (BYTE)(rand() % 0x100);

		RegSetValueEx(key, value, 0, REG_BINARY, buffer, size);
		free(buffer);
		});
}

VOID RenameSubkey(HKEY key, LPCWSTR subkey, LPCWSTR name)
{
	HKEY k = 0;
	DWORD error = RegCreateKey(key, name, &k);
	if (ERROR_CHILD_MUST_BE_VOLATILE == error)
		error = RegCreateKeyEx(key, name, 0, 0, REG_OPTION_VOLATILE, KEY_ALL_ACCESS, 0, &k, 0);

	if (ERROR_SUCCESS != error)
	{
		printf("[+] 创建键值失败 %ws  %ws \n", GetKeyPath(key), name);
		return;
	}

	if (ERROR_SUCCESS == RegCopyTree(key, subkey, k))
	{
		if (ERROR_SUCCESS == SHDeleteKey(key, subkey))
			printf("[+] %ws  %ws -> %ws \n", GetKeyPath(key), subkey, name);
		else
			printf("[-] 删除键值失败 %ws  %ws \n", GetKeyPath(key), subkey);
	}
	else
		printf("[-] 复制键值失败  %ws  %ws \n", GetKeyPath(key), subkey);

	RegCloseKey(k);
}

VOID DeleteKey(HKEY key, LPCWSTR subkey)
{
	DWORD s = SHDeleteKey(key, subkey);
	if (ERROR_FILE_NOT_FOUND == s)
		return;
	else if (ERROR_SUCCESS == s)
		printf("[+] 键值删除成功 %ws  %ws \n", GetKeyPath(key), subkey);
	else
		printf("[-] 键值删除失败 %ws  %ws \n", GetKeyPath(key), subkey);
}

VOID DeleteValue(HKEY key, LPCWSTR subkey, LPCWSTR value)
{
	DWORD s = SHDeleteValue(key, subkey, value);
	if (ERROR_FILE_NOT_FOUND == s)
		return;
	else if (ERROR_SUCCESS == s)
		printf("[+] 成功删除  %ws  %ws  %ws \n", GetKeyPath(key), subkey, value);
	else
		printf("[-] 删除失败  %ws  %ws  %ws \n", GetKeyPath(key), subkey, value);
}

BOOL AdjustCurrentPrivilege(LPCWSTR privilege)
{
	LUID luid = { 0 };
	if (!LookupPrivilegeValue(0, privilege, &luid))
	{
		printf("[-]不能调整权限为 %ws  %d \n", privilege, GetLastError());
		return FALSE;
	}

	TOKEN_PRIVILEGES tp = { 0 };
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	HANDLE token = 0;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token))
	{
		printf("[-] 不能打开当前进程标识 %d \n", GetLastError());
		return FALSE;
	}

	if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), 0, 0))
	{
		printf("[-] 不能调整当前进程的标志 %d \n", GetLastError());
		CloseHandle(token);
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		printf("[-] 权限调整失败\n");
		CloseHandle(token);
		return FALSE;
	}

	CloseHandle(token);
	return TRUE;
}

VOID ForceDeleteFile(LPWSTR path)
{
	if (!PathFileExistsW(path)) return;

	PSID all = 0, admin = 0;
	SID_IDENTIFIER_AUTHORITY world = SECURITY_WORLD_SID_AUTHORITY;
	if (!AllocateAndInitializeSid(&world, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &all))
	{
		printf("[-] Sid初始化失败  %ws  %d \n", path, GetLastError());
		return;
	}

	SID_IDENTIFIER_AUTHORITY auth = SECURITY_NT_AUTHORITY;
	if (!AllocateAndInitializeSid(&auth, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &admin))
	{
		printf("[-] Sid初始化失败  %ws  %d \n", path, GetLastError());
		FreeSid(all);
		return;
	}

	EXPLICIT_ACCESS access[2] = { 0 };
	access[0].grfAccessPermissions = GENERIC_ALL;
	access[0].grfAccessMode = SET_ACCESS;
	access[0].grfInheritance = NO_INHERITANCE;
	access[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	access[0].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
	access[0].Trustee.ptstrName = all;
	access[1].grfAccessPermissions = GENERIC_ALL;
	access[1].grfAccessMode = SET_ACCESS;
	access[1].grfInheritance = NO_INHERITANCE;
	access[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	access[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
	access[1].Trustee.ptstrName = admin;

	PACL acl = { 0 };
	DWORD error = SetEntriesInAclW(2, access, 0, &acl);
	if (ERROR_SUCCESS != error)
	{
		printf("[-] 设置ACL失败 %ws  %d \n", path, error);
		FreeSid(all);
		FreeSid(admin);
		return;
	}

	if (ERROR_SUCCESS != (error = SetNamedSecurityInfo((LPWSTR)path, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, admin, 0, 0, 0)))
	{
		printf("[-] 设置进程安全信息失败 %ws  %d \n", path, error);
		FreeSid(all);
		FreeSid(admin);
		LocalFree(acl);
		return;
	}

	if (ERROR_SUCCESS != (error = SetNamedSecurityInfo((LPWSTR)path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, 0, 0, acl, 0)))
	{
		printf("[-] 设置DACL失败 %ws  %d  \n", path, error);
		FreeSid(all);
		FreeSid(admin);
		LocalFree(acl);
		return;
	}

	SetFileAttributes(path, FILE_ATTRIBUTE_NORMAL);

	SHFILEOPSTRUCT op = { 0 };
	op.wFunc = FO_DELETE;
	path[wcslen(path) + 1] = 0;
	op.pFrom = path;
	op.pTo = L"\0";
	op.fFlags = FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT;
	op.lpszProgressTitle = L"";
	if (DeleteFile(path) || !SHFileOperation(&op))
		printf("[+] 删除成功  %ws \n", path);
	else
		printf("[-] 删除文件失败  %ws  %d  \n", path, GetLastError());

	FreeSid(all);
	FreeSid(admin);
	LocalFree(acl);
}

VOID RecursiveDelete(LPWSTR dir, LPWSTR match)
{
	WCHAR path[1024] = { 0 };
	wsprintf(path, L"%ws\\*", dir);

	WIN32_FIND_DATAW fd = { 0 };
	HANDLE f = FindFirstFileW(path, &fd);
	if (f != INVALID_HANDLE_VALUE)
	{
		do
		{
			WCHAR sub[1024] = { 0 };
			wsprintf(sub, L"%ws\\%ws", dir, fd.cFileName);

			if (wcscmp(fd.cFileName, L".") && wcscmp(fd.cFileName, L".."))
			{
				if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
					RecursiveDelete(sub, match);
				else if (StrStrW(fd.cFileName, match))
					ForceDeleteFile(sub);
			}
		} while (FindNextFile(f, &fd));
		FindClose(f);
	}
}