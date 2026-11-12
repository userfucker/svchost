//#include "pch.h"
#include "TIHelper.h"

// ----------------------------------------------------------------
// 静态成员定义
// ----------------------------------------------------------------
DWORD TIHelper::s_lastError = 0;

// ----------------------------------------------------------------
// 内部文件作用域辅助函数
// ----------------------------------------------------------------
static std::wstring HKeyToString(HKEY hRoot)
{
    if (hRoot == HKEY_LOCAL_MACHINE)  return L"HKLM";
    if (hRoot == HKEY_CURRENT_USER)   return L"HKCU";
    if (hRoot == HKEY_CLASSES_ROOT)   return L"HKCR";
    if (hRoot == HKEY_USERS)          return L"HKU";
    if (hRoot == HKEY_CURRENT_CONFIG) return L"HKCC";
    return L"HKLM";
}

static std::wstring RegTypeToStr(DWORD regType)
{
    switch (regType) {
    case REG_SZ:        return L"REG_SZ";
    case REG_EXPAND_SZ: return L"REG_EXPAND_SZ";
    case REG_DWORD:     return L"REG_DWORD";
    case REG_QWORD:     return L"REG_QWORD";
    case REG_BINARY:    return L"REG_BINARY";
    case REG_MULTI_SZ:  return L"REG_MULTI_SZ";
    default:            return L"REG_SZ";
    }
}

// ----------------------------------------------------------------
// ExtendPath
// ----------------------------------------------------------------
std::wstring TIHelper::ExtendPath(const std::wstring& path)
{
    if (path.size() >= 4 && path.compare(0, 4, L"\\\\?\\") == 0)
        return path;
    return std::wstring(L"\\\\?\\") + path;
}

// ----------------------------------------------------------------
// EnablePrivilege
// ----------------------------------------------------------------
bool TIHelper::EnablePrivilege(HANDLE hToken, LPCWSTR lpPrivilege)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;
    ZeroMemory(&tp, sizeof(tp));
    ZeroMemory(&luid, sizeof(luid));

    if (!LookupPrivilegeValueW(NULL, lpPrivilege, &luid))
        return false;

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    return (GetLastError() != ERROR_NOT_ALL_ASSIGNED);
}

// ----------------------------------------------------------------
// EnableRequiredPrivileges
// ----------------------------------------------------------------
bool TIHelper::EnableRequiredPrivileges()
{
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    EnablePrivilege(hToken, L"SeDebugPrivilege");
    EnablePrivilege(hToken, L"SeImpersonatePrivilege");
    EnablePrivilege(hToken, L"SeTakeOwnershipPrivilege");
    EnablePrivilege(hToken, L"SeRestorePrivilege");
    EnablePrivilege(hToken, L"SeBackupPrivilege");

    CloseHandle(hToken);
    return true;
}

// ----------------------------------------------------------------
// GetTrustedInstallerToken
// 返回 Primary Token（用于 CreateProcessWithTokenW）
// ----------------------------------------------------------------
bool TIHelper::GetTrustedInstallerToken(HANDLE& hToken)
{
    hToken = NULL;
    EnableRequiredPrivileges();

    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) { s_lastError = GetLastError(); return false; }

    SC_HANDLE hSvc = OpenServiceW(hSCM, L"TrustedInstaller",
        SERVICE_START | SERVICE_QUERY_STATUS);
    if (!hSvc)
    {
        s_lastError = GetLastError();
        CloseServiceHandle(hSCM);
        return false;
    }

    StartServiceW(hSvc, 0, NULL); // 已运行则忽略错误

    SERVICE_STATUS_PROCESS ssp;
    DWORD dwBytes = 0;
    ZeroMemory(&ssp, sizeof(ssp));
    for (int i = 0; i < 20; i++)
    {
        QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
            (LPBYTE)&ssp, sizeof(ssp), &dwBytes);
        if (ssp.dwCurrentState == SERVICE_RUNNING) break;
        Sleep(500);
    }
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);

    if (ssp.dwCurrentState != SERVICE_RUNNING || ssp.dwProcessId == 0)
    {
        s_lastError = ERROR_SERVICE_NOT_ACTIVE;
        return false;
    }

    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ssp.dwProcessId);
    if (!hProc) { s_lastError = GetLastError(); return false; }

    HANDLE hTIToken = NULL;
    if (!OpenProcessToken(hProc, TOKEN_DUPLICATE, &hTIToken))
    {
        s_lastError = GetLastError();
        CloseHandle(hProc);
        return false;
    }
    CloseHandle(hProc);

    // 复制为 Primary Token（供 CreateProcessWithTokenW 使用）
    HANDLE hDup = NULL;
    if (!DuplicateTokenEx(hTIToken, TOKEN_ALL_ACCESS, NULL,
        SecurityImpersonation, TokenPrimary, &hDup))
    {
        s_lastError = GetLastError();
        CloseHandle(hTIToken);
        return false;
    }
    CloseHandle(hTIToken);

    // 开启全部特权
    DWORD dwSize = 0;
    GetTokenInformation(hDup, TokenPrivileges, NULL, 0, &dwSize);
    if (dwSize > 0)
    {
        std::vector<BYTE> buf(dwSize);
        if (GetTokenInformation(hDup, TokenPrivileges,
            buf.data(), dwSize, &dwSize))
        {
            TOKEN_PRIVILEGES* pTP = reinterpret_cast<TOKEN_PRIVILEGES*>(buf.data());
            for (DWORD i = 0; i < pTP->PrivilegeCount; i++)
                pTP->Privileges[i].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hDup, FALSE, pTP, dwSize, NULL, NULL);
        }
    }

    hToken = hDup;
    return true;
}

// ----------------------------------------------------------------
// RunAsTI
// ----------------------------------------------------------------
bool TIHelper::RunAsTI(const std::wstring& cmdLine, bool bWait)
{
    HANDLE hToken = NULL;
    if (!GetTrustedInstallerToken(hToken))
        return false;

    std::vector<wchar_t> buf(cmdLine.begin(), cmdLine.end());
    buf.push_back(L'\0');

    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.lpDesktop = const_cast<LPWSTR>(L"Winsta0\\Default");
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    BOOL bOk = CreateProcessWithTokenW(
        hToken, LOGON_WITH_PROFILE, NULL, buf.data(),
        CREATE_UNICODE_ENVIRONMENT, NULL, NULL, &si, &pi);

    if (!bOk)
    {
        s_lastError = GetLastError();
        CloseHandle(hToken);
        return false;
    }

    bool success = true;
    if (bWait)
    {
        WaitForSingleObject(pi.hProcess, INFINITE);
        DWORD exitCode = 0;
        if (GetExitCodeProcess(pi.hProcess, &exitCode) && exitCode != 0)
        {
            success = false;
            s_lastError = exitCode;
        }
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hToken);
    return success;
}

// ----------------------------------------------------------------
// DeleteFileAsTI / DeleteDirectoryAsTI
// ----------------------------------------------------------------
bool TIHelper::DeleteFileAsTI(const std::wstring& filePath)
{
    std::wstring cmd = L"cmd.exe /c del /f /q \"" + filePath + L"\"";
    return RunAsTI(cmd, true);
}

bool TIHelper::DeleteDirectoryAsTI(const std::wstring& dirPath)
{
    std::wstring cmd = L"cmd.exe /c rd /s /q \"" + dirPath + L"\"";
    return RunAsTI(cmd, true);
}

// ----------------------------------------------------------------
// TakeOwnership
// ----------------------------------------------------------------
bool TIHelper::TakeOwnership(const std::wstring& path, bool recursive)
{
    EnableRequiredPrivileges();

    std::wstring extPath = ExtendPath(path);

    PSID pAdminSid = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(&ntAuth, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &pAdminSid))
    {
        s_lastError = GetLastError();
        return false;
    }

    DWORD dwRet = SetNamedSecurityInfoW(
        const_cast<LPWSTR>(extPath.c_str()),
        SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION,
        pAdminSid, NULL, NULL, NULL);

    if (dwRet == ERROR_SUCCESS && recursive)
    {
        DWORD attr = GetFileAttributesW(extPath.c_str());
        if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY))
        {
            std::wstring search = extPath + L"\\*";
            WIN32_FIND_DATAW fd; ZeroMemory(&fd, sizeof(fd));
            HANDLE hFind = FindFirstFileW(search.c_str(), &fd);
            if (hFind != INVALID_HANDLE_VALUE)
            {
                do {
                    if (wcscmp(fd.cFileName, L".") == 0 ||
                        wcscmp(fd.cFileName, L"..") == 0) continue;
                    TakeOwnership(extPath + L"\\" + fd.cFileName, true);
                } while (FindNextFileW(hFind, &fd));
                FindClose(hFind);
            }
        }
    }

    FreeSid(pAdminSid);
    if (dwRet != ERROR_SUCCESS) s_lastError = dwRet;
    return (dwRet == ERROR_SUCCESS);
}

// ----------------------------------------------------------------
// ResetAcl
// ----------------------------------------------------------------
bool TIHelper::ResetAcl(const std::wstring& path, bool recursive)
{
    EnableRequiredPrivileges();

    std::wstring extPath = ExtendPath(path);

    PSID pAdminSid = NULL, pSystemSid = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;

    AllocateAndInitializeSid(&ntAuth, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &pAdminSid);
    AllocateAndInitializeSid(&ntAuth, 1,
        SECURITY_LOCAL_SYSTEM_RID,
        0, 0, 0, 0, 0, 0, 0, &pSystemSid);

    EXPLICIT_ACCESSW ea[2];
    ZeroMemory(ea, sizeof(ea));

    ea[0].grfAccessPermissions = GENERIC_ALL;
    ea[0].grfAccessMode = SET_ACCESS;
    ea[0].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[0].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    ea[0].Trustee.ptstrName = (LPWSTR)pAdminSid;

    ea[1].grfAccessPermissions = GENERIC_ALL;
    ea[1].grfAccessMode = SET_ACCESS;
    ea[1].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[1].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[1].Trustee.ptstrName = (LPWSTR)pSystemSid;

    PACL pNewDacl = NULL;
    DWORD dwRet = SetEntriesInAclW(2, ea, NULL, &pNewDacl);
    if (dwRet == ERROR_SUCCESS)
    {
        dwRet = SetNamedSecurityInfoW(
            const_cast<LPWSTR>(extPath.c_str()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            NULL, NULL, pNewDacl, NULL);
        LocalFree(pNewDacl);
    }

    if (dwRet == ERROR_SUCCESS && recursive)
    {
        DWORD attr = GetFileAttributesW(extPath.c_str());
        if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY))
        {
            std::wstring search = extPath + L"\\*";
            WIN32_FIND_DATAW fd; ZeroMemory(&fd, sizeof(fd));
            HANDLE hFind = FindFirstFileW(search.c_str(), &fd);
            if (hFind != INVALID_HANDLE_VALUE)
            {
                do {
                    if (wcscmp(fd.cFileName, L".") == 0 ||
                        wcscmp(fd.cFileName, L"..") == 0) continue;
                    ResetAcl(extPath + L"\\" + fd.cFileName, true);
                } while (FindNextFileW(hFind, &fd));
                FindClose(hFind);
            }
        }
    }

    FreeSid(pAdminSid);
    FreeSid(pSystemSid);
    if (dwRet != ERROR_SUCCESS) s_lastError = dwRet;
    return (dwRet == ERROR_SUCCESS);
}

// ----------------------------------------------------------------
// DeleteDirContents / DoDelete
// ----------------------------------------------------------------
bool TIHelper::DeleteDirContents(const std::wstring& path)
{
    std::wstring search = path + L"\\*";
    WIN32_FIND_DATAW fd; ZeroMemory(&fd, sizeof(fd));

    HANDLE hFind = FindFirstFileW(search.c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE) return true;

    do {
        if (wcscmp(fd.cFileName, L".") == 0 ||
            wcscmp(fd.cFileName, L"..") == 0) continue;

        std::wstring child = path + L"\\" + fd.cFileName;
        SetFileAttributesW(child.c_str(), FILE_ATTRIBUTE_NORMAL);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            DeleteDirContents(child);
            RemoveDirectoryW(child.c_str());
        }
        else
            DeleteFileW(child.c_str());

    } while (FindNextFileW(hFind, &fd));

    FindClose(hFind);
    return true;
}

bool TIHelper::DoDelete(const std::wstring& path)
{
    std::wstring extPath = ExtendPath(path);
    DWORD attr = GetFileAttributesW(extPath.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) return true;

    SetFileAttributesW(extPath.c_str(), FILE_ATTRIBUTE_NORMAL);

    if (attr & FILE_ATTRIBUTE_DIRECTORY)
    {
        DeleteDirContents(extPath);
        return (RemoveDirectoryW(extPath.c_str()) == TRUE);
    }
    return (DeleteFileW(extPath.c_str()) == TRUE);
}

// ----------------------------------------------------------------
// ForceDelete / ForceDeleteBatch
// ----------------------------------------------------------------
bool TIHelper::ForceDelete(const std::wstring& path)
{
    EnableRequiredPrivileges();
    TakeOwnership(path, true);
    ResetAcl(path, true);

    if (DoDelete(path)) return true;

    DWORD attr = GetFileAttributesW(path.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) return true;

    bool result = (attr & FILE_ATTRIBUTE_DIRECTORY)
        ? DeleteDirectoryAsTI(path)
        : DeleteFileAsTI(path);

    return (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES);
}

bool TIHelper::ForceDeleteBatch(const std::vector<std::wstring>& paths)
{
    bool allOk = true;
    for (auto& p : paths)
        if (!ForceDelete(p)) allOk = false;
    return allOk;
}

// ----------------------------------------------------------------
// ForceCreateFile
// ----------------------------------------------------------------
bool TIHelper::ForceCreateFile(const std::wstring& dirPath,
    const std::wstring& fileName,
    const std::vector<BYTE>& content)
{
    EnableRequiredPrivileges();
    TakeOwnership(dirPath, false);
    ResetAcl(dirPath, false);

    std::wstring fullPath = dirPath;
    if (!fullPath.empty() && fullPath.back() != L'\\')
        fullPath += L'\\';
    fullPath += fileName;

    std::wstring extPath = ExtendPath(fullPath);

    HANDLE hFile = CreateFileW(extPath.c_str(), GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        if (!content.empty()) {
            DWORD written = 0;
            WriteFile(hFile, content.data(), (DWORD)content.size(), &written, NULL);
        }
        CloseHandle(hFile);
        return true;
    }

    if (content.empty()) {
        std::wstring cmd = L"cmd.exe /c echo. > \"" + fullPath + L"\"";
        return RunAsTI(cmd, true);
    }

    wchar_t tempDir[MAX_PATH] = {}, tempFile[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, tempDir);
    GetTempFileNameW(tempDir, L"TIH", 0, tempFile);

    HANDLE hTemp = CreateFileW(tempFile, GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hTemp == INVALID_HANDLE_VALUE) { s_lastError = GetLastError(); return false; }
    DWORD written = 0;
    WriteFile(hTemp, content.data(), (DWORD)content.size(), &written, NULL);
    CloseHandle(hTemp);

    std::wstring cmd = L"cmd.exe /c copy /y \"" +
        std::wstring(tempFile) + L"\" \"" + fullPath + L"\"";
    bool ok = RunAsTI(cmd, true);
    DeleteFileW(tempFile);
    return ok;
}

// ----------------------------------------------------------------
// RegWriteAsTI
// 三级降级：直接写 → 模拟TI Token → reg.exe add
// ----------------------------------------------------------------
bool TIHelper::RegWriteAsTI(HKEY hRootKey,
    const std::wstring& subKey,
    const std::wstring& valueName,
    DWORD               regType,
    const void* pData,
    DWORD               dataSize)
{
    EnableRequiredPrivileges();

    // ===== 通用写入 lambda =====
    auto DoWrite = [&]() -> bool {
        HKEY hKey = NULL;
        DWORD disposition = 0;
        LONG ret = RegCreateKeyExW(hRootKey, subKey.c_str(), 0, NULL,
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE | KEY_WOW64_64KEY,
            NULL, &hKey, &disposition);
        if (ret != ERROR_SUCCESS) return false;
        LONG wr = RegSetValueExW(hKey, valueName.c_str(), 0,
            regType, (LPBYTE)pData, dataSize);
        RegCloseKey(hKey);
        return (wr == ERROR_SUCCESS);
    };

    // ===== 第一级：直接写 =====
    if (DoWrite()) return true;

    // ===== 第二级：模拟 TI Token =====
    // GetTrustedInstallerToken 返回 Primary Token
    // ImpersonateLoggedOnUser 需要 Impersonation Token，单独复制一份
    {
        HANDLE hPrimaryToken = NULL;
        if (GetTrustedInstallerToken(hPrimaryToken))
        {
            HANDLE hImpToken = NULL;
            BOOL dupOk = DuplicateTokenEx(hPrimaryToken, TOKEN_ALL_ACCESS, NULL,
                SecurityImpersonation, TokenImpersonation, &hImpToken);
            CloseHandle(hPrimaryToken);

            if (dupOk)
            {
                if (ImpersonateLoggedOnUser(hImpToken))
                {
                    bool ok = DoWrite();
                    RevertToSelf();
                    CloseHandle(hImpToken);
                    if (ok) return true;
                }
                else
                    CloseHandle(hImpToken);
            }
        }
    }

    // ===== 第三级：reg.exe add（RunAsTI）=====
    std::wstring fullKey = HKeyToString(hRootKey) + L"\\" + subKey;
    std::wstring typeStr = RegTypeToStr(regType);
    std::wstring valStr;

    switch (regType)
    {
    case REG_DWORD: {
        DWORD dw = *(DWORD*)pData;
        wchar_t buf[32]; swprintf_s(buf, L"%lu", dw);
        valStr = buf;
        break;
    }
    case REG_QWORD: {
        ULONGLONG qw = *(ULONGLONG*)pData;
        wchar_t buf[32]; swprintf_s(buf, L"%llu", qw);
        valStr = buf;
        break;
    }
    case REG_SZ:
    case REG_EXPAND_SZ: {
        valStr = std::wstring((const wchar_t*)pData);
        // 双引号转义，防止命令行截断
        std::wstring escaped;
        for (wchar_t c : valStr) {
            if (c == L'"') escaped += L"\\\"";
            else escaped += c;
        }
        valStr = escaped;
        break;
    }
    case REG_BINARY: {
        // reg.exe /d 需要空格分隔的十六进制字节，如 "03 00 00 00"
        const BYTE* pb = (const BYTE*)pData;
        for (DWORD i = 0; i < dataSize; i++) {
            wchar_t hex[8];
            swprintf_s(hex, L"%02x", pb[i]);
            if (i > 0) valStr += L" ";
            valStr += hex;
        }
        break;
    }
    default:
        valStr = L"0";
        break;
    }

    // 值名为空 → 写默认值用 /ve，否则用 /v "名称"
    std::wstring cmd = L"reg.exe add \"" + fullKey + L"\"";
    if (valueName.empty())
        cmd += L" /ve";
    else
        cmd += L" /v \"" + valueName + L"\"";
    cmd += L" /t " + typeStr
        + L" /d \"" + valStr + L"\""
        + L" /f";

    return RunAsTI(cmd, true);
}

// ----------------------------------------------------------------
// RegDeleteAsTI
// 三级降级：直接删 → 模拟TI Token → reg.exe delete
// valueName 为空 → 删整个键（递归）
// ----------------------------------------------------------------
bool TIHelper::RegDeleteAsTI(HKEY hRootKey,
    const std::wstring& subKey,
    const std::wstring& valueName)
{
    EnableRequiredPrivileges();

    std::wstring fullKey = HKeyToString(hRootKey) + L"\\" + subKey;

    // ===== 通用删除 lambda =====
    auto DoDelete = [&]() -> bool {
        if (valueName.empty()) {
            LONG ret = RegDeleteTreeW(hRootKey, subKey.c_str());
            return (ret == ERROR_SUCCESS || ret == ERROR_FILE_NOT_FOUND);
        }
        HKEY hKey = NULL;
        LONG ret = RegOpenKeyExW(hRootKey, subKey.c_str(), 0,
            KEY_SET_VALUE | KEY_WOW64_64KEY, &hKey);
        if (ret == ERROR_FILE_NOT_FOUND) return true;
        if (ret != ERROR_SUCCESS) return false;
        LONG dr = RegDeleteValueW(hKey, valueName.c_str());
        RegCloseKey(hKey);
        return (dr == ERROR_SUCCESS || dr == ERROR_FILE_NOT_FOUND);
    };

    // ===== 第一级：直接删 =====
    if (DoDelete()) return true;

    // ===== 第二级：模拟 TI Token =====
    {
        HANDLE hPrimaryToken = NULL;
        if (GetTrustedInstallerToken(hPrimaryToken))
        {
            HANDLE hImpToken = NULL;
            BOOL dupOk = DuplicateTokenEx(hPrimaryToken, TOKEN_ALL_ACCESS, NULL,
                SecurityImpersonation, TokenImpersonation, &hImpToken);
            CloseHandle(hPrimaryToken);

            if (dupOk)
            {
                if (ImpersonateLoggedOnUser(hImpToken))
                {
                    bool ok = DoDelete();
                    RevertToSelf();
                    CloseHandle(hImpToken);
                    if (ok) return true;
                }
                else
                    CloseHandle(hImpToken);
            }
        }
    }

    // ===== 第三级：reg.exe delete（RunAsTI）=====
    std::wstring cmd;
    if (valueName.empty()) {
        cmd = L"reg.exe delete \"" + fullKey + L"\" /f";
    }
    else {
        cmd = L"reg.exe delete \"" + fullKey + L"\""
            + L" /v \"" + valueName + L"\" /f";
    }

    return RunAsTI(cmd, true);
}

// ----------------------------------------------------------------
// GetLastErrorMsg
// ----------------------------------------------------------------
std::wstring TIHelper::GetLastErrorMsg()
{
    if (s_lastError == 0) return std::wstring(L"Success");

    LPWSTR pMsg = NULL;
    FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
        NULL, s_lastError,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&pMsg, 0, NULL);

    std::wstring result = pMsg ? pMsg : L"Unknown error";
    if (pMsg) LocalFree(pMsg);

    while (!result.empty() &&
        (result.back() == L'\n' || result.back() == L'\r'))
        result.pop_back();

    return result;
}