#include "TIHelper.h"

// ----------------------------------------------------------------
// 静态成员定义
// ----------------------------------------------------------------
DWORD TIHelper::s_lastError = 0;

// ----------------------------------------------------------------
// 内部工具：扩展路径
// ----------------------------------------------------------------
std::wstring TIHelper::ExtendPath(const std::wstring& path)
{
    if (path.size() >= 4 && path.compare(0, 4, L"\\\\?\\") == 0)
        return path;
    return std::wstring(L"\\\\?\\") + path;
}

// ----------------------------------------------------------------
// 开启指定特权
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
// 开启当前进程所需特权
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
// 获取 TrustedInstaller 服务进程的 Token
// ----------------------------------------------------------------
bool TIHelper::GetTrustedInstallerToken(HANDLE& hToken)
{
    hToken = NULL;
    EnableRequiredPrivileges();

    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM)
    {
        s_lastError = GetLastError();
        return false;
    }

    SC_HANDLE hSvc = OpenServiceW(hSCM, L"TrustedInstaller",
        SERVICE_START | SERVICE_QUERY_STATUS);
    if (!hSvc)
    {
        s_lastError = GetLastError();
        CloseServiceHandle(hSCM);
        return false;
    }

    // 启动服务（已运行则忽略错误）
    StartServiceW(hSvc, 0, NULL);

    // 等待服务进入 Running 状态，最多 10 秒
    SERVICE_STATUS_PROCESS ssp;
    DWORD dwBytes = 0;
    ZeroMemory(&ssp, sizeof(ssp));

    for (int i = 0; i < 20; i++)
    {
        QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
            (LPBYTE)&ssp, sizeof(ssp), &dwBytes);
        if (ssp.dwCurrentState == SERVICE_RUNNING)
            break;
        Sleep(500);
    }

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);

    if (ssp.dwCurrentState != SERVICE_RUNNING || ssp.dwProcessId == 0)
    {
        s_lastError = ERROR_SERVICE_NOT_ACTIVE;
        return false;
    }

    // 打开 TrustedInstaller.exe 进程
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ssp.dwProcessId);
    if (!hProc)
    {
        s_lastError = GetLastError();
        return false;
    }

    // 获取其 Token
    HANDLE hTIToken = NULL;
    if (!OpenProcessToken(hProc, TOKEN_DUPLICATE, &hTIToken))
    {
        s_lastError = GetLastError();
        CloseHandle(hProc);
        return false;
    }
    CloseHandle(hProc);

    // 复制为 Primary Token
    HANDLE hDup = NULL;
    if (!DuplicateTokenEx(hTIToken, TOKEN_ALL_ACCESS, NULL,
        SecurityImpersonation, TokenPrimary, &hDup))
    {
        s_lastError = GetLastError();
        CloseHandle(hTIToken);
        return false;
    }
    CloseHandle(hTIToken);

    // 开启复制 Token 的全部特权
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

    if (bWait)
        WaitForSingleObject(pi.hProcess, INFINITE);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hToken);
    return true;
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
        if (attr != INVALID_FILE_ATTRIBUTES &&
            (attr & FILE_ATTRIBUTE_DIRECTORY))
        {
            std::wstring search = extPath + L"\\*";
            WIN32_FIND_DATAW fd;
            ZeroMemory(&fd, sizeof(fd));
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

    PSID pAdminSid = NULL;
    PSID pSystemSid = NULL;
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
        if (attr != INVALID_FILE_ATTRIBUTES &&
            (attr & FILE_ATTRIBUTE_DIRECTORY))
        {
            std::wstring search = extPath + L"\\*";
            WIN32_FIND_DATAW fd;
            ZeroMemory(&fd, sizeof(fd));
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
    WIN32_FIND_DATAW fd;
    ZeroMemory(&fd, sizeof(fd));

    HANDLE hFind = FindFirstFileW(search.c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE)
        return true;

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
        {
            DeleteFileW(child.c_str());
        }
    } while (FindNextFileW(hFind, &fd));

    FindClose(hFind);
    return true;
}

bool TIHelper::DoDelete(const std::wstring& path)
{
    std::wstring extPath = ExtendPath(path);

    DWORD attr = GetFileAttributesW(extPath.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES)
        return true; // 已不存在，视为成功

    SetFileAttributesW(extPath.c_str(), FILE_ATTRIBUTE_NORMAL);

    if (attr & FILE_ATTRIBUTE_DIRECTORY)
    {
        DeleteDirContents(extPath);
        return (RemoveDirectoryW(extPath.c_str()) == TRUE);
    }
    return (DeleteFileW(extPath.c_str()) == TRUE);
}

// ----------------------------------------------------------------
// ForceDelete
// ----------------------------------------------------------------
bool TIHelper::ForceDelete(const std::wstring& path)
{
    EnableRequiredPrivileges();
    TakeOwnership(path, true);
    ResetAcl(path, true);

    if (DoDelete(path))
        return true;

    // 升级为 TrustedInstaller 身份重试
    DWORD attr = GetFileAttributesW(path.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES)
        return true; // 已删除

    if (attr & FILE_ATTRIBUTE_DIRECTORY)
        return DeleteDirectoryAsTI(path);

    return DeleteFileAsTI(path);
}

bool TIHelper::ForceDeleteBatch(const std::vector<std::wstring>& paths)
{
    bool allOk = true;
    for (size_t i = 0; i < paths.size(); i++)
        if (!ForceDelete(paths[i])) allOk = false;
    return allOk;
}

// ----------------------------------------------------------------
// GetLastErrorMsg
// ----------------------------------------------------------------
std::wstring TIHelper::GetLastErrorMsg()
{
    if (s_lastError == 0)
        return std::wstring(L"Success");

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

// 在 TIHelper.cpp 里加这个函数
bool TIHelper::ForceCreateFile(const std::wstring& dirPath,
    const std::wstring& fileName,
    const std::vector<BYTE>& content)
{
    EnableRequiredPrivileges();

    // 先对目录夺权+重置ACL
    TakeOwnership(dirPath, false);
    ResetAcl(dirPath, false);

    // 拼完整路径
    std::wstring fullPath = dirPath;
    if (!fullPath.empty() && fullPath.back() != L'\\')
        fullPath += L'\\';
    fullPath += fileName;

    std::wstring extPath = ExtendPath(fullPath);

    // 尝试直接创建
    HANDLE hFile = CreateFileW(extPath.c_str(),
        GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile != INVALID_HANDLE_VALUE) {
        if (!content.empty()) {
            DWORD written = 0;
            WriteFile(hFile, content.data(), (DWORD)content.size(), &written, NULL);
        }
        CloseHandle(hFile);
        return true;
    }

    // 直接创建失败，升级到TI身份写文件
    // 先把内容写到临时文件，再用TI身份的cmd复制过去
    if (content.empty()) {
        // 只需要创建空文件
        std::wstring cmd = L"cmd.exe /c echo. > \"" + fullPath + L"\"";
        return RunAsTI(cmd, true);
    }

    // 有内容：先写临时文件，再用TI身份copy过去
    wchar_t tempDir[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, tempDir);
    wchar_t tempFile[MAX_PATH] = {};
    GetTempFileNameW(tempDir, L"TIH", 0, tempFile);

    HANDLE hTemp = CreateFileW(tempFile, GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hTemp == INVALID_HANDLE_VALUE) {
        s_lastError = GetLastError();
        return false;
    }
    DWORD written = 0;
    WriteFile(hTemp, content.data(), (DWORD)content.size(), &written, NULL);
    CloseHandle(hTemp);

    // 用TI身份copy临时文件到目标
    std::wstring cmd = L"cmd.exe /c copy /y \"" +
        std::wstring(tempFile) + L"\" \"" + fullPath + L"\"";
    bool ok = RunAsTI(cmd, true);

    DeleteFileW(tempFile);
    return ok;
}