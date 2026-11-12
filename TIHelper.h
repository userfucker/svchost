#pragma once
#include <windows.h>
#include <winsvc.h>
#include <aclapi.h>
#include <sddl.h>
#include <string>
#include <vector>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "userenv.lib")

class TIHelper
{
public:
    // 以 TrustedInstaller 身份执行任意命令行
    static bool RunAsTI(const std::wstring& cmdLine, bool bWait = true);

    // 删除单个文件（TrustedInstaller 权限）
    static bool DeleteFileAsTI(const std::wstring& filePath);

    // 删除整个目录（递归）
    static bool DeleteDirectoryAsTI(const std::wstring& dirPath);

    // 强制删除：夺权 -> 重置ACL -> 删除 -> 失败则升级TI身份重试
    static bool ForceDelete(const std::wstring& path);

    // 批量强制删除
    static bool ForceDeleteBatch(const std::vector<std::wstring>& paths);

    // 夺取所有权（归Administrators）
    static bool TakeOwnership(const std::wstring& path, bool recursive = true);

    // 重置ACL：清除所有Deny，授予Administrators完全控制
    static bool ResetAcl(const std::wstring& path, bool recursive = true);

    // 强制创建文件（TI权限）
    static bool ForceCreateFile(const std::wstring& dirPath,
        const std::wstring& fileName,
        const std::vector<BYTE>& content = {});

    // 以 TI 身份写注册表值（三级降级：直接写→模拟TI→reg.exe）
    // REG_SZ/REG_EXPAND_SZ: pData = wchar_t*, dataSize = (wcslen+1)*2
    // REG_DWORD:             pData = DWORD*,   dataSize = 4
    // REG_QWORD:             pData = ULONGLONG*, dataSize = 8
    // REG_BINARY:            pData = BYTE*,    dataSize = 字节数
    // valueName 为空 → 写默认值
    static bool RegWriteAsTI(HKEY hRootKey,
        const std::wstring& subKey,
        const std::wstring& valueName,
        DWORD               regType,
        const void* pData,
        DWORD               dataSize);

    // 以 TI 身份删注册表值或整个键（三级降级）
    // valueName 为空 → 删整个键（递归）
    static bool RegDeleteAsTI(HKEY hRootKey,
        const std::wstring& subKey,
        const std::wstring& valueName = L"");

    // 获取最后一次错误描述
    static std::wstring GetLastErrorMsg();

private:
    static DWORD s_lastError;

    static bool EnablePrivilege(HANDLE hToken, LPCWSTR lpPrivilege);
    static bool EnableRequiredPrivileges();
    static bool GetTrustedInstallerToken(HANDLE& hToken);
    static bool DoDelete(const std::wstring& path);
    static bool DeleteDirContents(const std::wstring& path);
    static std::wstring ExtendPath(const std::wstring& path);
};