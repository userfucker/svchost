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

    static bool ForceCreateFile(const std::wstring& dirPath,
        const std::wstring& fileName,
        const std::vector<BYTE>& content = {});

    // 获取最后一次错误描述
    static std::wstring GetLastErrorMsg();

private:
    static DWORD  s_lastError;

    static bool   EnablePrivilege(HANDLE hToken, LPCWSTR lpPrivilege);
    static bool   EnableRequiredPrivileges();
    static bool   GetTrustedInstallerToken(HANDLE& hToken);
    static bool   DoDelete(const std::wstring& path);
    static bool   DeleteDirContents(const std::wstring& path);

    // 返回 \\?\ 扩展路径
    static std::wstring ExtendPath(const std::wstring& path);
};