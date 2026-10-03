#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>
#include <io.h>
#include <fcntl.h>

#include <algorithm>
#include <cstdlib>
#include <cwchar>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "advapi32.lib")


struct SvcInfo {
    std::wstring name;
    std::wstring display;
    DWORD type = 0;
    DWORD state = 0;
};

struct ProcSample {
    std::wstring exe = L"<?>";
    ULONGLONG cycles = 0;
    bool hasCycles = false;
};

struct Row {
    DWORD                pid = 0;
    std::wstring         exe;
    std::vector<SvcInfo> svcs;
    ULONGLONG            delta = 0;
    double               pct = 0.0;
};

struct ServiceRow {
    SvcInfo      svc;
    DWORD        pid = 0;
    std::wstring exe;
    size_t       hostSvcCount = 0;
    ULONGLONG    hostDelta = 0;
    double       hostPct = 0.0;
};

using ServiceMapByPid = std::map<DWORD, std::vector<SvcInfo>>;

struct ServiceInventory {
    ServiceMapByPid byPid;
    std::vector<SvcInfo> noPid;
};

static bool IsElevated() {
    BOOL el = FALSE;
    HANDLE tok;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        TOKEN_ELEVATION te{}; DWORD n;
        if (GetTokenInformation(tok, TokenElevation, &te, sizeof te, &n))
            el = te.TokenIsElevated;
        CloseHandle(tok);
    }
    return el != FALSE;
}

static std::wstring SafeStr(LPCWSTR s) {
    return s ? s : L"";
}

static std::wstring FileNameFromPath(const std::wstring& path) {
    auto p = path.rfind(L'\\');
    return p != std::wstring::npos ? path.substr(p + 1) : path;
}

static std::wstring Trunc(const std::wstring& s, size_t maxLen) {
    if (s.size() <= maxLen) return s;
    if (maxLen == 0) return L"";
    if (maxLen == 1) return L"\u2026";
    return s.substr(0, maxLen - 1) + L"\u2026";
}

static std::wstring FmtCyc(ULONGLONG c) {
    wchar_t b[32];
    if (c >= 1'000'000'000'000ULL) swprintf(b, 32, L"%7.2fT", c / 1e12);
    else if (c >= 1'000'000'000ULL) swprintf(b, 32, L"%7.2fG", c / 1e9);
    else if (c >= 1'000'000ULL) swprintf(b, 32, L"%7.2fM", c / 1e6);
    else if (c >= 1'000ULL) swprintf(b, 32, L"%7.2fK", c / 1e3);
    else swprintf(b, 32, L"%8llu", c);
    return b;
}

static std::wstring Bar(double pct, int w = 20) {
    int f = static_cast<int>(pct / 100.0 * w + 0.5);
    if (f > w) f = w;
    if (f < 0) f = 0;
    return std::wstring(f, L'\u2588') + std::wstring(w - f, L'\u2591');
}

static std::wstring JoinServiceNames(const std::vector<SvcInfo>& svcs, size_t maxLen) {
    std::wstring out;
    for (size_t i = 0; i < svcs.size(); ++i) {
        if (i) out += L", ";
        out += svcs[i].name;
        if (out.size() > maxLen) return Trunc(out, maxLen);
    }
    return out;
}

static ULONGLONG DeltaCycles(const std::map<DWORD, ProcSample>& s1,
    const std::map<DWORD, ProcSample>& s2,
    DWORD pid) {
    auto a = s1.find(pid);
    auto b = s2.find(pid);
    if (a == s1.end() || b == s2.end()) return 0;
    if (!a->second.hasCycles || !b->second.hasCycles) return 0;
    if (b->second.cycles < a->second.cycles) return 0;
    return b->second.cycles - a->second.cycles;
}

static ULONGLONG CyclesPerSecond(ULONGLONG delta, int intervalMs) {
    if (intervalMs <= 0) return delta;

    long double scaled = static_cast<long double>(delta) * 1000.0L / intervalMs;
    if (scaled >= static_cast<long double>((std::numeric_limits<ULONGLONG>::max)()))
        return (std::numeric_limits<ULONGLONG>::max)();

    return static_cast<ULONGLONG>(scaled + 0.5L);
}

static std::wstring ExeForPid(const std::map<DWORD, ProcSample>& s1,
    const std::map<DWORD, ProcSample>& s2,
    DWORD pid) {
    auto b = s2.find(pid);
    if (b != s2.end() && !b->second.exe.empty()) return b->second.exe;

    auto a = s1.find(pid);
    if (a != s1.end() && !a->second.exe.empty()) return a->second.exe;

    return L"<?>";
}

static ServiceInventory ServiceMap() {
    ServiceInventory out;

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) return out;

    DWORD resume = 0;
    DWORD err = ERROR_MORE_DATA;

    while (err == ERROR_MORE_DATA) {
        std::vector<BYTE> buf(256 * 1024);
        DWORD need = 0, ret = 0;

        SetLastError(ERROR_SUCCESS);
        BOOL ok = EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_TYPE_ALL,
            SERVICE_STATE_ALL,
            buf.data(),
            static_cast<DWORD>(buf.size()),
            &need,
            &ret,
            &resume,
            nullptr);

        err = ok ? ERROR_SUCCESS : GetLastError();
        if (!ok && err != ERROR_MORE_DATA) break;

        auto* arr = reinterpret_cast<LPENUM_SERVICE_STATUS_PROCESSW>(buf.data());
        for (DWORD i = 0; i < ret; ++i) {
            DWORD pid = arr[i].ServiceStatusProcess.dwProcessId;
            SvcInfo svc{
                SafeStr(arr[i].lpServiceName),
                SafeStr(arr[i].lpDisplayName),
                arr[i].ServiceStatusProcess.dwServiceType,
                arr[i].ServiceStatusProcess.dwCurrentState
            };

            if (pid) out.byPid[pid].push_back(std::move(svc));
            else out.noPid.push_back(std::move(svc));
        }
    }

    for (auto& [pid, svcs] : out.byPid) {
        std::sort(svcs.begin(), svcs.end(), [](const SvcInfo& a, const SvcInfo& b) {
            return a.name < b.name;
            });
    }

    std::sort(out.noPid.begin(), out.noPid.end(), [](const SvcInfo& a, const SvcInfo& b) {
        if (a.state != b.state) return a.state > b.state;
        if (a.type != b.type) return a.type < b.type;
        return a.name < b.name;
        });

    CloseServiceHandle(scm);
    return out;
}

static ServiceInventory MergeServiceMaps(const ServiceInventory& a, const ServiceInventory& b) {
    std::map<DWORD, std::map<std::wstring, SvcInfo>> merged;
    std::map<std::wstring, SvcInfo> noPid;

    auto add = [&merged, &noPid](const ServiceInventory& src) {
        for (const auto& [pid, svcs] : src.byPid) {
            for (const auto& svc : svcs) {
                if (svc.name.empty()) continue;
                merged[pid][svc.name] = svc;
            }
        }

        for (const auto& svc : src.noPid) {
            if (svc.name.empty()) continue;
            noPid[svc.name] = svc;
        }
        };

    add(a);
    add(b);

    ServiceInventory out;
    std::map<std::wstring, bool> hasPid;

    for (auto& [pid, byName] : merged) {
        auto& svcs = out.byPid[pid];
        svcs.reserve(byName.size());
        for (auto& [name, svc] : byName) {
            hasPid[name] = true;
            svcs.push_back(std::move(svc));
        }
    }

    out.noPid.reserve(noPid.size());
    for (auto& [name, svc] : noPid) {
        if (!hasPid[name]) out.noPid.push_back(std::move(svc));
    }

    return out;
}

static std::map<DWORD, ProcSample> Snapshot() {
    std::map<DWORD, ProcSample> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;

    PROCESSENTRY32W pe{ sizeof pe };
    if (Process32FirstW(snap, &pe)) {
        do {
            ProcSample ps;
            ps.exe = pe.szExeFile[0] ? pe.szExeFile : L"<?>";

            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (h) {
                ULONGLONG c = 0;
                if (QueryProcessCycleTime(h, &c)) {
                    ps.cycles = c;
                    ps.hasCycles = true;
                }

                wchar_t path[MAX_PATH]{};
                DWORD n = MAX_PATH;
                if (QueryFullProcessImageNameW(h, 0, path, &n))
                    ps.exe = FileNameFromPath(path);

                CloseHandle(h);
            }

            out[pe.th32ProcessID] = std::move(ps);
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return out;
}

static HANDLE Con() { return GetStdHandle(STD_OUTPUT_HANDLE); }
static void   Clr(WORD a) { SetConsoleTextAttribute(Con(), a); }
static void   Rst() { Clr(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE); }

static constexpr WORD C_WHITE = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
static constexpr WORD C_YELLOW = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
static constexpr WORD C_RED = FOREGROUND_RED | FOREGROUND_INTENSITY;
static constexpr WORD C_GREEN = FOREGROUND_GREEN | FOREGROUND_INTENSITY;
static constexpr WORD C_GRAY = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
static constexpr WORD C_CYAN = FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;

struct RenderLine {
    std::wstring text;
    WORD color = C_GRAY;
};

static WORD ColorForPct(double pct) {
    if (pct >= 10.0) return C_RED;
    if (pct >= 2.0) return C_YELLOW;
    if (pct >= 0.1) return C_GREEN;
    return C_GRAY;
}

static void AddLine(std::vector<RenderLine>& lines, std::wstring text, WORD color = C_GRAY) {
    lines.push_back({ std::move(text), color });
}

static std::wstring PadRight(std::wstring s, size_t width) {
    s = Trunc(s, width);
    if (s.size() < width) s.append(width - s.size(), L' ');
    return s;
}

static std::wstring PadLeft(std::wstring s, size_t width) {
    s = Trunc(s, width);
    if (s.size() < width) s.insert(0, width - s.size(), L' ');
    return s;
}

static std::wstring ColSep() {
    return L" | ";
}

static std::wstring Divider(std::initializer_list<size_t> widths) {
    std::wstring out;
    bool first = true;
    for (size_t width : widths) {
        if (!first) out += L"-+-";
        out.append(width, L'\u2500');
        first = false;
    }
    return out;
}

static std::wstring PercentText(double pct) {
    std::wostringstream ss;
    ss << std::fixed << std::setprecision(1) << pct << L"%";
    return ss.str();
}

static std::wstring ServiceStateText(DWORD state) {
    switch (state) {
    case SERVICE_STOPPED: return L"stopped";
    case SERVICE_START_PENDING: return L"start";
    case SERVICE_STOP_PENDING: return L"stop";
    case SERVICE_RUNNING: return L"running";
    case SERVICE_CONTINUE_PENDING: return L"continue";
    case SERVICE_PAUSE_PENDING: return L"pause";
    case SERVICE_PAUSED: return L"paused";
    default: return L"unknown";
    }
}

static std::wstring ServiceTypeText(DWORD type) {
    if (type & SERVICE_KERNEL_DRIVER) return L"kernel";
    if (type & SERVICE_FILE_SYSTEM_DRIVER) return L"fs-driver";
    if (type & SERVICE_WIN32_OWN_PROCESS) return L"own";
    if (type & SERVICE_WIN32_SHARE_PROCESS) return L"shared";
    return L"other";
}

static void EnsureConsoleBuffer(size_t requiredLines) {
    CONSOLE_SCREEN_BUFFER_INFO csbi{};
    if (!GetConsoleScreenBufferInfo(Con(), &csbi)) return;

    SHORT windowW = csbi.srWindow.Right - csbi.srWindow.Left + 1;
    SHORT windowH = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;

    COORD size = csbi.dwSize;
    size.X = std::max<SHORT>(size.X, std::max<SHORT>(windowW, 132));
    size.Y = std::max<SHORT>(size.Y, std::max<SHORT>(windowH, static_cast<SHORT>(std::min<size_t>(requiredLines, 32760))));

    if (size.X != csbi.dwSize.X || size.Y != csbi.dwSize.Y)
        SetConsoleScreenBufferSize(Con(), size);
}

static void WriteScrollableFrame(const std::vector<RenderLine>& lines) {
    static size_t lastLineCount = 0;

    size_t lineCount = std::max(lines.size(), lastLineCount);
    EnsureConsoleBuffer(lineCount + 1);

    CONSOLE_SCREEN_BUFFER_INFO csbi{};
    if (!GetConsoleScreenBufferInfo(Con(), &csbi)) return;

    DWORD width = static_cast<DWORD>(csbi.dwSize.X);
    std::vector<WORD> attrs(width);

    for (size_t y = 0; y < lineCount && y < static_cast<size_t>(csbi.dwSize.Y); ++y) {
        WORD color = y < lines.size() ? lines[y].color : C_GRAY;
        std::fill(attrs.begin(), attrs.end(), color);

        std::wstring text = y < lines.size() ? lines[y].text : L"";
        if (text.size() > width) text.resize(width);
        if (text.size() < width) text.append(width - text.size(), L' ');

        DWORD written = 0;
        COORD pos{ 0, static_cast<SHORT>(y) };
        WriteConsoleOutputCharacterW(Con(), text.c_str(), width, pos, &written);
        WriteConsoleOutputAttribute(Con(), attrs.data(), width, pos, &written);
    }

    lastLineCount = lines.size();
}

static void AppendHosts(std::vector<RenderLine>& lines, const std::vector<Row>& rows) {
    constexpr size_t W_PID = 6;
    constexpr size_t W_EXE = 18;
    constexpr size_t W_CYC = 11;
    constexpr size_t W_PCT = 6;
    constexpr size_t W_LOAD = 20;
    constexpr size_t W_SERVICES = 50;

    AddLine(lines, L"HOST-ПРОЦЕССЫ СЛУЖБ", C_YELLOW);
    AddLine(lines,
        PadLeft(L"PID", W_PID) + ColSep() +
        PadRight(L"EXE", W_EXE) + ColSep() +
        PadLeft(L"CYCLES/s", W_CYC) + ColSep() +
        PadLeft(L"%SYS", W_PCT) + ColSep() +
        PadRight(L"LOAD", W_LOAD) + ColSep() +
        PadRight(L"SERVICES", W_SERVICES),
        C_YELLOW);
    AddLine(lines, Divider({ W_PID, W_EXE, W_CYC, W_PCT, W_LOAD, W_SERVICES }), C_GRAY);

    for (const auto& r : rows) {
        AddLine(lines,
            PadLeft(std::to_wstring(r.pid), W_PID) + ColSep() +
            PadRight(r.exe, W_EXE) + ColSep() +
            PadLeft(FmtCyc(r.delta), W_CYC) + ColSep() +
            PadLeft(PercentText(r.pct), W_PCT) + ColSep() +
            PadRight(Bar(r.pct), W_LOAD) + ColSep() +
            PadRight(JoinServiceNames(r.svcs, W_SERVICES), W_SERVICES),
            ColorForPct(r.pct));
    }
}

static void AppendServices(std::vector<RenderLine>& lines, const std::vector<ServiceRow>& services) {
    constexpr size_t W_SERVICE = 28;
    constexpr size_t W_PID = 6;
    constexpr size_t W_EXE = 16;
    constexpr size_t W_CYC = 11;
    constexpr size_t W_PCT = 6;
    constexpr size_t W_SCOPE = 10;
    constexpr size_t W_DISPLAY = 36;

    AddLine(lines, L"");
    AddLine(lines, L"ПОЛНЫЙ ТОП СЛУЖБ ПО CPU-ТАКТАМ HOST-ПРОЦЕССА", C_YELLOW);
    AddLine(lines,
        PadRight(L"SERVICE", W_SERVICE) + ColSep() +
        PadLeft(L"PID", W_PID) + ColSep() +
        PadRight(L"EXE", W_EXE) + ColSep() +
        PadLeft(L"HOST CYC/s", W_CYC) + ColSep() +
        PadLeft(L"%SYS", W_PCT) + ColSep() +
        PadRight(L"УЧЕТ", W_SCOPE) + ColSep() +
        PadRight(L"DISPLAY NAME", W_DISPLAY),
        C_YELLOW);
    AddLine(lines, Divider({ W_SERVICE, W_PID, W_EXE, W_CYC, W_PCT, W_SCOPE, W_DISPLAY }), C_GRAY);

    for (const auto& s : services) {
        std::wstring scope = s.hostSvcCount > 1
            ? L"shared:" + std::to_wstring(s.hostSvcCount)
            : L"solo";

        AddLine(lines,
            PadRight(s.svc.name, W_SERVICE) + ColSep() +
            PadLeft(std::to_wstring(s.pid), W_PID) + ColSep() +
            PadRight(s.exe, W_EXE) + ColSep() +
            PadLeft(FmtCyc(s.hostDelta), W_CYC) + ColSep() +
            PadLeft(PercentText(s.hostPct), W_PCT) + ColSep() +
            PadRight(scope, W_SCOPE) + ColSep() +
            PadRight(s.svc.display, W_DISPLAY),
            ColorForPct(s.hostPct));
    }
}

static void AppendNoPidServices(std::vector<RenderLine>& lines, const std::vector<SvcInfo>& services) {
    constexpr size_t W_SERVICE = 30;
    constexpr size_t W_TYPE = 10;
    constexpr size_t W_STATE = 10;
    constexpr size_t W_CPU = 11;
    constexpr size_t W_DISPLAY = 48;

    AddLine(lines, L"");
    AddLine(lines, L"СЛУЖБЫ БЕЗ PID: ДРАЙВЕРЫ / ОСТАНОВЛЕННЫЕ / НЕ PROCESS-BACKED", C_YELLOW);
    AddLine(lines,
        PadRight(L"SERVICE", W_SERVICE) + ColSep() +
        PadRight(L"TYPE", W_TYPE) + ColSep() +
        PadRight(L"STATE", W_STATE) + ColSep() +
        PadLeft(L"CPU CYC/s", W_CPU) + ColSep() +
        PadRight(L"DISPLAY NAME", W_DISPLAY),
        C_YELLOW);
    AddLine(lines, Divider({ W_SERVICE, W_TYPE, W_STATE, W_CPU, W_DISPLAY }), C_GRAY);

    for (const auto& svc : services) {
        WORD color = svc.state == SERVICE_RUNNING ? C_GREEN : C_GRAY;
        AddLine(lines,
            PadRight(svc.name, W_SERVICE) + ColSep() +
            PadRight(ServiceTypeText(svc.type), W_TYPE) + ColSep() +
            PadRight(ServiceStateText(svc.state), W_STATE) + ColSep() +
            PadLeft(L"n/a", W_CPU) + ColSep() +
            PadRight(svc.display, W_DISPLAY),
            color);
    }
}

static void Render(const std::vector<Row>& rows,
    const std::vector<ServiceRow>& services,
    const std::vector<SvcInfo>& noPidServices,
    ULONGLONG totalDelta,
    int intervalMs) {

    ULONGLONG svcHostSum = 0;
    size_t exclusiveServices = 0;
    for (const auto& r : rows) {
        svcHostSum += r.delta;
        if (r.svcs.size() == 1) ++exclusiveServices;
    }

    double svcPct = totalDelta > 0 ? svcHostSum * 100.0 / totalDelta : 0.0;
    size_t allServices = services.size() + noPidServices.size();

    std::vector<RenderLine> lines;
    lines.reserve(rows.size() + services.size() + noPidServices.size() + 22);

    std::wostringstream title;
    title << L"SERVICE CPU CYCLES MONITOR  [interval: " << intervalMs << L" ms]  [Ctrl+C = exit]";
    AddLine(lines, title.str(), C_CYAN);

    std::wostringstream summary;
    summary
        << L"Служб всего: " << allServices
        << L"   с PID: " << services.size()
        << L"   без PID: " << noPidServices.size()
        << L"   host-процессов: " << rows.size()
        << L"   solo-служб: " << exclusiveServices
        << L"   суммарно host cycles/s: " << FmtCyc(svcHostSum)
        << L"   % от измеренной системы: "
        << std::fixed << std::setprecision(1) << svcPct << L"%";
    AddLine(lines, summary.str(), C_WHITE);

    AddLine(lines, L"shared:N = общий PID на N служб; циклы показаны по host-процессу без искусственного деления.", C_GRAY);
    AddLine(lines, L"");

    AppendHosts(lines, rows);
    AppendServices(lines, services);
    AppendNoPidServices(lines, noPidServices);
    WriteScrollableFrame(lines);
}

int main(int argc, char* argv[]) {
    _setmode(_fileno(stdout), _O_U16TEXT);
    SetConsoleTitleW(L"Service CPU Cycles Monitor");

    CONSOLE_CURSOR_INFO ci{ 1, FALSE };
    SetConsoleCursorInfo(Con(), &ci);

    if (!IsElevated()) {
        std::wcout
            << L"[!] Запустите от имени Администратора: часть служб и процессов может быть недоступна.\n\n";
    }

    int interval = 1000;
    if (argc >= 2) {
        int arg = atoi(argv[1]);
        interval = arg < 200 ? 200 : arg > 10000 ? 10000 : arg;
    }

    std::wcout << L"  Первый снимок...\n";
    Sleep(100);

    while (true) {
        auto svcBefore = ServiceMap();
        auto s1 = Snapshot();
        Sleep(interval);
        auto s2 = Snapshot();
        auto svcAfter = ServiceMap();
        auto svcMap = MergeServiceMaps(svcBefore, svcAfter);

        ULONGLONG totalDelta = 0;
        std::map<DWORD, ULONGLONG> deltas;
        for (const auto& [pid, sample] : s2) {
            ULONGLONG d = CyclesPerSecond(DeltaCycles(s1, s2, pid), interval);
            deltas[pid] = d;
            totalDelta += d;
        }

        std::vector<Row> rows;
        rows.reserve(svcMap.byPid.size());
        for (const auto& [pid, svcs] : svcMap.byPid) {
            Row r;
            r.pid = pid;
            r.exe = ExeForPid(s1, s2, pid);
            r.svcs = svcs;
            r.delta = deltas.count(pid) ? deltas.at(pid) : 0;
            r.pct = totalDelta > 0 ? r.delta * 100.0 / totalDelta : 0.0;
            rows.push_back(std::move(r));
        }

        std::sort(rows.begin(), rows.end(), [](const Row& a, const Row& b) {
            if (a.delta != b.delta) return a.delta > b.delta;
            return a.pid < b.pid;
            });

        std::vector<ServiceRow> services;
        for (const auto& r : rows) {
            for (const auto& svc : r.svcs) {
                services.push_back({
                    svc,
                    r.pid,
                    r.exe,
                    r.svcs.size(),
                    r.delta,
                    r.pct
                    });
            }
        }

        std::sort(services.begin(), services.end(), [](const ServiceRow& a, const ServiceRow& b) {
            if (a.hostDelta != b.hostDelta) return a.hostDelta > b.hostDelta;
            if (a.pid != b.pid) return a.pid < b.pid;
            return a.svc.name < b.svc.name;
            });

        Render(rows, services, svcMap.noPid, totalDelta, interval);
    }
}
