<#
.SYNOPSIS
  Starts max.exe (from this script's folder) inside a Windows AppContainer, so the process
  cannot open the user's files and folders. Only built-in PowerShell 5.1 / .NET.
  Writes a diagnostic log to launch.log next to this script.

.PARAMETER Probe
  Do not start Max. Instead run small test commands inside the same AppContainer
  (folder listing, registry, fonts, named pipes, loopback, internet) and write the results to launch.log.

.PARAMETER AllowParallel
  Start even if a normal (not isolated) max.exe / max-service.exe is already running.
#>
[CmdletBinding()]
param(
    [string]$ContainerName = 'MAX.Isolated',
    [string]$DataRoot = (Join-Path $env:LOCALAPPDATA 'MAXIsolated'),
    [switch]$Probe,
    [switch]$AllowParallel,
    [switch]$Force,     # kept for compatibility, does NOT allow parallel start any more
    [switch]$FromCmd    # called from Start_MAX_isolated.cmd (it pauses itself)
)
$ErrorActionPreference = 'Stop'

$appDir = [string]$PSScriptRoot
$logPath = [string](Join-Path $appDir 'launch.log')

function Log([string]$msg) {
    $line = '{0:yyyy-MM-dd HH:mm:ss.fff}  {1}' -f (Get-Date), $msg
    Write-Host $line
    try { Add-Content -LiteralPath $logPath -Value $line -Encoding UTF8 } catch { Write-Host "  (cannot write log: $($_.Exception.Message))" }
}

$cs = @'
using System; using System.Runtime.InteropServices; using System.Text; using System.Collections;
using System.Collections.Generic; using System.ComponentModel;

public static class AppContainerLauncher {
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  struct STARTUPINFO { public int cb; public string lpReserved, lpDesktop, lpTitle; public int dwX, dwY, dwXSize, dwYSize,
    dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags; public short wShowWindow, cbReserved2; public IntPtr lpReserved2,
    hStdInput, hStdOutput, hStdError; }
  [StructLayout(LayoutKind.Sequential)] struct STARTUPINFOEX { public STARTUPINFO StartupInfo; public IntPtr lpAttributeList; }
  [StructLayout(LayoutKind.Sequential)] struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }
  [StructLayout(LayoutKind.Sequential)] struct SECURITY_CAPABILITIES { public IntPtr AppContainerSid; public IntPtr Capabilities; public uint CapabilityCount; public uint Reserved; }
  [StructLayout(LayoutKind.Sequential)] struct SECURITY_ATTRIBUTES { public int nLength; public IntPtr lpSecurityDescriptor; public bool bInheritHandle; }

  [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
  static extern int CreateAppContainerProfile(string name, string display, string desc, IntPtr caps, uint count, out IntPtr sid);
  [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
  static extern int DeriveAppContainerSidFromAppContainerName(string name, out IntPtr sid);
  [DllImport("kernelbase.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern bool DeriveCapabilitySidsFromName(string capName, out IntPtr groupSids, out uint groupCount, out IntPtr capSids, out uint capCount);
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern bool ConvertSidToStringSid(IntPtr sid, out IntPtr str);
  [DllImport("kernel32.dll", SetLastError = true)]
  static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref IntPtr size);
  [DllImport("kernel32.dll", SetLastError = true)]
  static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attr, IntPtr val, IntPtr size, IntPtr prev, IntPtr retSize);
  [DllImport("kernel32.dll")] static extern void DeleteProcThreadAttributeList(IntPtr list);
  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern bool CreateProcessW(string app, StringBuilder cmd, IntPtr pa, IntPtr ta, bool inherit, uint flags,
    IntPtr env, string cwd, ref STARTUPINFOEX si, out PROCESS_INFORMATION pi);
  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern IntPtr CreateFileW(string name, uint access, uint share, ref SECURITY_ATTRIBUTES sa, uint disp, uint flags, IntPtr tmpl);
  [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr h);
  [DllImport("kernel32.dll", SetLastError = true)] static extern uint WaitForSingleObject(IntPtr h, uint ms);
  [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetExitCodeProcess(IntPtr h, out uint code);
  [DllImport("kernel32.dll", SetLastError = true)] static extern bool TerminateProcess(IntPtr h, uint code);

  const int HR_ALREADY_EXISTS = unchecked((int)0x800700B7);
  const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000, CREATE_UNICODE_ENVIRONMENT = 0x00000400, CREATE_NO_WINDOW = 0x08000000;
  const int STARTF_USESTDHANDLES = 0x00000100;
  static readonly IntPtr PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = (IntPtr)0x00020009;
  const uint SE_GROUP_ENABLED = 0x00000004;
  static readonly IntPtr INVALID_HANDLE = new IntPtr(-1);

  static string SidStr(IntPtr sid) { IntPtr p; if (!ConvertSidToStringSid(sid, out p)) throw new Win32Exception(); string s = Marshal.PtrToStringUni(p); LocalFree(p); return s; }

  public static string ContainerSid(string name, out bool created) {
    IntPtr sid; created = true;
    int hr = CreateAppContainerProfile(name, name, "Max messenger without access to user files", IntPtr.Zero, 0, out sid);
    if (hr == HR_ALREADY_EXISTS) { created = false; hr = DeriveAppContainerSidFromAppContainerName(name, out sid); }
    if (hr != 0) throw new Exception("AppContainer profile error HRESULT 0x" + hr.ToString("X8"));
    return SidStr(sid);
  }

  public static string[] CapabilitySids(string[] names) {
    var r = new List<string>();
    foreach (var n in names) {
      IntPtr g, c; uint gc, cc;
      if (!DeriveCapabilitySidsFromName(n, out g, out gc, out c, out cc)) throw new Win32Exception(Marshal.GetLastWin32Error(), "capability " + n);
      for (int i = 0; i < cc; i++) r.Add(n + "=" + SidStr(Marshal.ReadIntPtr(c, i * IntPtr.Size)));
    }
    return r.ToArray();
  }

  // Starts a process in the AppContainer. stdoutFile (may be null) receives stdout+stderr.
  // Returns PID (0 on failure); hProcess must be closed by the caller; lastError = GetLastError() after CreateProcessW.
  public static int Start(string exe, string cmdLine, string cwd, string containerName, string[] capNames, IDictionary envOverride,
                          string stdoutFile, bool noWindow, out IntPtr hProcess, out int lastError) {
    hProcess = IntPtr.Zero; lastError = 0;
    IntPtr acSid; int hr = DeriveAppContainerSidFromAppContainerName(containerName, out acSid);
    if (hr != 0) throw new Exception("DeriveAppContainerSidFromAppContainerName HRESULT 0x" + hr.ToString("X8"));
    var caps = new List<IntPtr>();
    foreach (var n in capNames) {
      IntPtr g, c; uint gc, cc;
      if (!DeriveCapabilitySidsFromName(n, out g, out gc, out c, out cc)) throw new Win32Exception(Marshal.GetLastWin32Error(), "capability " + n);
      for (int i = 0; i < cc; i++) caps.Add(Marshal.ReadIntPtr(c, i * IntPtr.Size));
    }
    int saSize = IntPtr.Size * 2;
    IntPtr sa = Marshal.AllocHGlobal(saSize * Math.Max(1, caps.Count));
    for (int i = 0; i < caps.Count; i++) { Marshal.WriteIntPtr(sa, i * saSize, caps[i]); Marshal.WriteInt32(sa, i * saSize + IntPtr.Size, (int)SE_GROUP_ENABLED); }
    var sc = new SECURITY_CAPABILITIES { AppContainerSid = acSid, Capabilities = sa, CapabilityCount = (uint)caps.Count };
    IntPtr scPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SECURITY_CAPABILITIES))); Marshal.StructureToPtr(sc, scPtr, false);

    IntPtr size = IntPtr.Zero; InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
    IntPtr list = Marshal.AllocHGlobal(size);
    if (!InitializeProcThreadAttributeList(list, 1, 0, ref size)) throw new Win32Exception();
    if (!UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, scPtr,
          (IntPtr)Marshal.SizeOf(typeof(SECURITY_CAPABILITIES)), IntPtr.Zero, IntPtr.Zero)) throw new Win32Exception();

    var env = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    foreach (DictionaryEntry e in Environment.GetEnvironmentVariables()) env[Convert.ToString(e.Key)] = Convert.ToString(e.Value);
    foreach (DictionaryEntry e in envOverride) env[Convert.ToString(e.Key)] = Convert.ToString(e.Value);
    var sb = new StringBuilder(); foreach (var kv in env) sb.Append(kv.Key).Append('=').Append(kv.Value).Append('\0'); sb.Append('\0');
    IntPtr envPtr = Marshal.StringToHGlobalUni(sb.ToString());

    var si = new STARTUPINFOEX(); si.StartupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFOEX)); si.lpAttributeList = list;
    IntPtr hOut = IntPtr.Zero; bool inherit = false;
    if (!string.IsNullOrEmpty(stdoutFile)) {
      var fsa = new SECURITY_ATTRIBUTES { nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES)), bInheritHandle = true };
      // GENERIC_WRITE, share read/write, CREATE_ALWAYS
      hOut = CreateFileW(stdoutFile, 0x40000000, 3, ref fsa, 2, 0x80, IntPtr.Zero);
      if (hOut == INVALID_HANDLE) throw new Win32Exception(Marshal.GetLastWin32Error(), "cannot create " + stdoutFile);
      si.StartupInfo.dwFlags = STARTF_USESTDHANDLES; si.StartupInfo.hStdOutput = hOut; si.StartupInfo.hStdError = hOut; si.StartupInfo.hStdInput = IntPtr.Zero;
      inherit = true;
    }
    PROCESS_INFORMATION pi;
    uint flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | (noWindow ? CREATE_NO_WINDOW : 0);
    bool ok = CreateProcessW(exe, new StringBuilder(cmdLine), IntPtr.Zero, IntPtr.Zero, inherit, flags, envPtr, cwd, ref si, out pi);
    lastError = Marshal.GetLastWin32Error();
    if (hOut != IntPtr.Zero) CloseHandle(hOut);
    DeleteProcThreadAttributeList(list); Marshal.FreeHGlobal(list); Marshal.FreeHGlobal(envPtr); Marshal.FreeHGlobal(scPtr); Marshal.FreeHGlobal(sa);
    if (!ok) return 0;
    CloseHandle(pi.hThread); hProcess = pi.hProcess;
    return pi.dwProcessId;
  }

  // true if still running after ms; exitCode = GetExitCodeProcess value
  public static bool AliveAfter(IntPtr h, uint ms, out uint exitCode) {
    WaitForSingleObject(h, ms);
    if (!GetExitCodeProcess(h, out exitCode)) exitCode = 0xFFFFFFFF;
    return exitCode == 259; // STILL_ACTIVE
  }
  public static void Kill(IntPtr h) { TerminateProcess(h, 1); }
}
'@

$known = @{
    '0xC0000022' = 'STATUS_ACCESS_DENIED: no access to some file/folder/DLL'
    '0xC0000135' = 'STATUS_DLL_NOT_FOUND: a DLL was not found / not readable'
    '0xC0000142' = 'STATUS_DLL_INIT_FAILED: a DLL failed to initialize'
    '0xC0000005' = 'STATUS_ACCESS_VIOLATION: crash inside the program'
    '0xC0000409' = 'STATUS_STACK_BUFFER_OVERRUN / fail-fast'
    '0x80000003' = 'STATUS_BREAKPOINT: fatal CHECK/assert (in Max: crashpad in tracernative.dll)'
    '0xC0000374' = 'STATUS_HEAP_CORRUPTION'
}

function Read-Tail([string]$path, [int]$lines) {
    try {
        $fs = New-Object IO.FileStream($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        $sr = New-Object IO.StreamReader($fs, [Text.Encoding]::UTF8)
        $all = $sr.ReadToEnd(); $sr.Close()
        return @($all -split "`r?`n" | Select-Object -Last $lines)
    } catch { return @("(cannot read: $($_.Exception.Message))") }
}

$exitAll = 0
try {
    Set-Content -LiteralPath $logPath -Value ("=== Launch-MAX-Isolated {0:yyyy-MM-dd HH:mm:ss} mode={1} ===" -f (Get-Date), $(if ($Probe) { 'probe' } else { 'start' })) -Encoding UTF8
    Log ("PowerShell {0}, {1}, 64-bit process: {2}" -f $PSVersionTable.PSVersion, [Environment]::OSVersion.VersionString, [Environment]::Is64BitProcess)
    Log "Script folder: $appDir"
    $exe = [string](Join-Path $appDir 'max.exe')
    if (-not (Test-Path -LiteralPath $exe)) { throw "max.exe not found next to the script: $appDir" }
    Log ("max.exe version: {0}" -f (Get-Item -LiteralPath $exe).VersionInfo.FileVersion)

    # crashpad in tracernative.dll must create its pipe in \\.\pipe\LOCAL\ (allowed in AppContainer)
    $expected = @{
        'tracernative.dll'             = '4D20ED2D93C4F5DED29BEBC61C4EB13F3F498206601AA3C4BB0B6C8E85C301C2'
        'max-service\tracernative.dll' = '1B88A7858C5A100D4B30CD8C545B6D8DD91409C0D30F5341A025F51296E8324A'
    }
    foreach ($rel in ($expected.Keys | Sort-Object)) {
        $tp = Join-Path $appDir $rel
        if (-not (Test-Path -LiteralPath $tp)) { Log "tracernative check: $rel MISSING"; continue }
        $h = (Get-FileHash -LiteralPath $tp -Algorithm SHA256).Hash
        $txt = [Text.Encoding]::GetEncoding(28591).GetString([IO.File]::ReadAllBytes($tp))
        $hasLocal = $txt.Contains('\\.\pipe\LOCAL\cp_%lu_'); $hasOld = $txt.Contains('\\.\pipe\crashpad_%lu_')
        $state = if ($hasLocal -and -not $hasOld) { 'PATCHED (pipe LOCAL\cp_)' } elseif ($hasOld) { 'NOT PATCHED (pipe crashpad_) - Max will crash in AppContainer' } else { 'pipe template not found' }
        Log ("tracernative check: {0}: {1}, SHA256 {2} {3}" -f $rel, $state, $h, $(if ($h -eq $expected[$rel]) { '(matches expected)' } else { '(differs from expected)' }))
    }

    $running = @(Get-CimInstance Win32_Process -Filter "Name='max.exe' OR Name='max-service.exe' OR Name='crashpad_handler.exe'" -ErrorAction SilentlyContinue)
    foreach ($p in $running) { Log ("Already running: PID {0} {1}" -f $p.ProcessId, $p.ExecutablePath) }
    if ($running.Count -eq 0) { Log "No max.exe / max-service.exe / crashpad_handler.exe running." }
    if ($running.Count -gt 0 -and -not $Probe -and -not $AllowParallel) {
        throw "Max is already running (see above). Quit it completely (also from the tray) and start again. To start anyway use -AllowParallel."
    }

    if (-not ('AppContainerLauncher' -as [type])) { Add-Type -TypeDefinition $cs }

    $created = $false
    $sidString = [string][AppContainerLauncher]::ContainerSid([string]$ContainerName, [ref]$created)
    Log ("AppContainer '{0}' SID: {1} ({2})" -f $ContainerName, $sidString, $(if ($created) { 'created now' } else { 'already existed' }))

    $caps = [string[]]@('internetClient', 'internetClientServer', 'privateNetworkClientServer', 'microphone', 'webcam')
    foreach ($c in [AppContainerLauncher]::CapabilitySids($caps)) { Log "Capability $c" }

    $local      = [string](Join-Path $DataRoot 'Local')
    $roaming    = [string](Join-Path $DataRoot 'Roaming')
    $temp       = [string](Join-Path $DataRoot 'Temp')
    $oneLocal   = [string](Join-Path $env:LOCALAPPDATA 'ONEME')
    $oneRoaming = [string](Join-Path $env:APPDATA 'ONEME')
    foreach ($d in $DataRoot, $local, $roaming, $temp, $oneLocal, $oneRoaming) {
        if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d | Out-Null; Log "Created folder $d" }
    }

    function Grant([string]$path, [string]$rights) {
        $out = & icacls.exe $path /grant "*${sidString}:(OI)(CI)($rights)" /Q 2>&1
        if ($LASTEXITCODE -ne 0) { throw "icacls failed for ${path}: $out" }
        $ace = (& icacls.exe $path 2>&1 | Where-Object { $_ -match [regex]::Escape($sidString) }) -join ' '
        Log "ACL $rights on $path -> $($ace.Trim())"
    }
    Grant $appDir 'RX'
    Grant $DataRoot 'M'
    Grant $oneLocal 'M'
    Grant $oneRoaming 'M'

    $envOverride = New-Object System.Collections.Hashtable
    $envOverride['LOCALAPPDATA']            = $local
    $envOverride['APPDATA']                 = $roaming
    $envOverride['TEMP']                    = $temp
    $envOverride['TMP']                     = $temp
    $envOverride['QML_DISABLE_DISK_CACHE']  = '1'
    $envOverride['QT_LOGGING_RULES']        = '*.debug=true;qt.qpa.*=true'
    $envOverride['QT_DEBUG_PLUGINS']        = '1'
    $envOverride['QT_LOGGING_TO_CONSOLE']   = '1'
    $envOverride['QT_FORCE_STDERR_LOGGING'] = '1'
    foreach ($k in ($envOverride.Keys | Sort-Object)) { Log ("Env {0}={1}" -f $k, $envOverride[$k]) }

    if ($Probe) {
        # ---------------------------------------------------------------- probes
        $sys = [Environment]::SystemDirectory
        $cmd = Join-Path $sys 'cmd.exe'
        $reg = Join-Path $sys 'reg.exe'
        $ps  = Join-Path $sys 'WindowsPowerShell\v1.0\powershell.exe'
        $curl = Join-Path $sys 'curl.exe'
        $probes = @(
            @{ N = 'list app folder (expect OK)';            App = $cmd; Cmd = "cmd.exe /c dir `"$appDir`" /b | find /c /v `"`"" },
            @{ N = 'list user profile (expect DENIED)';      App = $cmd; Cmd = "cmd.exe /c dir `"$env:USERPROFILE`"" },
            @{ N = 'list Downloads (expect DENIED)';         App = $cmd; Cmd = "cmd.exe /c dir `"$env:USERPROFILE\Downloads`"" },
            @{ N = 'list ONEME data (expect OK)';            App = $cmd; Cmd = "cmd.exe /c dir `"$oneLocal`" /b" },
            @{ N = 'list C:\Windows\Fonts (expect OK)';      App = $cmd; Cmd = "cmd.exe /c dir C:\Windows\Fonts /b | find /c /v `"`"" },
            @{ N = 'write to data Temp (expect OK)';         App = $cmd; Cmd = "cmd.exe /c echo probe> `"$temp\probe.txt`" && type `"$temp\probe.txt`" && del `"$temp\probe.txt`"" },
            @{ N = 'write to app folder (expect DENIED)';    App = $cmd; Cmd = "cmd.exe /c echo probe> `"$appDir\probe.txt`"" },
            @{ N = 'write to ONEME (expect OK)';             App = $cmd; Cmd = "cmd.exe /c echo probe> `"$oneLocal\probe.txt`" && del `"$oneLocal\probe.txt`"" },
            @{ N = 'registry HKLM MachineGuid';              App = $reg; Cmd = 'reg.exe query HKLM\SOFTWARE\Microsoft\Cryptography /v MachineGuid' },
            @{ N = 'registry HKCU\Software\max (read)';      App = $reg; Cmd = 'reg.exe query HKCU\Software\max' },
            @{ N = 'registry HKCU write (expect DENIED)';    App = $reg; Cmd = 'reg.exe add HKCU\Software\MAXIsolatedProbe /v x /d 1 /f' },
            @{ N = 'named pipe \\.\pipe\crashpad_* (as crashpad does)'; App = $ps; Cmd = "powershell.exe -NoProfile -NonInteractive -Command `"try { `$s = New-Object IO.Pipes.NamedPipeServerStream('crashpad_probe_$PID'); `$s.Dispose(); 'PIPE OK' } catch { 'PIPE FAILED: ' + `$_.Exception.Message }`"" },
            @{ N = 'named pipe \\.\pipe\LOCAL\*';            App = $ps; Cmd = "powershell.exe -NoProfile -NonInteractive -Command `"try { `$s = New-Object IO.Pipes.NamedPipeServerStream('LOCAL\crashpad_probe_$PID'); `$s.Dispose(); 'PIPE OK' } catch { 'PIPE FAILED: ' + `$_.Exception.Message }`"" },
            @{ N = 'loopback 127.0.0.1 inside container';    App = $ps; Cmd = "powershell.exe -NoProfile -NonInteractive -Command `"try { `$l = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0); `$l.Start(); `$p = `$l.LocalEndpoint.Port; `$c = New-Object Net.Sockets.TcpClient; `$c.Connect('127.0.0.1', `$p); 'LOOPBACK OK port ' + `$p; `$c.Close(); `$l.Stop() } catch { 'LOOPBACK FAILED: ' + `$_.Exception.Message }`"" },
            @{ N = 'internet https://max.ru (HEAD)';         App = $curl; Cmd = 'curl.exe -sS -I -m 10 https://max.ru' }
        )
        $i = 0
        foreach ($p in $probes) {
            $i++
            if (-not (Test-Path -LiteralPath $p.App)) { Log "PROBE $i [$($p.N)]: $($p.App) not found, skipped"; continue }
            $out = [string](Join-Path $temp ("probe_{0:D2}.txt" -f $i))
            $h = [IntPtr]::Zero; $le = 0
            $procId = [AppContainerLauncher]::Start([string]$p.App, [string]$p.Cmd, [string]$appDir, [string]$ContainerName, $caps, $envOverride, $out, $true, [ref]$h, [ref]$le)
            if ($procId -eq 0) {
                Log ("PROBE {0} [{1}]: CreateProcessW FAILED GetLastError={2} ({3})" -f $i, $p.N, $le, (New-Object ComponentModel.Win32Exception($le)).Message)
                continue
            }
            $code = [uint32]0
            $alive = [AppContainerLauncher]::AliveAfter($h, 30000, [ref]$code)
            if ($alive) { [AppContainerLauncher]::Kill($h); $codeText = 'TIMEOUT (killed after 30 s)' } else { $codeText = ('exit 0x{0:X8} ({0})' -f $code) }
            [void][AppContainerLauncher]::CloseHandle($h)
            Log ("PROBE {0} [{1}]: {2}" -f $i, $p.N, $codeText)
            Log ("    cmd: " + $p.Cmd)
            foreach ($l in (Read-Tail $out 15)) { if ($l.Trim()) { Log ("    | " + $l.TrimEnd()) } }
            Remove-Item -LiteralPath $out -ErrorAction SilentlyContinue
        }
        Remove-Item -Path 'HKCU:\Software\MAXIsolatedProbe' -Recurse -ErrorAction SilentlyContinue
        Log "Probe finished. Max was not started."
    }
    else {
        # ---------------------------------------------------------------- start Max
        $stdout = [string](Join-Path $temp 'max_stdout.log')
        $cmdLine = '"' + $exe + '"'
        Log "CreateProcessW: app=$exe cmdline=$cmdLine cwd=$appDir stdout+stderr -> $stdout"
        $hProc = [IntPtr]::Zero; $lastErr = 0
        $startTime = Get-Date
        $procId = [AppContainerLauncher]::Start([string]$exe, [string]$cmdLine, [string]$appDir, [string]$ContainerName, $caps, $envOverride, $stdout, $false, [ref]$hProc, [ref]$lastErr)
        if ($procId -eq 0) {
            $msg = (New-Object System.ComponentModel.Win32Exception($lastErr)).Message
            throw ("CreateProcessW failed, GetLastError={0} (0x{0:X8}): {1}" -f $lastErr, $msg)
        }
        Log "CreateProcessW OK, PID $procId (GetLastError=$lastErr)"

        $code = [uint32]0
        $alive = [AppContainerLauncher]::AliveAfter($hProc, 5000, [ref]$code)
        [void][AppContainerLauncher]::CloseHandle($hProc)
        if ($alive) {
            Log "After 5 s max.exe (PID $procId) is still running."
            foreach ($k in @(Get-CimInstance Win32_Process -Filter "ParentProcessId=$procId" -ErrorAction SilentlyContinue)) { Log ("  child: PID {0} {1}" -f $k.ProcessId, $k.Name) }
        } else {
            $hex = '0x{0:X8}' -f $code
            $meaning = $known[$hex]; if (-not $meaning) { $meaning = 'unknown code' }
            Log ("max.exe EXITED within 5 s. Exit code {0} ({1}): {2}" -f $hex, $code, $meaning)
            $exitAll = 3
        }

        Log "---- max.exe stdout/stderr (last 200 lines of $stdout)"
        foreach ($l in (Read-Tail $stdout 200)) { Log ("    | " + $l.TrimEnd()) }

        if (-not $alive) {
            Start-Sleep -Seconds 2
            $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; StartTime = $startTime.AddSeconds(-5) } -ErrorAction SilentlyContinue |
                    Where-Object { ($_.ProviderName -in 'Application Error', 'Windows Error Reporting', 'Application Hang', 'SideBySide') -or ($_.Message -match 'max(-service)?\.exe|crashpad') })
            if ($ev.Count -eq 0) { Log "No Application events since start." }
            foreach ($e in $ev) {
                Log ("EVENT {0:HH:mm:ss} {1} id={2} level={3}" -f $e.TimeCreated, $e.ProviderName, $e.Id, $e.LevelDisplayName)
                foreach ($l in ($e.Message -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 20)) { Log ("    " + $l.Trim()) }
            }
            # Windows Error Reporting report (readable without admin in most cases)
            foreach ($root in 'C:\ProgramData\Microsoft\Windows\WER\ReportArchive', 'C:\ProgramData\Microsoft\Windows\WER\ReportQueue', (Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\WER\ReportArchive')) {
                $w = Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'max\.exe' -and $_.LastWriteTime -gt $startTime.AddSeconds(-5) } | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                if ($w) {
                    $wer = Join-Path $w.FullName 'Report.wer'
                    Log "WER report: $wer"
                    try {
                        $txt = [IO.File]::ReadAllText($wer, [Text.Encoding]::Unicode) -split "`r?`n"
                        foreach ($l in ($txt | Where-Object { $_ -match '^(Sig\[\d+\]\.Value|DynamicSig\[\d+\]\.Value|AppPath|NsAppName)' })) { Log ("    " + $l) }
                        $mods = @($txt | Where-Object { $_ -match '^LoadedModule\[' })
                        Log ("    loaded modules: {0}; last 5:" -f $mods.Count)
                        foreach ($l in ($mods | Select-Object -Last 5)) { Log ("      " + $l) }
                    } catch { Log "    cannot read: $($_.Exception.Message)" }
                }
            }
        }
    }

    # Max's own logs / dumps (recent)
    $recent = (Get-Date).AddMinutes(-10)
    $files = @(foreach ($d in $DataRoot, $oneLocal, $oneRoaming, $appDir) {
        Get-ChildItem -LiteralPath $d -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -gt $recent -and $_.Extension -in '.log', '.txt', '.dmp', '.json' -and $_.FullName -ne $logPath }
    })
    if ($files.Count -eq 0) { Log "No recent Max log/dump files in $DataRoot, $oneLocal, $oneRoaming, $appDir" }
    foreach ($f in $files | Select-Object -First 20) {
        Log ("Max file: {0} ({1} B, {2:HH:mm:ss})" -f $f.FullName, $f.Length, $f.LastWriteTime)
        if ($f.Extension -in '.log', '.txt' -and $f.Name -notmatch '^max_stdout') {
            foreach ($l in (Read-Tail $f.FullName 100)) { if ($l.Trim()) { Log ("    | " + $l.TrimEnd()) } }
        }
    }
}
catch {
    $exitAll = 1
    Log ("ERROR: " + $_.Exception.Message)
    Log ("  at: " + ($_.InvocationInfo.PositionMessage -replace "`r?`n", ' '))
}
finally {
    Log "Log file: $logPath"
    if (-not $FromCmd) { Read-Host 'Press Enter to close' | Out-Null }
}
exit $exitAll
