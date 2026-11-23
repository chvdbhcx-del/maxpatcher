<#
.SYNOPSIS
  Undoes what Launch-MAX-Isolated.ps1 set up: removes the container's rights (ACL) from the folders
  and deletes the AppContainer profile "MAX.Isolated". Only built-in PowerShell 5.1 / .NET.

.PARAMETER DeleteData
  Also delete %LOCALAPPDATA%\MAXIsolated (temp/env folders of the container).
  %LOCALAPPDATA%\ONEME and %APPDATA%\ONEME (Max's own data, used by the normal Max too) are never deleted.

.NOTES
  Run it from the MAX_patched folder (the script folder is treated as the program folder).
  Quit the isolated Max first.
#>
[CmdletBinding()]
param(
    [string]$ContainerName = 'MAX.Isolated',
    [string]$DataRoot = (Join-Path $env:LOCALAPPDATA 'MAXIsolated'),
    [switch]$DeleteData
)
$ErrorActionPreference = 'Stop'

$cs = @'
using System; using System.Runtime.InteropServices; using System.ComponentModel;
public static class AppContainerRemover {
  [DllImport("userenv.dll", CharSet = CharSet.Unicode)] static extern int DeriveAppContainerSidFromAppContainerName(string name, out IntPtr sid);
  [DllImport("userenv.dll", CharSet = CharSet.Unicode)] static extern int DeleteAppContainerProfile(string name);
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool ConvertSidToStringSid(IntPtr sid, out IntPtr str);
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr h);
  public static string Sid(string name) {
    IntPtr sid; int hr = DeriveAppContainerSidFromAppContainerName(name, out sid);
    if (hr != 0) throw new Exception("DeriveAppContainerSidFromAppContainerName HRESULT 0x" + hr.ToString("X8"));
    IntPtr p; if (!ConvertSidToStringSid(sid, out p)) throw new Win32Exception();
    string s = Marshal.PtrToStringUni(p); LocalFree(p); return s;
  }
  public static int Delete(string name) { return DeleteAppContainerProfile(name); }
}
'@
if (-not ('AppContainerRemover' -as [type])) { Add-Type -TypeDefinition $cs }

$running = @(Get-CimInstance Win32_Process -Filter "Name='max.exe' OR Name='max-service.exe'" -ErrorAction SilentlyContinue)
if ($running.Count -gt 0) { Write-Warning "max.exe / max-service.exe is running. Quit Max first if it is the isolated one." }

# the SID is derived from the name, so it is known even if the profile was already deleted
$sid = [string][AppContainerRemover]::Sid([string]$ContainerName)
Write-Host "AppContainer '$ContainerName' SID: $sid"

$folders = @(
    [string]$PSScriptRoot,
    [string]$DataRoot,
    [string](Join-Path $env:LOCALAPPDATA 'ONEME'),
    [string](Join-Path $env:APPDATA 'ONEME'),
    [string](Join-Path $env:LOCALAPPDATA 'Communication Platform LLC'),   # used by early versions of the launcher
    [string](Join-Path $env:APPDATA 'Communication Platform LLC')
)
foreach ($f in $folders) {
    if (-not (Test-Path -LiteralPath $f)) { continue }
    $out = & icacls.exe $f /remove "*$sid" /T /C /Q 2>&1
    Write-Host ("  ACL removed ({0}): {1}" -f $(if ($LASTEXITCODE -eq 0) { 'ok' } else { "code $LASTEXITCODE" }), $f)
}

$hr = [AppContainerRemover]::Delete([string]$ContainerName)
if ($hr -eq 0) { Write-Host "AppContainer profile '$ContainerName' deleted." }
else { Write-Host ("DeleteAppContainerProfile returned 0x{0:X8} (profile may not exist)." -f $hr) }

if ($DeleteData -and (Test-Path -LiteralPath $DataRoot)) {
    Remove-Item -LiteralPath $DataRoot -Recurse -Force
    Write-Host "Deleted $DataRoot"
}
Write-Host "Done. Max's own data in %LOCALAPPDATA%\ONEME and %APPDATA%\ONEME was kept."
