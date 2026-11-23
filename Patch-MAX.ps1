<#
.SYNOPSIS
  Makes a patched COPY of the MAX desktop messenger in which the file/folder pickers,
  "Save as" dialogs and drag-and-drop of files into a chat are disabled.
  The original installation / MSI is never modified.

.PARAMETER Source
  Folder with MAX (the one containing max.exe), or a path to MAX.msi.
  If omitted, the installed MAX is searched for (Uninstall registry, App Paths, typical folders).

.PARAMETER Dest
  Where to put the patched copy. Default: .\MAX_patched next to this script. Must not exist or be empty.

.NOTES
  Only built-in PowerShell 5.1 / .NET.
  Also patches the crashpad pipe name in both tracernative.dll (needed to run Max in an AppContainer)
  and copies Launch-MAX-Isolated.ps1, Start_MAX_isolated.cmd, Probe_MAX_isolated.cmd, Remove-MAX-Isolated.ps1
  (they must lie next to this script) into the copy.
  Start the copy with Start_MAX_isolated.cmd (isolated, recommended) or Start_MAX_patched.cmd (not isolated).
  Both set QML_DISABLE_DISK_CACHE=1: without it Qt uses the QML precompiled into max.exe
  and the patched QML sources are ignored.
#>
[CmdletBinding()]
param(
    [string]$Source,
    [string]$Dest
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------- C# helper
$cs = @'
using System; using System.IO; using System.IO.Compression; using System.Text;
using System.Text.RegularExpressions; using System.Collections.Generic;

public class MaxRepl { public string Find; public string Repl; public bool IsRegex; public int Count; }
public class MaxPatch { public int Id; public string Name; public string Exe; public string[] Markers; public MaxRepl[] Repls; }
public class MaxResult { public int Id; public string Name; public string Exe; public string Status; public string Detail; }

public static class MaxPatcher {
  static readonly Encoding L1 = Encoding.GetEncoding(28591);
  static uint BE(byte[] b, long p) { return ((uint)b[p] << 24) | ((uint)b[p+1] << 16) | ((uint)b[p+2] << 8) | b[p+3]; }
  static void WBE(byte[] b, long p, uint v) { b[p]=(byte)(v>>24); b[p+1]=(byte)(v>>16); b[p+2]=(byte)(v>>8); b[p+3]=(byte)v; }
  static uint Adler(byte[] d) { uint a = 1, s = 0; foreach (byte x in d) { a = (a + x) % 65521; s = (s + a) % 65521; } return (s << 16) | a; }

  static byte[] Inflate(byte[] b, long k, int zlen) {
    using (var ms = new MemoryStream(b, (int)k + 2, zlen - 2))
    using (var ds = new DeflateStream(ms, CompressionMode.Decompress))
    using (var o = new MemoryStream()) { ds.CopyTo(o); return o.ToArray(); }
  }
  static byte[] Zlib(byte[] d) {
    using (var o = new MemoryStream()) {
      o.WriteByte(0x78); o.WriteByte(0xDA);
      using (var ds = new DeflateStream(o, CompressionLevel.Optimal, true)) ds.Write(d, 0, d.Length);
      uint a = Adler(d); o.WriteByte((byte)(a>>24)); o.WriteByte((byte)(a>>16)); o.WriteByte((byte)(a>>8)); o.WriteByte((byte)a);
      return o.ToArray();
    }
  }

  // Block = one Qt rcc resource. Compressed: [S BE][U BE][zlib...], S = 4 + zlib length, data offset = k (zlib start).
  // Plain: [L BE][text], data offset = text start.
  class Block { public bool Compressed; public long Data; public int ZLen; public string Text; }

  static List<Block> Compressed(byte[] b) {
    var r = new List<Block>();
    for (long k = 8; k < b.Length - 6; k++) {
      if (b[k] != 0x78) continue; byte f = b[k+1]; if (f != 0x9C && f != 0xDA && f != 0x01 && f != 0x5E) continue;
      uint U = BE(b, k-4), S = BE(b, k-8);
      if (U == 0 || U > 20000000 || S < 7 || k - 4 + S > b.Length) continue;
      try { var raw = Inflate(b, k, (int)S - 4); if (raw.Length != U) continue;
        r.Add(new Block { Compressed = true, Data = k, ZLen = (int)S - 4, Text = L1.GetString(raw) }); k += S - 5; } catch { }
    }
    return r;
  }

  // Find uncompressed rcc blocks that contain all markers: locate first marker, walk back to an "import"/"pragma"
  // start whose 4-byte BE length prefix covers the marker and whose content has no NUL bytes.
  static List<Block> Plain(byte[] b, string[] markers) {
    var r = new List<Block>(); string all = L1.GetString(b); int pos = 0;
    while ((pos = all.IndexOf(markers[0], pos, StringComparison.Ordinal)) >= 0) {
      int found = -1;
      for (int q = pos; q > Math.Max(4, pos - 200000); q--) {
        if (!(all.Length > q + 7 && (string.CompareOrdinal(all, q, "import ", 0, 7) == 0 || string.CompareOrdinal(all, q, "pragma ", 0, 7) == 0))) continue;
        uint L = BE(b, q - 4); if (L == 0 || L > 2000000 || q + L < pos + markers[0].Length || q + L > b.Length) continue;
        if (all.IndexOf('\0', q, (int)L) >= 0) continue;
        found = q; break;
      }
      if (found >= 0) {
        uint L = BE(b, found - 4); string t = all.Substring(found, (int)L); bool ok = true;
        foreach (var m in markers) if (t.IndexOf(m, StringComparison.Ordinal) < 0) { ok = false; break; }
        if (ok) r.Add(new Block { Compressed = false, Data = found, Text = t });
        pos = found + (int)L;
      } else pos += markers[0].Length;
    }
    return r;
  }

  static int CountOf(string t, MaxRepl x) {
    if (x.IsRegex) return Regex.Matches(t, x.Find).Count;
    int n = 0, i = 0; while ((i = t.IndexOf(x.Find, i, StringComparison.Ordinal)) >= 0) { n++; i += x.Find.Length; } return n;
  }

  public static MaxResult[] Apply(string exePath, MaxPatch[] patches, out bool changed) {
    var res = new List<MaxResult>(); changed = false;
    byte[] b = File.ReadAllBytes(exePath);
    List<Block> comp = null;
    foreach (var p in patches) {
      var R = new MaxResult { Id = p.Id, Name = p.Name, Exe = p.Exe };
      if (comp == null) comp = Compressed(b);
      var hits = new List<Block>();
      foreach (var bl in comp) { bool ok = true; foreach (var m in p.Markers) if (bl.Text.IndexOf(m, StringComparison.Ordinal) < 0) { ok = false; break; } if (ok) hits.Add(bl); }
      hits.AddRange(Plain(b, p.Markers));
      if (hits.Count == 0) { R.Status = "NOT FOUND"; R.Detail = "no resource block with markers: " + string.Join(" | ", p.Markers); res.Add(R); continue; }
      var det = new List<string>(); int applied = 0, already = 0, failed = 0;
      foreach (var bl in hits) {
        string t = bl.Text; string err = null; bool isAlready = true;
        foreach (var x in p.Repls) { int n = CountOf(t, x); if (n != 0) isAlready = false; }
        if (isAlready) { already++; det.Add((bl.Compressed ? "zlib" : "plain") + " @0x" + bl.Data.ToString("X") + ": already patched (pattern absent)"); continue; }
        foreach (var x in p.Repls) {
          int n = CountOf(t, x); if (n != x.Count) { err = "pattern found " + n + "x, expected " + x.Count + ": " + x.Find; break; }
          if (!bl.Compressed) {
            // same-length edit: pad shorter replacement with spaces, refuse longer
            string nt = x.IsRegex ? Regex.Replace(t, x.Find, m => { string rr = m.Result(x.Repl); return rr.Length <= m.Length ? rr.PadRight(m.Length) : null; })
                                  : t.Replace(x.Find, x.Repl.Length <= x.Find.Length ? x.Repl.PadRight(x.Find.Length) : null);
            if (nt == null || nt.Length != t.Length) { err = "replacement longer than original in uncompressed block"; break; }
            t = nt;
          } else t = x.IsRegex ? Regex.Replace(t, x.Find, x.Repl) : t.Replace(x.Find, x.Repl);
        }
        if (err == null) {
          if (!bl.Compressed) {
            var nb = L1.GetBytes(t); Buffer.BlockCopy(nb, 0, b, (int)bl.Data, nb.Length);
            det.Add("plain @0x" + bl.Data.ToString("X") + " (" + nb.Length + " B, same length)");
          } else {
            var nd = L1.GetBytes(t); var z = Zlib(nd);
            if (z.Length > bl.ZLen) err = "recompressed block bigger than original (" + (z.Length + 4) + " > " + (bl.ZLen + 4) + " B)";
            else {
              var save = new byte[bl.ZLen + 8]; Buffer.BlockCopy(b, (int)bl.Data - 8, save, 0, save.Length);
              WBE(b, bl.Data - 8, (uint)(z.Length + 4)); WBE(b, bl.Data - 4, (uint)nd.Length);
              Buffer.BlockCopy(z, 0, b, (int)bl.Data, z.Length);
              for (long i = bl.Data + z.Length; i < bl.Data + bl.ZLen; i++) b[i] = 0;
              string chk = null; try { chk = L1.GetString(Inflate(b, bl.Data, z.Length)); } catch { }
              if (chk != t) { Buffer.BlockCopy(save, 0, b, (int)bl.Data - 8, save.Length); err = "verification after repack failed, block restored"; }
              else det.Add("zlib @0x" + (bl.Data - 8).ToString("X") + " (" + (bl.ZLen + 4) + " -> " + (z.Length + 4) + " B, zero-padded)");
            }
          }
        }
        if (err != null) { failed++; det.Add((bl.Compressed ? "zlib" : "plain") + " @0x" + bl.Data.ToString("X") + ": SKIPPED - " + err); }
        else { applied++; changed = true; }
      }
      R.Status = failed > 0 ? (applied > 0 ? "PARTIAL" : "FAILED") : (applied > 0 ? "APPLIED" : "ALREADY PATCHED");
      R.Detail = string.Join("; ", det); res.Add(R);
      if (applied > 0) comp = null; // offsets unchanged, but texts changed: rescan for next patch
    }
    if (changed) File.WriteAllBytes(exePath, b);
    return res.ToArray();
  }
}
'@
if (-not ('MaxPatcher' -as [type])) { Add-Type -TypeDefinition $cs }

function New-Repl([string]$find, [string]$repl, [switch]$Regex, [int]$Count = 1) {
    $r = New-Object MaxRepl; $r.Find = $find; $r.Repl = $repl; $r.IsRegex = [bool]$Regex; $r.Count = $Count; $r
}
function New-Patch([int]$id, [string]$name, [string]$exe, [string[]]$markers, [object[]]$repls) {
    $p = New-Object MaxPatch; $p.Id = $id; $p.Name = $name; $p.Exe = $exe; $p.Markers = $markers; $p.Repls = [MaxRepl[]]$repls; $p
}

# ---------------------------------------------------------------- the 8 patches
$noOpen = New-Repl 'dialogInstance.open();' ''
$patches = @(
    (New-Patch 1 'Attach file / photo / video dialog (AttachmentAddDialog)' 'max.exe' `
        @('FileDialog {', 'signal fileUploadSelected', '"AttachmentAddDialog", "Choose a file"') `
        @(New-Repl 'Component.onCompleted: root.open()' 'Component.onCompleted: destroy()')),
    (New-Patch 2 'Avatar image picker (AvatarCreator)' 'max.exe' `
        @('FileDialog {', '"AvatarCreator", "Choose an image"') `
        @(New-Repl 'Component.onCompleted: root.open()' 'Component.onCompleted: {}')),
    (New-Patch 3 'Download folder picker (SettingsDownloadPathButton)' 'max.exe' `
        @('FolderDialog {', 'changeDownloadPath(selectedFolder)') `
        @(New-Repl '[ \t]{2}dialogInstance\.open\(\);' 'dialogInstance.destroy()' -Regex)),
    (New-Patch 4 'Cover image/video picker' 'max.exe' `
        @('FileDialog {', 'onAddCoverSelected(selectedFile)') `
        @(New-Repl '(\r?\n)[ \t]*Component\.onCompleted: open\(\)\r?\n(?:\r?\n)?' '$1' -Regex)),
    (New-Patch 5 '"Save as" for files (MessageMenu)' 'max.exe' `
        @('FileDialog.SaveFile', '"MessageMenu", "Save as"') @($noOpen)),
    (New-Patch 6 '"Save as" for photos (media downloader)' 'max.exe' `
        @('FileDialog.SaveFile', 'downloadImp(downloadUrl, dynamicDialog.selectedFile)') @($noOpen)),
    (New-Patch 7 'Drag-and-drop of files into chat (HistoryDropArea)' 'max.exe' `
        @('DropArea {', 'historyDragAndDropDependency', 'signal filesDropped') `
        @((New-Repl 'drag\.accepted = root\.attachMsgSendEnabled && context\.tryAccept\(drag\.urls\);' 'drag.accepted = false;' -Regex),
          (New-Repl 'drag\.accepted = root\.attachMsgSendEnabled && context\.tryDrop\(drag\.urls\);' 'drag.accepted = false;' -Regex))),
    (New-Patch 8 '"Save as" for photos (copy in max-service)' 'max-service\max-service.exe' `
        @('FileDialog.SaveFile', 'downloadImp(downloadUrl, dynamicDialog.selectedFile)') @($noOpen))
)

# ---------------------------------------------------------------- locate source
function Find-MaxDir([string]$dir) {
    if (Test-Path -LiteralPath (Join-Path $dir 'max.exe')) { return (Resolve-Path -LiteralPath $dir).Path }
    $hit = Get-ChildItem -LiteralPath $dir -Recurse -Filter max.exe -File -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($hit) { return $hit.DirectoryName }
    return $null
}

$tempExtract = $null
if ($Source) {
    if (-not (Test-Path -LiteralPath $Source)) { throw "Source not found: $Source" }
    $Source = (Resolve-Path -LiteralPath $Source).Path
    if ((Get-Item -LiteralPath $Source).PSIsContainer) {
        $srcDir = Find-MaxDir $Source
    } elseif ($Source -match '\.msi$') {
        $tempExtract = Join-Path ([IO.Path]::GetTempPath()) ('MAX_admin_' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory $tempExtract | Out-Null
        Write-Host "Extracting MSI (administrative install, nothing is installed) to $tempExtract ..."
        $p = Start-Process msiexec.exe -ArgumentList "/a `"$Source`" /qn TARGETDIR=`"$tempExtract`"" -Wait -PassThru
        if ($p.ExitCode -ne 0) { throw "msiexec /a failed with exit code $($p.ExitCode)" }
        $srcDir = Find-MaxDir $tempExtract
    } else { throw "Source must be a folder with max.exe or a .msi file" }
} else {
    $cands = @()
    foreach ($k in 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
                   'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
                   'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') {
        Get-ItemProperty $k -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match '^MAX\b' -and $_.InstallLocation } |
            ForEach-Object { $cands += $_.InstallLocation }
    }
    foreach ($k in 'HKCU:\Software\Microsoft\Windows\CurrentVersion\App Paths\max.exe',
                   'HKLM:\Software\Microsoft\Windows\CurrentVersion\App Paths\max.exe') {
        $v = Get-ItemProperty $k -ErrorAction SilentlyContinue
        if ($v.Path) { $cands += $v.Path }
        if ($v.'(default)') { $cands += (Split-Path ($v.'(default)'.Trim('"'))) }
    }
    $v = Get-ItemProperty 'Registry::HKEY_CLASSES_ROOT\max' -ErrorAction SilentlyContinue
    if ($v.InstallPath) { $cands += $v.InstallPath }
    $cands += @("$env:ProgramFiles\MAX", "${env:ProgramFiles(x86)}\MAX", "$env:LOCALAPPDATA\Programs\MAX", "$env:LOCALAPPDATA\MAX")
    $srcDir = $null
    foreach ($c in $cands) { if ($c -and (Test-Path -LiteralPath (Join-Path $c 'max.exe'))) { $srcDir = (Resolve-Path -LiteralPath $c).Path; break } }
    if (-not $srcDir) { throw "Installed MAX not found. Pass -Source <folder with max.exe> or -Source <path to MAX.msi>." }
}
if (-not $srcDir) { throw "max.exe not found in $Source" }
Write-Host "Source: $srcDir"
$ver = (Get-Item -LiteralPath (Join-Path $srcDir 'max.exe')).VersionInfo.FileVersion
Write-Host "max.exe version: $ver (patches were made for 26.41.1.83827; other versions may not match)"

# ---------------------------------------------------------------- copy
if (-not $Dest) { $Dest = Join-Path $PSScriptRoot 'MAX_patched' }
$Dest = [IO.Path]::GetFullPath($Dest)
if ($Dest.TrimEnd('\') -ieq $srcDir.TrimEnd('\')) { throw "Dest must differ from Source" }
if ((Test-Path -LiteralPath $Dest) -and (Get-ChildItem -LiteralPath $Dest -Force | Select-Object -First 1)) { throw "Dest already exists and is not empty: $Dest" }
Write-Host "Copying to $Dest ..."
robocopy $srcDir $Dest /E /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -ge 8) { throw "robocopy failed with code $LASTEXITCODE" }
if ($tempExtract) { Remove-Item -LiteralPath $tempExtract -Recurse -Force -ErrorAction SilentlyContinue }

# ---------------------------------------------------------------- patch
$results = @()
foreach ($exe in ($patches | ForEach-Object { $_.Exe } | Select-Object -Unique)) {
    $path = Join-Path $Dest $exe
    $set = [MaxPatch[]]@($patches | Where-Object { $_.Exe -eq $exe })
    if (-not (Test-Path -LiteralPath $path)) {
        foreach ($p in $set) { $results += [pscustomobject]@{ Id = $p.Id; Name = $p.Name; Exe = $exe; Status = 'NOT FOUND'; Detail = "$exe missing" } }
        continue
    }
    Write-Host "Patching $exe ..."
    $changed = $false
    $results += [MaxPatcher]::Apply($path, $set, [ref]$changed)
}

# ---------------------------------------------------------------- crashpad pipe name in tracernative.dll
# Max's crash reporter (crashpad inside tracernative.dll) creates \\.\pipe\crashpad_<pid>_<rand>.
# Inside an AppContainer only \\.\pipe\LOCAL\... may be created, otherwise crashpad aborts Max (0x80000003).
# Same-length replacement of the name template; crashpad_handler.exe gets the name from the client.
function Patch-PipeName([int]$id, [string]$rel) {
    $old = '\\.\pipe\crashpad_%lu_'; $new = '\\.\pipe\LOCAL\cp_%lu_'
    $r = [pscustomobject]@{ Id = $id; Name = "crashpad pipe name in $rel"; Exe = $rel; Status = ''; Detail = '' }
    $p = Join-Path $Dest $rel
    if (-not (Test-Path -LiteralPath $p)) { $r.Status = 'NOT FOUND'; $r.Detail = "$rel missing"; return $r }
    $L1 = [Text.Encoding]::GetEncoding(28591)
    $b = [IO.File]::ReadAllBytes($p); $t = $L1.GetString($b)
    $find = { param($s) $list = @(); $i = 0; while (($i = $t.IndexOf($s, $i, [StringComparison]::Ordinal)) -ge 0) { $list += $i; $i++ }; ,$list }
    $o = & $find $old; $n = & $find $new
    if ($o.Count -eq 0 -and $n.Count -ge 1) { $r.Status = 'ALREADY PATCHED'; $r.Detail = ('template already {0} at 0x{1:X}' -f $new, $n[0]); return $r }
    if ($o.Count -ne 1) { $r.Status = $(if ($o.Count -eq 0) { 'NOT FOUND' } else { 'FAILED' }); $r.Detail = "template '$old' found $($o.Count)x (expected 1), file not changed"; return $r }
    $at = $o[0]
    if ($b[$at + $old.Length] -ne 0) { $r.Status = 'FAILED'; $r.Detail = ('no NUL terminator after template at 0x{0:X}, file not changed' -f $at); return $r }
    $bak = "$p.orig"; if (-not (Test-Path -LiteralPath $bak)) { Copy-Item -LiteralPath $p -Destination $bak }
    $nb = $L1.GetBytes($new); [Array]::Copy($nb, 0, $b, $at, $nb.Length)
    [IO.File]::WriteAllBytes($p, $b)
    $chk = [IO.File]::ReadAllBytes($p)
    if ($L1.GetString($chk, $at, $new.Length) -ne $new -or $chk.Length -ne $b.Length) {
        Copy-Item -LiteralPath $bak -Destination $p -Force; $r.Status = 'FAILED'; $r.Detail = 'verification failed, restored from .orig'; return $r
    }
    $r.Status = 'APPLIED'; $r.Detail = ('0x{0:X}: {1} -> {2} (same length, backup {3}.orig)' -f $at, $old, $new, (Split-Path $rel -Leaf))
    return $r
}
Write-Host "Patching tracernative.dll ..."
$results += Patch-PipeName 9  'tracernative.dll'
$results += Patch-PipeName 10 'max-service\tracernative.dll'

# ---------------------------------------------------------------- launchers
$cmd = "@echo off`r`nrem Without this variable Qt uses the QML precompiled into max.exe and ignores the patched QML sources.`r`nset QML_DISABLE_DISK_CACHE=1`r`nstart `"`" `"%~dp0max.exe`" %*`r`n"
[IO.File]::WriteAllText((Join-Path $Dest 'Start_MAX_patched.cmd'), $cmd, [Text.Encoding]::ASCII)

$support = 'Launch-MAX-Isolated.ps1', 'Start_MAX_isolated.cmd', 'Probe_MAX_isolated.cmd', 'Remove-MAX-Isolated.ps1'
$missing = @($support | Where-Object { -not (Test-Path -LiteralPath (Join-Path $PSScriptRoot $_)) })
$lr = [pscustomobject]@{ Id = 11; Name = 'AppContainer launch scripts copied'; Exe = '-'; Status = ''; Detail = '' }
if ($missing.Count -gt 0) { $lr.Status = 'NOT FOUND'; $lr.Detail = "missing next to Patch-MAX.ps1: $($missing -join ', ')" }
else {
    foreach ($s in $support) { Copy-Item -LiteralPath (Join-Path $PSScriptRoot $s) -Destination (Join-Path $Dest $s) -Force }
    $lr.Status = 'APPLIED'; $lr.Detail = ($support -join ', ')
}
$results += $lr

# ---------------------------------------------------------------- report
$total = 11
Write-Host ""
Write-Host "=== Result ==="
$results | Sort-Object Id | Format-Table Id, Status, Name -AutoSize | Out-String -Width 200 | Write-Host
$results | Sort-Object Id | ForEach-Object { Write-Host ("[{0}] {1}: {2}" -f $_.Id, $_.Status, $_.Detail) }
$ok = @($results | Where-Object { $_.Status -in 'APPLIED', 'ALREADY PATCHED' }).Count
Write-Host ""
Write-Host "$ok of $total steps in place. Patched copy: $Dest"
Write-Host "Start Max isolated (quit the normal Max first, also from the tray): $(Join-Path $Dest 'Start_MAX_isolated.cmd')"
Write-Host "Diagnostics: $(Join-Path $Dest 'Probe_MAX_isolated.cmd'), log: $(Join-Path $Dest 'launch.log')"
foreach ($f in 'max.exe', 'max-service\max-service.exe', 'tracernative.dll', 'max-service\tracernative.dll') {
    $fp = Join-Path $Dest $f; if (Test-Path -LiteralPath $fp) { Write-Host ("SHA256 {0}  {1}" -f (Get-FileHash -LiteralPath $fp).Hash, $f) }
}
if ($ok -lt $total) { exit 2 }
exit 0
