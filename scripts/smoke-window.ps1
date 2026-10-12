param([string]$Executable = (Join-Path $PSScriptRoot '..\target\release\yubivault.exe'))
$ErrorActionPreference = 'Stop'

# Launches only the locked screen; never opens a vault or requests a PIN.
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class VaultWindowCheck {
    public delegate bool Callback(IntPtr hwnd, IntPtr state);
    [DllImport("user32.dll")] static extern bool EnumWindows(Callback callback, IntPtr state);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint process);
    [DllImport("user32.dll")] public static extern bool GetWindowDisplayAffinity(IntPtr hwnd, out uint affinity);
    [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr hwnd, uint message, IntPtr wparam, IntPtr lparam);
    public static IntPtr Find(uint process) {
        IntPtr found = IntPtr.Zero;
        EnumWindows((hwnd, state) => {
            uint owner;
            GetWindowThreadProcessId(hwnd, out owner);
            if (owner == process) { found = hwnd; return false; }
            return true;
        }, IntPtr.Zero);
        return found;
    }
}
'@
$application = Start-Process -FilePath (Resolve-Path -LiteralPath $Executable).Path -WindowStyle Hidden -PassThru
try {
    $started = [DateTime]::UtcNow
    $window = [IntPtr]::Zero
    $affinity = [uint32]0
    while (([DateTime]::UtcNow - $started).TotalSeconds -lt 15) {
        $application.Refresh()
        if ($application.HasExited) { throw "Application exited during startup: $($application.ExitCode)" }
        $window = [VaultWindowCheck]::Find([uint32]$application.Id)
        if ($window -ne [IntPtr]::Zero -and [VaultWindowCheck]::GetWindowDisplayAffinity($window, [ref]$affinity) -and $affinity -eq 17) { break }
        Start-Sleep -Milliseconds 100
    }
    if ($window -eq [IntPtr]::Zero -or $affinity -ne 17) { throw 'Protected native window did not become ready.' }
    Write-Output 'Native application window: WDA_EXCLUDEFROMCAPTURE confirmed.'
    [void][VaultWindowCheck]::PostMessageW($window, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)
    if (-not $application.WaitForExit(5000)) { throw 'Locked application did not close normally.' }
    if ($application.ExitCode -ne 0) { throw "Application exit code: $($application.ExitCode)" }
    Write-Output 'Locked-screen startup and normal shutdown passed.'
} finally {
    $application.Refresh()
    if (-not $application.HasExited) { Stop-Process -Id $application.Id }
    $application.Dispose()
}
