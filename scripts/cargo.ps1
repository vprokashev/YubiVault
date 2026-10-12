param([Parameter(ValueFromRemainingArguments = $true)][string[]]$CargoArguments)
$ErrorActionPreference = 'Stop'

# Keep linker/SDK selection local to this process; do not change machine settings.
$msvcRoots = @('C:\Program Files (x86)\Microsoft Visual Studio', 'C:\Program Files\Microsoft Visual Studio')
$msvcLinker = $msvcRoots | Where-Object { Test-Path -LiteralPath $_ } | ForEach-Object {
    Get-ChildItem -LiteralPath $_ -Filter link.exe -File -Recurse -ErrorAction SilentlyContinue
} | Where-Object { $_.FullName -match 'Hostx64\\x64\\link.exe$' } | Sort-Object FullName -Descending | Select-Object -First 1
if (-not $msvcLinker) { throw 'Install Visual Studio Build Tools with Desktop development with C++.' }
$msvcVersionRoot = $msvcLinker.Directory.Parent.Parent.Parent.FullName
$sdkRoot = 'C:\Program Files (x86)\Windows Kits\10'
$sdkVersion = Get-ChildItem -LiteralPath (Join-Path $sdkRoot 'Lib') -Directory | Where-Object {
    Test-Path -LiteralPath (Join-Path $_.FullName 'um\x64\kernel32.lib')
} | Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1
if (-not $sdkVersion) { throw 'Install the Windows SDK x64 development libraries.' }
$env:CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER = $msvcLinker.FullName
$env:PATH = $msvcLinker.Directory.FullName + ';' + $env:PATH
$env:LIB = (Join-Path $msvcVersionRoot 'lib\x64') + ';' + (Join-Path $sdkVersion.FullName 'ucrt\x64') + ';' + (Join-Path $sdkVersion.FullName 'um\x64')
$sdkInclude = Join-Path (Join-Path $sdkRoot 'Include') $sdkVersion.Name
$env:INCLUDE = (Join-Path $msvcVersionRoot 'include') + ';' + (Join-Path $sdkInclude 'ucrt') + ';' + (Join-Path $sdkInclude 'shared') + ';' + (Join-Path $sdkInclude 'um')
& cargo @CargoArguments
exit $LASTEXITCODE

