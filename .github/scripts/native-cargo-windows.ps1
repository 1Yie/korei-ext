[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [AllowEmptyString()]
    [string[]] $CargoArguments
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$cargo = $null
$cargoStarted = $false
$result = 1

try {
    if (-not [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [System.Runtime.InteropServices.OSPlatform]::Windows
    )) {
        throw 'Windows is required; no environment changes were made.'
    }
    if ($CargoArguments.Count -eq 0) {
        throw 'Usage: native-cargo-windows.ps1 -CargoArguments <string[]>'
    }

    $vswhere = Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) `
        'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) {
        throw 'The runner must already provide vswhere.exe.'
    }
    $installations = @(& $vswhere -latest -products '*' `
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        -property installationPath 2>$null)
    $vswhereStatus = $LASTEXITCODE
    if ($vswhereStatus -ne 0 -or $installations.Count -ne 1) {
        throw "Could not locate the installed MSVC tools (vswhere exit $vswhereStatus)."
    }
    $vsDevCmd = Join-Path ($installations[0].Trim()) 'Common7\Tools\VsDevCmd.bat'
    if (-not (Test-Path -LiteralPath $vsDevCmd -PathType Leaf)) {
        throw 'The installed Visual Studio instance must provide VsDevCmd.bat.'
    }
    if ($vsDevCmd -match '["&|<>^%!\r\n]') {
        throw 'The VsDevCmd path contains unsupported cmd.exe metacharacters.'
    }

    $setupInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $setupInfo.FileName = Join-Path ([Environment]::SystemDirectory) 'cmd.exe'
    $setupInfo.WorkingDirectory = (Get-Location).ProviderPath
    $setupInfo.UseShellExecute = $false
    $setupInfo.RedirectStandardOutput = $true
    $setupInfo.RedirectStandardError = $true
    # cmd.exe parses the fixed batch command with its own quoting grammar.
    $setupInfo.Arguments = '/d /s /v:off /c "call "{0}" -no_logo -arch=x64 -host_arch=x64 >nul && set"' -f $vsDevCmd
    $setup = [System.Diagnostics.Process]::new()
    $setupStarted = $false
    try {
        $setup.StartInfo = $setupInfo
        if (-not $setup.Start()) {
            throw 'Could not start VsDevCmd.'
        }
        $setupStarted = $true
        $environmentOutput = $setup.StandardOutput.ReadToEndAsync()
        $environmentErrors = $setup.StandardError.ReadToEndAsync()
        $setup.WaitForExit()
        $setupStatus = $setup.ExitCode
        $environmentText = $environmentOutput.GetAwaiter().GetResult()
        $null = $environmentErrors.GetAwaiter().GetResult()
        if ($setupStatus -ne 0) {
            throw "VsDevCmd failed with exit code $setupStatus."
        }
    }
    finally {
        if ($setupStarted -and -not $setup.HasExited) {
            $setup.Kill($true)
            $setup.WaitForExit()
        }
        $setup.Dispose()
    }

    $nativeEnvironment = @{}
    foreach ($line in ($environmentText -split '\r?\n')) {
        $separator = $line.IndexOf('=')
        if ($separator -gt 0) {
            $nativeEnvironment[$line.Substring(0, $separator)] = $line.Substring($separator + 1)
        }
    }
    foreach ($name in @('PATH', 'INCLUDE', 'LIB', 'VCToolsInstallDir',
        'WindowsSdkDir', 'WindowsSDKVersion')) {
        if (-not $nativeEnvironment.ContainsKey($name) -or
            [string]::IsNullOrWhiteSpace($nativeEnvironment[$name])) {
            throw "VsDevCmd did not supply the required $name entry."
        }
    }

    $cl = Join-Path ($nativeEnvironment['VCToolsInstallDir']) 'bin\Hostx64\x64\cl.exe'
    $lib = Join-Path ($nativeEnvironment['VCToolsInstallDir']) 'bin\Hostx64\x64\lib.exe'
    $sdkVersion = $nativeEnvironment['WindowsSDKVersion'].TrimEnd('\')
    $sdkInclude = Join-Path ($nativeEnvironment['WindowsSdkDir']) "Include\$sdkVersion"
    $sdkLib = Join-Path ($nativeEnvironment['WindowsSdkDir']) "Lib\$sdkVersion"
    foreach ($path in @($cl, $lib,
        (Join-Path $sdkInclude 'ucrt\stdio.h'),
        (Join-Path $sdkInclude 'shared\sdkddkver.h'),
        (Join-Path $sdkInclude 'um\Windows.h'),
        (Join-Path $sdkLib 'ucrt\x64\ucrt.lib'),
        (Join-Path $sdkLib 'um\x64\kernel32.lib'))) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw 'The runner must already provide the complete x64 MSVC toolchain and Windows SDK.'
        }
    }
    foreach ($entry in $nativeEnvironment.GetEnumerator()) {
        [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, 'Process')
    }
    foreach ($name in @('CC', 'CXX', 'HOST_CC', 'HOST_CXX',
        'CC_x86_64_pc_windows_msvc', 'CXX_x86_64_pc_windows_msvc',
        'CC_x86_64-pc-windows-msvc', 'CXX_x86_64-pc-windows-msvc')) {
        [Environment]::SetEnvironmentVariable($name, $cl, 'Process')
    }
    foreach ($name in @('AR', 'HOST_AR', 'AR_x86_64_pc_windows_msvc',
        'AR_x86_64-pc-windows-msvc')) {
        [Environment]::SetEnvironmentVariable($name, $lib, 'Process')
    }
    $env:CARGO_BUILD_JOBS = '1'
    $env:RUST_TEST_THREADS = '1'

    $cargoPath = (Get-Command cargo.exe -CommandType Application -ErrorAction Stop).Source
    $cargoInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $cargoInfo.FileName = $cargoPath
    $cargoInfo.WorkingDirectory = (Get-Location).ProviderPath
    $cargoInfo.UseShellExecute = $false
    foreach ($argument in $CargoArguments) {
        $cargoInfo.ArgumentList.Add($argument)
    }
    $cargo = [System.Diagnostics.Process]::new()
    $cargo.StartInfo = $cargoInfo
    if (-not $cargo.Start()) {
        throw 'Could not start cargo.exe.'
    }
    $cargoStarted = $true
    try {
        $cargo.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::BelowNormal
    }
    catch {
        $cargo.Refresh()
        if (-not $cargo.HasExited) {
            throw 'Could not set Cargo priority to BelowNormal.'
        }
    }
    $cargo.WaitForExit()
    $result = $cargo.ExitCode
}
catch {
    [Console]::Error.WriteLine("native-cargo-windows: $($_.Exception.Message)")
    $result = 1
}
finally {
    if ($cargoStarted -and -not $cargo.HasExited) {
        $cargo.Kill($true)
        $cargo.WaitForExit()
    }
    if ($null -ne $cargo) {
        $cargo.Dispose()
    }
}
exit $result
