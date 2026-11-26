$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$coreDir = Join-Path $root 'gdportal-lite'
$deskDir = Join-Path $root 'gdportal-desktop'
$coreExe = Join-Path $coreDir 'gdportal-lite.exe'
$coreGZ  = Join-Path $deskDir 'core_amd64.gz'
$oldGZ   = Join-Path $deskDir 'core_386.gz'
$outExe  = Join-Path $root 'GDPortal.exe'

$env:CGO_ENABLED = '0'

Write-Host '[1/6] Testing & vetting gdportal-lite (GOARCH=386, includes native cross-verify)...'
Push-Location $coreDir
try {
    $env:GOARCH = '386'
    go test -tags purego -count=1 ./...
    if ($LASTEXITCODE -ne 0) { throw "gdportal-lite 386 tests failed ($LASTEXITCODE)" }
    go vet -tags purego -unsafeptr=false ./...
    if ($LASTEXITCODE -ne 0) { throw "gdportal-lite 386 vet failed ($LASTEXITCODE)" }

    Write-Host '[2/6] Testing & vetting gdportal-lite (GOARCH=amd64, pure-Go x86emu)...'
    $env:GOARCH = 'amd64'
    go test -tags purego -count=1 ./...
    if ($LASTEXITCODE -ne 0) { throw "gdportal-lite amd64 tests failed ($LASTEXITCODE)" }
    go vet -tags purego -unsafeptr=false ./...
    if ($LASTEXITCODE -ne 0) { throw "gdportal-lite amd64 vet failed ($LASTEXITCODE)" }

    Write-Host '[3/6] Building native 64-bit gdportal-lite.exe (amd64)...'
    Get-ChildItem -Filter 'gdportal-lite.old*.exe' -ErrorAction SilentlyContinue | ForEach-Object {
        Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path $coreExe) {
        Rename-Item $coreExe ("gdportal-lite.old.$(Get-Date -Format 'HHmmss').exe") -Force
    }
    go build -tags purego -trimpath -ldflags='-s -w' -o $coreExe .
    if ($LASTEXITCODE -ne 0) { throw "gdportal-lite build failed ($LASTEXITCODE)" }
} finally {
    Pop-Location
}

if (Test-Path $oldGZ) {
    Remove-Item $oldGZ -Force -ErrorAction SilentlyContinue
}

Write-Host '[4/6] Compressing 64-bit core -> core_amd64.gz...'
$src = [System.IO.File]::ReadAllBytes($coreExe)
$ms = New-Object System.IO.MemoryStream
$gz = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionLevel]::Optimal, $true)
$gz.Write($src, 0, $src.Length)
$gz.Dispose()
[System.IO.File]::WriteAllBytes($coreGZ, $ms.ToArray())
Write-Host ("      core: {0:N0} B -> {1:N0} B" -f $src.Length, $ms.Length)

Write-Host '[5/6] Testing & vetting gdportal-desktop (GOARCH=amd64)...'
Push-Location $deskDir
try {
    $env:GOARCH = 'amd64'
    go test -v ./...
    if ($LASTEXITCODE -ne 0) { throw "gdportal-desktop tests failed ($LASTEXITCODE)" }
    go vet -unsafeptr=false ./...
    if ($LASTEXITCODE -ne 0) { throw "gdportal-desktop vet failed ($LASTEXITCODE)" }

    Write-Host '[6/6] Building GDPortal.exe (-H=windowsgui, single standalone)...'
    Get-ChildItem $root -Filter 'GDPortal.old.*.exe' -ErrorAction SilentlyContinue | ForEach-Object {
        Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path $outExe) {
        try {
            Remove-Item $outExe -Force -ErrorAction Stop
        } catch {
            Rename-Item $outExe ("GDPortal.old.$(Get-Date -Format 'HHmmss').exe") -Force
        }
    }
    go build -trimpath -ldflags='-s -w -H=windowsgui' -o $outExe .
    if ($LASTEXITCODE -ne 0) { throw "gdportal-desktop build failed ($LASTEXITCODE)" }
} finally {
    Pop-Location
}

$corePE = [BitConverter]::ToUInt16($src, [BitConverter]::ToInt32($src, 0x3C) + 4)
$outBytes = [System.IO.File]::ReadAllBytes($outExe)
$outPE = [BitConverter]::ToUInt16($outBytes, [BitConverter]::ToInt32($outBytes, 0x3C) + 4)
Write-Host ("Done! Core: {0} ({1:N0} B, PE Machine=0x{2:X4})" -f $coreExe, $src.Length, $corePE)
Write-Host ("      GUI : {0} ({1:N0} B, PE Machine=0x{2:X4})" -f $outExe, $outBytes.Length, $outPE)
