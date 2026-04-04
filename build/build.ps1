param(
    [ValidateSet("Debug", "Release")]
    [string]$Config = "Debug",
    [switch]$Clean
)

$BuildDir  = $PSScriptRoot
$RootDir   = Split-Path $BuildDir -Parent

# Clean
if ($Clean) {
    Write-Host "Cleaning build directory..."
    Get-ChildItem $BuildDir -Exclude "build.ps1" | Remove-Item -Recurse -Force
}

# Configure
Write-Host "Configuring ($Config)..."
cmake -S $RootDir -B $BuildDir `
    -DCMAKE_BUILD_TYPE=$Config `
    -DCMAKE_C_COMPILER="C:/msys64/ucrt64/bin/gcc.exe" `
    -G "MinGW Makefiles"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# Build
Write-Host "Building ($Config)..."
cmake --build $BuildDir --config $Config --parallel
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host ""
Write-Host "Build complete: $BuildDir\$Config\aes_encryption.exe"
