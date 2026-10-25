# Cross-build for Keenetic Hopper (mipsle, softfloat). Run from the project root:
#   powershell -ExecutionPolicy Bypass -File scripts\build.ps1
$ErrorActionPreference = 'Stop'

$version = $env:VERSION
if (-not $version) {
    $version = (git describe --tags --always --dirty 2>$null)
    if (-not $version) { $version = 'dev' }
}

New-Item -ItemType Directory -Force dist | Out-Null

$old = @{ GOOS = $env:GOOS; GOARCH = $env:GOARCH; GOMIPS = $env:GOMIPS; CGO_ENABLED = $env:CGO_ENABLED }
$env:GOOS = 'linux'; $env:GOARCH = 'mipsle'; $env:GOMIPS = 'softfloat'; $env:CGO_ENABLED = '0'
try {
    go build -trimpath -ldflags "-s -w -X main.version=$version" -o dist/xkeen-ui-linux-mipsle ./cmd/xkeen-ui
    if ($LASTEXITCODE -ne 0) { throw "go build failed" }
} finally {
    $env:GOOS = $old.GOOS; $env:GOARCH = $old.GOARCH; $env:GOMIPS = $old.GOMIPS; $env:CGO_ENABLED = $old.CGO_ENABLED
}

# sha256sum-compatible file (lowercase hash, two spaces, LF line ending)
$hash = (Get-FileHash dist/xkeen-ui-linux-mipsle -Algorithm SHA256).Hash.ToLower()
[IO.File]::WriteAllText("$PWD/dist/xkeen-ui-linux-mipsle.sha256", "$hash  xkeen-ui-linux-mipsle`n")

Get-ChildItem dist | Format-Table Name, Length
Write-Host "version: $version"
