# Package a tool directory into an installable MyCorePlat tool ZIP.
#
#   pwsh tools/package-tool.ps1 -ToolDir tools/pdf-compressor
#
# The resulting ZIP is what an administrator uploads through
# Admin -> Installer -> Upload ZIP. Nothing else is required: the installer
# validates the package, builds the image and runs the container.
#
# The archive contains the tool directory contents at the ROOT of the ZIP
# (manifest.json, Dockerfile, app/, requirements.txt, ...) because the
# installer extracts it as the Docker build context.
param(
    [Parameter(Mandatory = $true)][string]$ToolDir,
    [string]$OutDir = "dist"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $ToolDir)) {
    throw "tool directory not found: $ToolDir"
}

$manifest = Join-Path $ToolDir "manifest.json"
$dockerfile = Join-Path $ToolDir "Dockerfile"
foreach ($required in @($manifest, $dockerfile)) {
    if (-not (Test-Path -LiteralPath $required)) {
        throw "missing required file: $required"
    }
}

$slug = (Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json).id
if (-not $slug) { throw "manifest.json has no id" }

# Files/directories that must never ship in a package.
$excludeDirs = @(".pytest_cache", "__pycache__", ".venv", "venv", "tests", ".git", "secrets", ".mypy_cache")
$excludeFiles = @("pytest.ini", "README.md", "docker-compose.yml", ".dockerignore", "*.pyc", "*.pyo", "*.db", "*.log")

$version = (Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json).version
$outName = "$slug-$version.zip"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$outPath = Join-Path $OutDir $outName
if (Test-Path -LiteralPath $outPath) { Remove-Item -LiteralPath $outPath -Force }

Add-Type -AssemblyName System.IO.Compression.FileSystem

$zip = [System.IO.Compression.ZipFile]::Open($outPath, [System.IO.Compression.ZipArchiveMode]::Create)
try {
    $root = (Resolve-Path -LiteralPath $ToolDir).Path
    Get-ChildItem -LiteralPath $root -Recurse -File | ForEach-Object {
        $rel = $_.FullName.Substring($root.Length + 1).Replace('\', '/')
        $segments = $rel.Split('/')

        # Skip excluded directories anywhere in the path.
        $skip = $false
        for ($i = 0; $i -lt $segments.Length - 1; $i++) {
            if ($excludeDirs -contains $segments[$i]) { $skip = $true; break }
        }
        if ($skip) { return }

        # Skip excluded files (basename) at any depth.
        $name = $segments[$segments.Length - 1]
        foreach ($pattern in $excludeFiles) {
            if ($name -like $pattern) { return }
        }

        [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
            $zip, $_.FullName, $rel, [System.IO.Compression.CompressionLevel]::Optimal) | Out-Null
    }
}
finally {
    $zip.Dispose()
}

$size = (Get-Item -LiteralPath $outPath).Length
Write-Output "packaged: $outPath ($size bytes)"
