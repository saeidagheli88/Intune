[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$fileName = 'windowsdesktop-runtime-9.0.20-win-x64.exe'
$destination = Join-Path $PSScriptRoot $fileName
$temporaryFile = "$destination.download"
$uri = 'https://builds.dotnet.microsoft.com/dotnet/WindowsDesktop/9.0.20/windowsdesktop-runtime-9.0.20-win-x64.exe'

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Write-Host "Downloading official Microsoft installer: $fileName"
    Invoke-WebRequest -Uri $uri -OutFile $temporaryFile -UseBasicParsing

    $signature = Get-AuthenticodeSignature -FilePath $temporaryFile
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Microsoft Corporation') {
        throw "Authenticode validation failed. Status: $($signature.Status); Signer: $($signature.SignerCertificate.Subject)"
    }

    Move-Item -LiteralPath $temporaryFile -Destination $destination -Force
    Write-Host "Downloaded and signature-verified: $destination" -ForegroundColor Green
}
finally {
    if (Test-Path -LiteralPath $temporaryFile) { Remove-Item -LiteralPath $temporaryFile -Force }
}

