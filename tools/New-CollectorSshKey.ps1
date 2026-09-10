param(
    [Parameter(Mandatory = $true)]
    [string]$Name,

    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
$directory = [System.IO.Path]::GetFullPath($OutputDirectory)
$privateKey = Join-Path $directory "id_ed25519_$Name"
$publicKey = "$privateKey.pub"

if (Test-Path -LiteralPath $privateKey) {
    throw "Refusing to overwrite existing key: $privateKey"
}

New-Item -ItemType Directory -Path $directory -Force | Out-Null
$sshKeygen = (Get-Command ssh-keygen).Source
$startInfo = [Diagnostics.ProcessStartInfo]::new()
$startInfo.FileName = $sshKeygen
$startInfo.UseShellExecute = $false
foreach ($argument in @('-q', '-t', 'ed25519', '-f', $privateKey, '-N', '', '-C', "codex-$Name-xui-collector")) {
    [void]$startInfo.ArgumentList.Add($argument)
}
$process = [Diagnostics.Process]::Start($startInfo)
$process.WaitForExit()
if ($process.ExitCode -ne 0) {
    throw "ssh-keygen failed with exit code $($process.ExitCode)"
}

# A key with a mistaken passphrase would prompt or fail here. This must succeed unattended.
& $sshKeygen -y -P '' -f $privateKey | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw 'Generated key failed the non-interactive private-key validation'
}

$fingerprint = & $sshKeygen -lf $publicKey
[pscustomobject]@{
    PrivateKey = $privateKey
    PublicKey = $publicKey
    Fingerprint = $fingerprint
}
