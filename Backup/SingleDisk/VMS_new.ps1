$date = Get-Date -Format "dd_MM_yyyy"
$dateMs = ([TimeSpan] (Get-Date).ToShortTimeString()).TotalMilliseconds

$urlFilesToDownload = @('https://github.com/marcusvd/PowerShell/raw/main/Backup/SingleDisk/BackupModule.psm1', 'https://raw.githubusercontent.com/marcusvd/PowerShell/main/Backup/SingleDisk/VMS.ps1')
$pathToSaveFile = $env:HOMEPATH + '\Downloads'
foreach ($url in $urlFilesToDownload) {
    Invoke-WebRequest -Uri $url -OutFile "$($pathToSaveFile)\$($url.split('/')[$url.split('/').Length - 1])"  -ErrorAction SilentlyContinue 
} 

$pathToSaveFile = $env:HOMEPATH + '\Downloads'
$LastUpdatedFiles = @("$($pathToSaveFile)\BackupModule.psm1", "$($pathToSaveFile)\VMS.ps1")
$hashUpdateFile = @()
#
$pathBaseCurrentFiles = "c:\util"
$currentFiles = @("$($pathBaseCurrentFiles)\BackupModule.psm1", "$($pathBaseCurrentFiles)\VMS.ps1")
$hashCurrentFile = @()

foreach ($updated in $LastUpdatedFiles) {
    if (Test-Path($updated)) {
        $hashUpdateFile += Get-FileHash -Path $updated -Algorithm SHA256
    }
}

foreach ($current in $currentFiles) {
    if (Test-Path($current)) {
        $hashCurrentFile += Get-FileHash -Path $current -Algorithm SHA256
    }
}

foreach ($fUpdatePath in $hashUpdateFile) {
    foreach ($fCurrentPath in $hashCurrentFile) {
        
        if ($fCurrentPath.Path.split('\')[$fCurrentPath.Path.split('\').Length - 1] -eq $fUpdatePath.Path.split('\')[$fUpdatePath.Path.split('\').Length - 1]) {
           
            if ($fUpdatePath.Hash -eq $fCurrentPath.Hash) {
                Write-Host("Hash e igual")
            }
            else {
                Write-Host('Hash nao e igual')
                Rename-Item -Path "$($pathBaseCurrentFiles)\$($fUpdatePath.Path.split('\')[$fUpdatePath.Path.split('\').Length - 1])" -NewName "$($($fUpdatePath.Path.split('\')[$fUpdatePath.Path.split('\').Length - 1]))-$($date)-$($dateMs)"
                Copy-Item -Path "$($pathToSaveFile)\$($fUpdatePath.Path.split('\')[$fUpdatePath.Path.split('\').Length - 1])" -Destination "$($pathBaseCurrentFiles)\$($fUpdatePath.Path.split('\')[$fUpdatePath.Path.split('\').Length - 1])"
            }
        }
    }
}
