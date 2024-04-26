$pathToSaveFile = $env:HOMEPATH + '\Downloads'
$LastUpdatedFiles = @("$($pathToSaveFile)\BackupModule.psm1", "$($pathToSaveFile)\VMS.ps1")
$resultCheckUpdatedFiles = @()
$hashUpdateFile = @()
#
$currentFiles = @("c:\util\BackupModule.psm1", "c:\util\VMS.ps1")
$resultCheckCurrentFiles = @()
$hashCurrentFile = @()


foreach ($updated in $LastUpdatedFiles) {
    
    if (Test-Path($updated)) {
        $resultCheckUpdatedFiles += $true
        $hashUpdateFile += Get-FileHash -Path $updated -Algorithm SHA256
    }

}

foreach ($current in $currentFiles) {
    
    if (Test-Path($updated)) {
        $resultCheckCurrentFiles += $true
        $hashCurrentFile += Get-FileHash -Path $current -Algorithm SHA256
    }

}


Write-Host($resultCheckUpdatedFiles, $hashUpdateFile)
Write-Host($resultCheckCurrentFiles, $hashCurrentFile)




# Caminho para o arquivo
#$arquivo = "Caminho\para\o\arquivo\arquivo.txt"

# Calcula a hash do arquivo usando o algoritmo SHA256
#$hash = Get-FileHash -Path $arquivo -Algorithm SHA256

# Imprime a hash do arquivo
#Write-Host "A hash SHA256 do arquivo é: $($hash.Hash)"


# $urlFilesToDownload = @('https://github.com/marcusvd/PowerShell/raw/main/Backup/SingleDisk/BackupModule.psm1', 'https://raw.githubusercontent.com/marcusvd/PowerShell/main/Backup/SingleDisk/VMS.ps1')
# $pathToSaveFile = $env:HOMEPATH + '\Downloads'
# foreach ($url in $urlFilesToDownload) {
#     Invoke-WebRequest -Uri $url -OutFile "$($pathToSaveFile)\$($url.split('/')[$url.split('/').Length - 1])"  -ErrorAction SilentlyContinue 
# } 

