$urlFilesToDownload = @('https://github.com/marcusvd/PowerShell/raw/main/Backup/SingleDisk/BackupModule.psm1', 'https://raw.githubusercontent.com/marcusvd/PowerShell/main/Backup/SingleDisk/VMS.ps1')
$pathToSaveFile = $env:HOMEPATH + '\Downloads'
foreach ($url in $urlFilesToDownload) {
    Invoke-WebRequest -Uri $url -OutFile "$($pathToSaveFile)\$($url.split('/')[$url.split('/').Length - 1])"  -ErrorAction SilentlyContinue 
} 


$pathToSaveFile = $env:HOMEPATH + '\Downloads'
$LastUpdatedFiles = @("$($pathToSaveFile)\BackupModule.psm1", "$($pathToSaveFile)\VMS.ps1")
# $resultCheckFileExistUpdatedFiles = @()
$hashUpdateFile = @()
#
$currentFiles = @("c:\util\BackupModule.psm1", "c:\util\VMS.ps1")
# $resultCheckFileExistCurrentFiles = @()
$hashCurrentFile = @()


foreach ($updated in $LastUpdatedFiles) {
    
    if (Test-Path($updated)) {
        # $resultCheckFileExistUpdatedFiles += $true
        $hashUpdateFile += Get-FileHash -Path $updated -Algorithm SHA256
    }

}

foreach ($current in $currentFiles) {
    
    if (Test-Path($current)) {
        # $resultCheckFileExistCurrentFiles += $true
        $hashCurrentFile += Get-FileHash -Path $current -Algorithm SHA256
    }

}


foreach ($fUpdatePath in $hashUpdateFile) {
    foreach ($fCurrentPath in $hashCurrentFile) {
        
        if ($fCurrentPath.Path.split('\')[$fCurrentPath.Path.split('\').Length - 1] -eq $fUpdatePath.Path.split('\')[$fUpdatePath.Path.split('\').Length - 1]) {
           
            if ($fUpdatePath.Hash -eq $fCurrentPath.Hash) {
                Write-Host($fUpdatePath.Path)
                Write-Host($fUpdatePath.Path)
                Write-Host("Hash e igual")
            }
            else {
                Write-Host('Hash nao e igual')
            }
            # Write-Host($fUpdatePath)
            # Write-Host($fCurrentPath)
            
            # Write-Host($fCurrentPath.split('\')[$fCurrentPath.split('\').Length -1])
        }
    }
    
}
# foreach ($fUpdatePath in $hashUpdateFile.Path) {
    
#     foreach ($fCurrentPath in $hashCurrentFile.Path) {
      
#         if ($fCurrentPath.split('\')[$fCurrentPath.split('\').Length -1] -eq $fUpdatePath.split('\')[$fUpdatePath.split('\').Length -1]) {
            
#             Write-Host($fCurrentPath.split('\')[$fCurrentPath.split('\').Length -1])
#         }
#     }
    
# }


#Write-Host($hashUpdateFile.Path[0])
#Write-Host($hashCurrentFile.Path[0])


# Write-Host($resultCheckFileExistUpdatedFiles, $hashUpdateFile)
# Write-Host($resultCheckFileExistCurrentFiles, $hashCurrentFile)




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

