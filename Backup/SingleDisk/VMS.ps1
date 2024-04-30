$headerJson = Get-Content -Path "C:\Util\BackupHeader.json" -Raw
$powerShellObj = $headerJson | ConvertFrom-Json
Import-Module -Name $powerShellObj.Module -Force

$Date = Get-Date -Format 'dd_MM_yyyy'
$VmsPathsSource = $powerShellObj.VmsPathsSource
$VmsPathsDestinyBase = $powerShellObj.VmsPathsDestinyBase
$VmsPathsDestiny = $powerShellObj.VmsPathsDestiny
$PathVmsToBackupCalculateAmount = $powerShellObj.PathVmsToBackupCalculateAmount
$ExtensionFilesToCalculateAmount = $powerShellObj.ExtensionFilesToCalculateAmount
$DriveToBackupIsFreeSpace = $powerShellObj.DriveToBackupIsFreeSpace
$PathToBackupFiles = $powerShellObj.PathToBackupFiles
$PathToDelete = $powerShellObj.PathToDelete
$MsgSource = $powerShellObj.MsgSource
$MsgDestiny = $powerShellObj.MsgDestiny
$daysBack = $powerShellObj.daysBack
#$MsgSuccess = $powerShellObj.MsgSuccess
#$Company = $powerShellObj.Company

Function TotalFilesToBackup {
    return CalcFilesSize -pathToFile $PathVmsToBackupCalculateAmount -extension $ExtensionFilesToCalculateAmount
}

Function TotalFreeSpaceLocalDriveToBackup {
    return CheckFreeSpaceDisk -DriverLetter $DriveToBackupIsFreeSpace
}

if (!(VmsCheckExists -paths $VmsPathsSource)) {
    SendMail($MsgSource)
    #Shutdown 
    Invoke-Command { shutdown -s -f -t 120 }
}

$fullDestinyPathToTest = @()

foreach ($destiny in $VmsPathsDestiny) {
    $fullDestinyPathToTest += "$($VmsPathsDestinyBase)$($Date)$($destiny)"
}


Function CheckDestiny {
    if (!(VmsCheckExists -paths $fullDestinyPathToTest)) {
        SendMail($MsgDestiny)
        #Shutdown
        Invoke-Command { shutdown -s -f -t 120 }
    }
    else {
        $domainName = (Get-WmiObject Win32_ComputerSystem).Domain
        $msg = "Success"
        #all Wednesday
        if ((Get-Date).DayOfWeek -eq "Tuesday" -or (Get-Date).DayOfWeek -eq "Wednesday") {
        # if ((Get-Date).DayOfWeek -eq "Wednesday") {
            SendMail("$($domainName)", $msg)
        }
    }
}



[int]$DriveToBackup = TotalFreeSpaceLocalDriveToBackup
[int]$FilesForBack = TotalFilesToBackup

While ($DriveToBackup -lt $FilesForBack) {
    $daysBack--
    DeleteOlderFiles -PathFilesToDelete $PathToDelete -daysBack $daysBack
    $DriveToBackup = TotalFreeSpaceLocalDriveToBackup
    $FilesForBack = TotalFilesToBackup
    Write-host($daysBack)
}


BackUpCopy -target $PathVmsToBackupCalculateAmount -destiny $PathToBackupFiles

CheckDestiny

Invoke-Command { shutdown -s -f -t 120 }