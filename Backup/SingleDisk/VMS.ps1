
$headerJson = Get-Content -Path "C:\Util\BackupHeader.json" -Raw

$powerShellObj = $headerJson | ConvertFrom-Json

Import-Module -Name $powerShellObj.Module -Force
#$Date = $powerShellObj.Date
$VmsPathsSource = $powerShellObj.VmsPathsSource
$VmsPathsDestiny = $powerShellObj.VmsPathsDestiny
$PathVmsToBackupCalculateAmount = $powerShellObj.PathVmsToBackupCalculateAmount
$ExtensionFilesToCalculateAmount = $powerShellObj.ExtensionFilesToCalculateAmount
$DriveToBackupIsFreeSpace = $powerShellObj.DriveToBackupIsFreeSpace
$PathToBackupFiles = $powerShellObj.PathToBackupFiles
$PathToDelete = $powerShellObj.PathToDelete
$MsgSource = $powerShellObj.MsgSource
$MsgDestiny = $powerShellObj.MsgDestiny
$daysBack = $powerShellObj.daysBack

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


Function CheckDestiny {
    if (!(VmsCheckExists -paths $VmsPathsDestiny)) {
        SendMail($MsgDestiny)
        #Shutdown
        Invoke-Command { shutdown -s -f -t 120 }
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