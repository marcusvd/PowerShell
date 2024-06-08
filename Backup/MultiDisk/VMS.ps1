
pause
$headerJson = Get-Content -Path "C:\Util\BackupHeader.json" -Raw
$powerShellObj = $headerJson | ConvertFrom-Json
Import-Module -Name $powerShellObj.Module -Force


$VmsPathsSource = $powerShellObj.VmsPathsSource
$VmsPathsDestinyBase = $powerShellObj.VmsPathsDestinyBase
$VmsPathsDestiny = $powerShellObj.VmsPathsDestiny

$DriveA = $powerShellObj.VmsPathsDestinyBase[0]
$DriveB = $powerShellObj.VmsPathsDestinyBase[1]
$Date = Get-Date -Format "dd_MM_yyyy"
$VmsVhdx = $powerShellObj.PathVmsToBackupCalculateAmount

if (!(VmsCheckExists -paths $VmsPathsSource)) {
    SendMail($MsgSource)
    #Shutdown 
    Invoke-Command { shutdown -s -f -t 120 }
}

$fullDestinyPathToTestDriveA = @()
$fullDestinyPathToTestDriveB = @()

foreach ($destiny in $VmsPathsDestiny) {
    $fullDestinyPathToTestDriveA += "$($VmsPathsDestinyBase[0])$($Date)$($destiny)"
}

foreach ($destiny in $VmsPathsDestiny) {
    $fullDestinyPathToTestDriveB += "$($VmsPathsDestinyBase[0])$($Date)$($destiny)"
}

Function CheckDestiny {
    if (!(VmsCheckExists -paths $fullDestinyPathToTestDriveA) -or !(VmsCheckExists -paths $fullDestinyPathToTestDriveB)) {
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



Function DeleteOlderFiles {
    Param([Parameter(ValueFromPipeLine)]
        [string]$PathFilesToDelete
    )

    Get-ChildItem  -Path $PathFilesToDelete | Remove-Item -recurse

    $MakeFile = Join-Path -Path $PathFilesToDelete.Split('\')[0] -ChildPath $PathFilesToDelete.Split('\')[1]

    New-Item -Path $MakeFile -ItemType file -Name "Lastclean.txt" -Value $Date

}


$DriveAToStorageBackup = (CheckFreeSpaceDisk -DriverLetter $DriveA.Split('\')[0])
$DriveBToStorageBackup = (CheckFreeSpaceDisk -DriverLetter $DriveB.Split('\')[0])


$VmsToBackup = CalcFilesSize -pathToFile $VmsVhdx -extension "*.vhd*"


$resultTwoDisk = $DriveAToStorageBackup -gt ($VmsToBackup) -or $DriveBToStorageBackup -gt ($VmsToBackup)


if ($resultTwoDisk) {

    $ResultDriveA = ($DriveAToStorageBackup) -gt ($VmsToBackup)

    if ($ResultDriveA) {
   
        Write-Host("primeiro if drive A tem espaço")
        Write-Host("Backuping Drive(A)....")
        #####pause
        BackUpCopy -target $VmsVhdx -destiny $DriveA

    }

    else {

        $ResultDriveB = ($DriveBToStorageBackup) -gt ($VmsToBackup)

        if ($ResultDriveB) {
            Write-Host("primeiro if drive B tem espaço")
            Write-Host("Backuping Drive(B)....")
            #####pause
            BackUpCopy -target $VmsVhdx -destiny $DriveB
        }
    }

}

else {

    Write-Host("Entrou no Else de quando os discos estão todos cheios")
    #####pause
    $pathDateBpkFileDriveA = Join-Path -Path $DriveA.Split('\')[0] -ChildPath $DriveA.Split('\')[1]
    $fileFullPathDriveA = Join-Path -Path $pathDateBpkFileDriveA -ChildPath "lastClean.txt"

    $pathDateBpkFileDriveB = Join-Path -Path $DriveB.Split('\')[0] -ChildPath $DriveB.Split('\')[1]
    $fileFullPathDriveB = Join-Path -Path $pathDateBpkFileDriveB -ChildPath "lastClean.txt"

    $resultDateOlderDriveA = Get-Item -Path $fileFullPathDriveA
    $resultDateOlderDriveB = Get-Item -Path $fileFullPathDriveB

    $olderDateFiles = $resultDateOlderDriveA.LastWriteTime -le $resultDateOlderDriveB.LastWriteTime


    if ($olderDateFiles) {
    
        Write-Host("Deletando driveA....")
        #####pause
        DeleteOlderFiles -PathFilesToDelete $DriveA
        
   
        New-Item -Name "lastClean.txt" -Path $pathDateBpkFileDriveA -ItemType file -Value $Date -Force
        Write-Host("Backuping Drive(A)....")
        BackUpCopy -target $VmsVhdx -destiny $DriveA

    }
    else {
    
        Write-Host("Deletando driveB....")
        #####pause
        DeleteOlderFiles -PathFilesToDelete $DriveB
        New-Item -Name "lastClean.txt" -Path $pathDateBpkFileDriveB -ItemType file -Value $Date -Force
        Write-Host("Backuping Drive(B)....")
        BackUpCopy -target $VmsVhdx -destiny $DriveB

    }




}

CheckDestiny

Invoke-Command { shutdown -s -f -t 120 }