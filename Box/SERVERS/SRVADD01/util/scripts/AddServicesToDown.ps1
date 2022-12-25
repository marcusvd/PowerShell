Function StartStopServ 
{Param([Parameter(ValueFromPipeline)]
  $ServiceName,
  $Status
)

if($Status -eq "Stopped"){

Stop-Service -Name $ServiceName -Force

}
$Services = Set-Service -Name $ServiceName -Status $Status
$Services
}
$getPath = get-process -Name "GoogleDriveFS" -FileVersionInfo
$FullPathToExeGDrive = $getPath.FileName[0]

StartStopServ -ServiceName "MSSQL`$ADDSOFT" -Status "Stopped"
invoke-command { taskkill /f /im GoogleDriveFS.exe}

Function StartProcess($Run){Start-Process -FilePath $Run} StartProcess -Run $FullPathToExeGDrive



