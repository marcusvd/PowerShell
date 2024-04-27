
#region SendMail
Function SendMail([string]$subject, [string]$body) {

    $Email = New-Object System.Net.Mail.MailMessage

    $Email.subject = $subject
    $Email.body = $body
    $Email.to.add("backup@nostopti.com.br")
    #$Email.CC.Add("lucaslaender@hotmail.com")
    $Email.from = "backup@nostopti.com.br"
    #$Email.attachments.add(Attachment)

    $Smtp = New-Object System.Net.Mail.SmtpClient("smtp.nostopti.com.br", 587);
    #$Smtp.EnableSsl =$true
    $Smtp.Credentials = New-Object System.Net.NetworkCredential("backup@nostopti.com.br", "Nsti@2024");
    $Smtp.Send($Email)
   
}
Export-ModuleMember -Function SendMail
#endregion

#region VmsCheckExists
#$Date = Get-Date -Format "dd_MM_yyyy"
#$VmsPaths = @("C:\Util\BACKUP\$($Date)\SRVAD01\SRVAD01.VHDX", "C:\Util\BACKUP\$($Date)\SRVFL01\SRVFL01.vhdx", "C:\Util\BACKUP\$($Date)\SRVFL01\DADOS.vhdx", "C:\Util\BACKUP\$($Date)\SRVSH01\SRVSH01.vhdx")

Function VmsCheckExists([string[]]$paths) { 

$resultBoolFalse = @()

$paths.ForEach({
           if(!(Test-Path($_)))
           {
            $resultBoolFalse += [System.IO.File]::Exists($_)
           }
        })
    
    if($resultBoolFalse.Count -gt 0)
    {
     Write-Host("Fail")
     #SendMail($false)
     return $false
    }

   Write-Host("Success")
   return $true
   
}
#VmsCheckExists -paths $VmsPaths
Export-ModuleMember -Function VmsCheckExists
#endregion

#region CheckFreeSpaceDisk
Function CheckFreeSpaceDisk {
    Param([Parameter(ValueFromPipeLine)]
        [string]$DriverLetter
    )

    [int]$result = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='$DriverLetter'"  | ForEach-Object { [Math]::Round(($_.FreeSpace / 1GB), 2) }

    return $result
}
#CheckFreeSpaceDisk -DriverLetter "c:"
Export-ModuleMember -Function CheckFreeSpaceDisk
#endregion

#region CalcFilesSize
Function CalcFilesSize{
Param([Parameter(ValueFromPipeline)]
[string]$pathToFile, [string]$extension 
)

$pathFiles = Join-Path -Path $pathToFile -ChildPath $extension


$getAllFfiles = Get-ChildItem -Path $pathFiles -Recurse

$vhdxTotalSize = $null

$getAllFfiles.ForEach({
    $vhdxTotalSize += $_.Length
})

[int]$result = $vhdxTotalSize | ForEach-Object {[Math]::Round(($_ / 1GB),2)}

return $result

}
#CalcFilesSize -pathToFile "\\srvhv10\v$\VMS\SERVIDORES" -extension "*.vhd*"
Export-ModuleMember -Function CalcFilesSize
#endregion

#region BackUpCopy
Function BackUpCopy {
    Param([Parameter(ValueFromPipeLine)]
        [string]$target, [string]$destiny
    )

    $Date = Get-Date -Format "dd_MM_yyyy"

    $destinyPlace = Join-Path -Path $destiny -ChildPath $Date

    write-host("-------BACKUPING...-------")
    Write-Host($target, $destinyPlace)
    Copy-Item -Path $target -Destination $destinyPlace -Recurse -Force
}
#BackUpCopy -target '\\SRVHV10\V$\vms\*' -destiny 'c:\users\adm02\desktop'
Export-ModuleMember -Function BackUpCopy
#endregion 

#region DeleteOlderFiles
Function DeleteOlderFiles {
    Param([Parameter(ValueFromPipeLine)]
        [string]$PathFilesToDelete, [int]$daysBack
    )

 $result = Get-ChildItem  -Path $PathFilesToDelete -Directory | where {$_.CreationTime -le $(get-date).AddDays(-$daysBack)} | Remove-Item -recurse  
 $result
 #Write-host($result)
    
}
Export-ModuleMember -Function DeleteOlderFiles
#DeleteOlderFiles -PathFilesToDelete $DriveA
#endregion
