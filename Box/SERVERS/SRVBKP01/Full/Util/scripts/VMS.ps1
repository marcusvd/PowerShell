Invoke-Command{net use \\srvhv01 /user:lvsa\nostop "sMtp2020$`&"}
Start-Transcript -Path c:\util\Backup.txt -Append -Force
write-host("CLEANING DATA OLD.")
#BACKUP CLEANING DATA OLD
$Date = Get-Date -Format "dd_MM_yyyy"
get-date -format F | add-content "C:\UTIL\BACKUP\Log_Cleaning_$Date.txt"
Get-ChildItem  -Path "C:\UTIL\BACKUP\" -Directory | where {$_.CreationTime -le $(get-date).AddDays(-3)} | Remove-Item -recurse
get-date -format F | add-content "C:\UTIL\BACKUP\Log_Cleaning_$Date.txt"
cls
write-host("-------BACKUPING...-------")
#BACKUP DATA
$Date = Get-Date -Format "dd_MM_yyyy"
$Storage = "C:\UTIL\BACKUP\"
get-date -format F | add-content "C:\UTIL\BACKUP\elapsed_$Date.txt"
Copy-Item -Path "\\srvhv01\e$\vms" -Destination "C:\UTIL\BACKUP\$Date" -Recurse -Force
get-date -format F | add-content "C:\UTIL\BACKUP\elapsed_$Date.txt"
#EMAIL

#<><><><><><><><><><><><><><><><><><><><>><><>#
Function SendMail{Param([Parameter(Mandatory=$false)]
$SMTPServer,
$SMTPPort,
$Username,
$Password,
$to,
$cc,
$subject,
$body,   
$attachment
)
$Email = New-Object System.Net.Mail.MailMessage
$Email.subject = $subject
$Email.body = $body
$Email.to.add("backup@nostopti.com")
#$Email.cc.add($cc)
$Email.from = $username
#$Email.attachments.add($attachment)
$Smtp = New-Object System.Net.Mail.SmtpClient($SMTPServer, $SMTPPort);
#$Smtp.EnableSsl =$true
$Smtp.Credentials = New-Object System.Net.NetworkCredential($Username, $Password);
$Smtp.Send($Email)


}
#Object to send email
$BackupObjResult = New-Object PSObject

[string[]]$Source = "\\srvhv01\e$\vms\SRVAD01\SRVAD01.vhdx", "\\srvhv01\e$\vms\SRVCP01\SRVCP01.vhdx", "\\srvhv01\e$\vms\SRVFL01\DADOS.vhdx", "\\srvhv01\e$\vms\SRVFL01\SRVFL01.vhdx"
[string[]]$Destiny = "$Storage$Date\SRVAD01\SRVAD01.vhdx", "$Storage$Date\SRVCP01\SRVCP01.vhdx", "$Storage$Date\SRVFL01\DADOS.vhdx", "$Storage$Date\SRVFL01\SRVFL01.vhdx"

if(Test-Path("C:\UTIL\BACKUP\$Date"))
{
    write-host("Test path")
    
         function Check($first, $second, [string]$rest)
            {
                $SourceGet = Get-ChildItem -Path $first
                $DestinyGet = Get-ChildItem -Path $second

                    if($SourceGet.Length -eq $DestinyGet.Length)
                      {
                        #write-host("Iguais!")
                        Add-Member -InputObject $BackupObjResult -MemberType NoteProperty -Name "Source$n" -value $Source[$control]
                        Add-Member -InputObject $BackupObjResult -MemberType NoteProperty -Name "Destiny$n" -value $Destiny[$control]
                        Add-Member -InputObject $BackupObjResult -MemberType NoteProperty -Name "Result$n" -value "PERFECT"
                        
                        
                      }
                      else
                      {
                        #write-host("Diferente")
                        
                        
                        Add-Member -InputObject $BackupObjResult -MemberType NoteProperty -Name "Source$n" -value $Source[$control]
                        Add-Member -InputObject $BackupObjResult -MemberType NoteProperty -Name "Destiny$n" -value $Destiny[$control]
                        Add-Member -InputObject $BackupObjResult -MemberType NoteProperty -Name "Result$n" -value "ERROR"
                      }
       
            }

            
                        for([int]$n = 0; $n -lt 4;  $n++){
                        [int]$control = $n
                        Check -first $Source[$control] -second $Destiny[$control]

                        }


                      
     
}
else
{
Write-Host("Falha total de rotina de BACKUP!")
SendMail -SMTPServer "ns1.a3msites.com.br" -SMTPPort "587" -Username "backup@nostopti.com" -Password "http2020$" -to "backup@nostopti.com" -subject "(FALHA GERAL(LVSA))" -body "LVSA FALHA GERAL"
}

   if($BackupObjResult.Result0 -and $BackupObjResult.Result1 -and $BackupObjResult.Result2 -and $BackupObjResult.Result3 -eq "PERFECT")
                        {

                        SendMail -SMTPServer "ns1.a3msites.com.br" -SMTPPort "587" -Username "backup@nostopti.com" -Password "http2020$" -to "backup@nostopti.com" -subject "LVSA PERFECT" -body $BackupObjResult
                         Write-Host("Enviando e-mail! Sucesso!")
                        Start-Sleep -Seconds 10
                        
                        }
                        else
                        {
                         SendMail -SMTPServer "ns1.a3msites.com.br" -SMTPPort "587" -Username "backup@nostopti.com" -Password "http2020$" -to "backup@nostopti.com" -subject "(LVSA) FAIL" -body $BackupObjResult
                          Write-Host("Enviando e-mail! Falha!")
                          Start-Sleep -Seconds 60
                         
                        }

shutdown -s -f -t 300
