

#$connection = New-PSSession -ComputerName srvhv10 -Credential nostopti\marcus

$connection = Enter-PSSession -ComputerName srvhv10 -Credential nostopti\marcus



#Invoke-Command -ComputerName srvhv10 -ScriptBlock {Get-VM}

