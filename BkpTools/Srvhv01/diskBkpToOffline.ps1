$disk = Get-Disk | Where-Object Number -Eq 3

function DiskToOff([boolean]$OnOff){

$disk  | Set-Disk -IsOffline $OnOff
 
}

while($disk.OperationalStatus -eq 'Offline'){
DiskToOff($true)
} 
while($disk.OperationalStatus -eq 'Online'){
DiskToOff($true)
} 