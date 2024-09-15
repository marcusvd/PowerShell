using module C:\util\scripts\modules\EmailModule.psm1
using module C:\util\scripts\modules\VmsModule.psm1

#Start VM BKP
Start-VM -Name "srvbkp01" -ErrorAction SilentlyContinue


$resultVmState = CheckStateVmOn -VmName 'SRVBKP01'



if($resultVmState){
#SendMailEncapsulated -subject "(SUCCESS)-[ARC_AR] VM-BACKUP turned on" -body "----NO STOP-TI----"
}
else{
SendMailEncapsulated -subject "(FAIL)-[ARC_AR] VM-BACKUP did not turn on." -body "----NO STOP-TI----"
}


$resultUpTime = UpTimeGreaterThan -vmName 'SRVBKP01' -days 0 -hours 12

if($resultUpTime){
SendMailEncapsulated -subject "(FAIL)-[ARC_AR]-VM-BACKUP-{long time turned on, one command was sent to turn off the vm.}" -body "----NO STOP-TI----"
}
