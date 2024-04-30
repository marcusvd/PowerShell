# Definir as credenciais
$Username = "NomeDoUsuario"
$Password = ConvertTo-SecureString "SuaSenhaAqui" -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential($Username, $Password)

# Conectar-se ao servidor remoto
$Session = New-PSSession -ComputerName "srvad10" -Credential $Credential
Invoke-Command -Session $Session -ScriptBlock {
    param($Username, $NewPassword)
    # Alterar a senha do usuário
    Set-ADAccountPassword -Identity $Username -NewPassword (ConvertTo-SecureString -AsPlainText $NewPassword -Force) -Reset
} -ArgumentList $Username = "administrator", $NewPassword ="sMtp2020$&"
Remove-PSSession $Session


# Definir as credenciais
# $Username = "nostop"
# $Password = ConvertTo-SecureString "sMtp2020$&" -AsPlainText -Force
# $Credential = New-Object System.Management.Automation.PSCredential($Username, $Password)

# # Conectar-se ao servidor remoto
# $Session = New-PSSession -ComputerName "NomeDoServidor" -Credential $Credential
# Invoke-Command -Session $Session -ScriptBlock {
#     param($Username, $NewPassword)
#     # Alterar a senha do usuário
#     Set-ADAccountPassword -Identity $Username -NewPassword (ConvertTo-SecureString -AsPlainText $NewPassword -Force) -Reset
# } -ArgumentList $Username, "NovaSenha"
# Remove-PSSession $Session


# Function MakeCredential {
#     param($usrName, $pass)
#     $Username = $usrName
#     $Pword = ConvertTo-SecureString $pass -AsPlainText -Force
#     $Credential = New-Object System.Management.Automation.PSCredential($Username, $Pword)
#     return $Credential
# }



# Function OpenSession {
#     param($adServer)
#     $Session = New-PSSession -ComputerName $adServer -Credential (MakeCredential -usrName "nostopti\nostop" -pass "sMtp2020$&")
#     return $Session
# }

# OpenSession -adServer "Srvad10"

# Function SendCommand() {
#     Invoke-Command -Session $Session -ScriptBlock {
#         param($Username, $NewPassword)
#         # Alterar a senha do usuário
#         Set-ADAccountPassword -Identity $Username -NewPassword (ConvertTo-SecureString -AsPlainText $NewPassword -Force) -Reset
#     } -ArgumentList $Username, "NovaSenha"
#     Remove-PSSession $Session
# }