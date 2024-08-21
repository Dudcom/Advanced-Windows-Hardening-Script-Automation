$option = Read-Host '
1. WinPeas Scanning 
2. StickyKeyChecker (add checks for svol)
3. Firewall
4. Server GPMC Clean + Import
5. Find "sus" services 
6. Local User/Group Script 
7. Changing Passwords (CHANGE YOUR ADMIN PASS RIGHR AFTER RUNNING THIS)
8. AD User/Group Script (not working rip do yourself)
9. Services 
10.  
11. Post-Kitty Secuirty
12. Clean GPO (DO NOT RUN THIS ON REAL COMP ROUNDS)
13.
14. Find Schedualed Tasks 
15. AD User Config
17. System32 ACLs (dont run)
18. LDAP/ CA SSL Cert 
19. DNS & DHCP Sec 
20. 
21. Kitty Power AD
22. Kitty Power
23. Features Server
24. Enable RDP & Secure RDP
25. Config Imports  
26. IIS Sec (make sure to turn on custom error pages)
27. Blueteam Persitence Sniper
28. Update Software 
29. BPA Scan 
30. SQL Hardening 
31. PowerShell Hardening (Do At the End XD)
32. RID Hijacking Test
33. Detect Hidden Windows Tasks 
34. BitsAdmin Job Check
35. ACL Perms Tool
36. AD SEC 
37. ChatGPT  
38. Remove User Dirs (li too funny)
39. Remove unsigned/nonsecure dlls
40. Find all unsigned File 
 '

# Beeeeeeg secure script
$Error.Clear()
$ErrorActionPreference = "Continue"

# DC detection
$DC = $false
if (Get-CimInstance -Class Win32_OperatingSystem -Filter 'ProductType = "2"') {
    $DC = $true
}

# IIS detection
$IIS = $false
if (Get-Service -Name W3SVC 2>$null) {
    $IIS = $true
}

if ($option -eq 1){
    REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1
    .\winPEASx64.exe log 
}

if ($option -eq 12){
Remove-Item -Recurse -Force "$env:WinDir\System32\GroupPolicy" | Out-Null
Remove-Item -Recurse -Force "$env:WinDir\System32\GroupPolicyUsers" | Out-Null
secedit /configure /cfg "$env:WinDir\inf\defltbase.inf" /db defltbase.sdb /verbose | Out-Null
gpupdate /force
}

if ($option -eq 2){
    Write-Host

    $cmdHash = Get-FileHash -LiteralPath $env:windir\System32\cmd.exe
    $psHash = Get-FileHash -LiteralPath $env:windir\System32\WindowsPowerShell\v1.0\powershell.exe
    $explorerHash = Get-FileHash -LiteralPath $env:windir\explorer.exe
    $sethcHash = Get-FileHash -LiteralPath $env:windir\System32\sethc.exe
    $oskHash = Get-FileHash -LiteralPath $env:windir\System32\osk.exe
    $narratorHash = Get-FileHash -LiteralPath $env:windir\System32\Narrator.exe
    $magnifyHash = Get-FileHash -LiteralPath $env:windir\System32\Magnify.exe
    $displayswitchHash = Get-FileHash -LiteralPath $env:windir\System32\DisplaySwitch.exe

    if ($cmdHash.Hash -eq $sethcHash.Hash) {

        Write-Output "Possible backdoor found. sethc.exe replaced with cmd.exe"
        Write-Host
        Write-Output "Checked the following hashes:"
        Write-Output "cmd.exe: $($cmdHash.Hash)"
        Write-Output "sethc.exe: $($sethcHash.Hash)"
        Write-Host

        } 

    if ($explorerHash.Hash -eq $sethcHash.Hash) {

        Write-Output "Possible backdoor found. sethc.exe replaced with explorer.exe"
        Write-Host
        Write-Output "Checked the following hashes:"
        Write-Output "explorer.exe: $($explorerHash.Hash)"
        Write-Output "sethc.exe: $($sethcHash.Hash)"
        Write-Host

        } 

    if ($psHash.Hash -eq $sethcHash.Hash) {

        Write-Output "Possible backdoor found. sethc.exe replaced with powershell.exe"
        Write-Host
        Write-Output "Checked the following hashes:"
        Write-Output "powershell.exe: $($psHash.Hash)"
        Write-Output "sethc.exe: $($sethcHash.Hash)"
        Write-Host

        } 

    if ($cmdHash.Hash -eq $oskHash.Hash) {

        Write-Output "Possible backdoor found. osk.exe replaced with cmd.exe"
        Write-Host
        Write-Output "Checked the following hashes:"
        Write-Output "cmd.exe: $($cmdHash.Hash)"
        Write-Output "osk.exe: $($oskHash.Hash)"
        Write-Host

        } 

    if ($explorerHash.Hash -eq $oskHash.Hash) {

        Write-Output "Possible backdoor found. osk.exe replaced with explorer.exe"
        Write-Host
        Write-Output "Checked the following hashes:"
        Write-Output "explorer.exe: $($explorerHash.Hash)"
        Write-Output "osk.exe: $($oskHash.Hash)"
        Write-Host

        } 

    if ($psHash.Hash -eq $oskHash.Hash) {

        Write-Output "Possible backdoor found. osk.exe replaced with powershell.exe"
        Write-Host
        Write-Output "Checked the following hashes:"
        Write-Output "powershell.exe: $($psHash.Hash)"
        Write-Output "osk.exe: $($oskHash.Hash)"
        Write-Host

        } 

    if ($cmdHash.Hash -eq $narratorHash.Hash) {

        Write-Output "Possible backdoor found. narrator.exe replaced with cmd.exe"
        Write-Host
        Write-Output "Checked the following hashes:"
        Write-Output "cmd.exe: $($cmdHash.Hash)"
        Write-Output "narrator.exe: $($narrator.Hash)"
        Write-Host

        }

    if ($explorerHash.Hash -eq $narratorHash.Hash) {

        Write-Output "Possible backdoor found. narrator.exe replaced with explorer.exe"
        Write-Host
        Write-Output "Checked the following hashes:"
        Write-Output "explorer.exe: $($explorerHash.Hash)"
        Write-Output "narrator.exe: $($narratorHash.Hash)"
        Write-Host

        } 

    if ($psHash.Hash -eq $narratorHash.Hash) {

        Write-Output "Possible backdoor found. narrator.exe replaced with powershell.exe"
        Write-Host
        Write-Output "Checked the following hashes:"
        Write-Output "powershell.exe: $($psHash.Hash)"
        Write-Output "narrator.exe: $($oskHash.Hash)"
        Write-Host

        } 

    if ($cmdHash.Hash -eq $magnifyHash.Hash) {

        Write-Output "Possible backdoor found. magnify.exe replaced with powershell.exe"
        Write-Host
        Write-Output "Checked the following hashes:"
        Write-Output "cmd.exe: $($cmdHash.Hash)"
        Write-Output "magnify.exe: $($magnifyHash.Hash)"
        Write-Host

        } 

     if ($explorerHash.Hash -eq $magnifycHash.Hash) {

        Write-Output "Possible backdoor found. sethc.exe replaced with explorer.exe"
        Write-Host
        Write-Output "Checked the following hashes:"
        Write-Output "explorer.exe: $($explorerHash.Hash)"
        Write-Output "magnify.exe: $($magnifyHash.Hash)"
        Write-Host

        } 

    if ($psHash.Hash -eq $magnifyHash.Hash) {

        Write-Output "Possible backdoor found. magnify.exe replaced with powershell.exe"
        Write-Host
        Write-Output "Checked the following hashes:"
        Write-Output "powershell.exe: $($psHash.Hash)"
        Write-Output "magnify.exe: $($magnifyHash.Hash)"
        Write-Host

        } 

    if ($cmdHash.Hash -eq $displayswitchHash.Hash) {

        Write-Output "Possible backdoor found. displayswitch.exe replaced with powershell.exe"
        Write-Host
        Write-Output "Checked the following hashes:"
        Write-Output "cmd.exe: $($cmdHash.Hash)"
        Write-Output "displayswitch.exe: $($displayswitchHash.Hash)"
        Write-Host

        } 

    if ($explorerHash.Hash -eq $displayswitchHash.Hash) {

        Write-Output "Possible backdoor found. displayswitch.exe replaced with explorer.exe"
        Write-Host
        Write-Output "Checked the following hashes:"
        Write-Output "explorer.exe: $($explorerHash.Hash)"
        Write-Output "displayswitch.exe: $($displayswitchHash.Hash)"
        Write-Host

        } 

    if ($psHash.Hash -eq $displayswitchHash.Hash) {

        Write-Output "Possible backdoor found. displayswitch.exe replaced with powershell.exe"
        Write-Host
        Write-Output "Checked the following hashes:"
        Write-Output "powershell.exe: $($psHash.Hash)"
        Write-Output "displayswitch.exe: $($magnifyHash.Hash)"
        Write-Host

        } 

    $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\'
    $nameSethc = 'sethc.exe'
    $nameUtilman = 'utilman.exe'
    $property = 'Debugger'

    if (Test-Path -LiteralPath ($key + $nameSethc)) {
          
          $tb = Get-Item -LiteralPath ($key + $nameSethc)
          
          if ($tb.GetValue($property) -ne $null) {

                Write-Output "Possible backdoor identified at:"
                Get-Item -LiteralPath ($key + $nameSethc)
                Write-Output ""
                Write-Output "Investigate to determine if value of Debugger property set to system-level shell 
                - e.g., cmd.exe"
                Write-Host
            
            }

    }

    if (Test-Path -LiteralPath ($key + $nameUtilman)) {
          
          $tb = Get-Item -LiteralPath ($key + $nameUtilman)
          
          if ($tb.GetValue($property) -ne $null) {

                Write-Output "Possible backdoor identified at:"
                Get-Item -LiteralPath ($key + $nameUtilman)
                Write-Output ""
                Write-Output "Investigate to determine if value of Debugger property set to system-level shell 
                - e.g., cmd.exe"
                Write-Host
            
            }

    }
}

if ($option -eq 3){
    Write-Warning "Setting up firewall and configuring..."
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    Set-NetFirewallProfile -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen True -AllowUnicastResponseToMulticast True -LogFileName %SystemRoot%\System32\logfiles\firewall\domainfw.log
    Set-NetFirewallProfile -LogBlocked True -LogMaxSizeKilobytes 16384 -LogAllowed True
    Set-NetFirewallProfile -Name Public -AllowLocalFirewallRules False
    netsh advfirewall import "C:\Users\$user\Desktop\CyberPatriot-Windows-Scripts\Win10Firewall.wfw"
    netsh advfirewall firewall set rule name="netcat" new enable=no
    netsh advfirewall firewall set rule name="Remote Assistance (DCOM-In)" new enable=no 
    netsh advfirewall firewall set rule name="Remote Assistance (PNRP-In)" new enable=no 
    netsh advfirewall firewall set rule name="Remote Assistance (RA Server TCP-In)" new enable=no 
    netsh advfirewall firewall set rule name="Remote Assistance (SSDP TCP-In)" new enable=no 
    netsh advfirewall firewall set rule name="Remote Assistance (SSDP UDP-In)" new enable=no 
    netsh advfirewall firewall set rule name="Remote Assistance (TCP-In)" new enable=no 
    netsh advfirewall firewall set rule name="Telnet Server" new enable=no
    #disabling network discovery
    netsh advfirewall firewall set rule group="Network Discovery" new enable=No
    #disabling file and printer sharing
    netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=No

    netsh advfirewall firewall add rule name="block_RemoteRegistry_in" dir=in service="RemoteRegistry" action=block enable=yes
    netsh advfirewall firewall add rule name="block_RemoteRegistry_out" dir=out service="RemoteRegistry" action=block enable=yes
    
    New-NetFirewallRule -DisplayName "ftpTCP" -Direction Inbound -LocalPort 21 -Protocol TCP -Action Block
    New-NetFirewallRule -DisplayName "sshTCP" -Direction Inbound -LocalPort 22 -Protocol TCP -Action Block
    New-NetFirewallRule -DisplayName "telnetTCP" -Direction Inbound -LocalPort 23 -Protocol TCP -Action Block
    New-NetFirewallRule -DisplayName "SMTPTCP" -Direction Inbound -LocalPort 25 -Protocol TCP -Action Block
    New-NetFirewallRule -DisplayName "POP3TCP" -Direction Inbound -LocalPort 110 -Protocol TCP -Action Block
    New-NetFirewallRule -DisplayName "RDPTCP" -Direction Inbound -LocalPort 3389 -Protocol TCP -Action Block
    New-NetFirewallRule -DisplayName "SNMPTCP" -Direction Inbound -LocalPort 161 -Protocol TCP -Action Block
    netsh advfirewall firewall add rule name="Block appvlp.exe netconns" program="C:\Program Files (x86)\Microsoft Office\root\client\AppVLP.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block appvlp.exe netconns" program="C:\Program Files\Microsoft Office\root\client\AppVLP.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block calc.exe netconns" program="%systemroot%\system32\calc.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block calc.exe netconns" program="%systemroot%\SysWOW64\calc.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block certutil.exe netconns" program="%systemroot%\system32\certutil.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block certutil.exe netconns" program="%systemroot%\SysWOW64\certutil.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block cmstp.exe netconns" program="%systemroot%\system32\cmstp.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block cmstp.exe netconns" program="%systemroot%\SysWOW64\cmstp.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block cscript.exe netconns" program="%systemroot%\system32\cscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block cscript.exe netconns" program="%systemroot%\SysWOW64\cscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block esentutl.exe netconns" program="%systemroot%\system32\esentutl.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block esentutl.exe netconns" program="%systemroot%\SysWOW64\esentutl.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block expand.exe netconns" program="%systemroot%\system32\expand.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block expand.exe netconns" program="%systemroot%\SysWOW64\expand.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block extrac32.exe netconns" program="%systemroot%\system32\extrac32.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block extrac32.exe netconns" program="%systemroot%\SysWOW64\extrac32.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block findstr.exe netconns" program="%systemroot%\system32\findstr.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block findstr.exe netconns" program="%systemroot%\SysWOW64\findstr.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block hh.exe netconns" program="%systemroot%\system32\hh.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block hh.exe netconns" program="%systemroot%\SysWOW64\hh.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block makecab.exe netconns" program="%systemroot%\system32\makecab.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block makecab.exe netconns" program="%systemroot%\SysWOW64\makecab.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block mshta.exe netconns" program="%systemroot%\system32\mshta.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block mshta.exe netconns" program="%systemroot%\SysWOW64\mshta.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block msiexec.exe netconns" program="%systemroot%\system32\msiexec.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block msiexec.exe netconns" program="%systemroot%\SysWOW64\msiexec.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block nltest.exe netconns" program="%systemroot%\system32\nltest.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block nltest.exe netconns" program="%systemroot%\SysWOW64\nltest.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block Notepad.exe netconns" program="%systemroot%\system32\notepad.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block Notepad.exe netconns" program="%systemroot%\SysWOW64\notepad.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block odbcconf.exe netconns" program="%systemroot%\system32\odbcconf.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block odbcconf.exe netconns" program="%systemroot%\SysWOW64\odbcconf.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block pcalua.exe netconns" program="%systemroot%\system32\pcalua.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block pcalua.exe netconns" program="%systemroot%\SysWOW64\pcalua.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block regasm.exe netconns" program="%systemroot%\system32\regasm.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block regasm.exe netconns" program="%systemroot%\SysWOW64\regasm.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block regsvr32.exe netconns" program="%systemroot%\system32\regsvr32.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block regsvr32.exe netconns" program="%systemroot%\SysWOW64\regsvr32.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block replace.exe netconns" program="%systemroot%\system32\replace.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block replace.exe netconns" program="%systemroot%\SysWOW64\replace.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block rpcping.exe netconns" program="%systemroot%\SysWOW64\rpcping.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block rundll32.exe netconns" program="%systemroot%\system32\rundll32.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block rundll32.exe netconns" program="%systemroot%\SysWOW64\rundll32.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block runscripthelper.exe netconns" program="%systemroot%\system32\runscripthelper.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block runscripthelper.exe netconns" program="%systemroot%\SysWOW64\runscripthelper.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block scriptrunner.exe netconns" program="%systemroot%\system32\scriptrunner.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block scriptrunner.exe netconns" program="%systemroot%\SysWOW64\scriptrunner.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block SyncAppvPublishingServer.exe netconns" program="%systemroot%\system32\SyncAppvPublishingServer.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block SyncAppvPublishingServer.exe netconns" program="%systemroot%\SysWOW64\SyncAppvPublishingServer.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block wmic.exe netconns" program="%systemroot%\system32\wbem\wmic.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block wmic.exe netconns" program="%systemroot%\SysWOW64\wbem\wmic.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block wscript.exe netconns" program="%systemroot%\system32\wscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block wscript.exe netconns" program="%systemroot%\SysWOW64\wscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
    #Firewall script
    #Disable every pre-existing rule
    Set-NetFirewallRule * -Enabled False -Action NotConfigured

    #Block multiple Windows features by pre-existing rules
    Set-NetFirewallRule -DisplayGroup "AllJoyn Router","*BranchCache*","Cast to Device functionality","Connect","Cortana","Delivery Optimization","DIAL protocol server","Feedback Hub","File and Printer Sharing","Get Office","Groove Music","HomeGroup","iSCSI Service","mDNS","Media Center Extenders","Microsoft Edge","Microsoft Photos","Microsoft Solitaire Collection","Movies & TV","MSN Weather","Network Discovery","OneNote","*Wi-Fi*","Paint 3D","Proximity Sharing","*Remote*","Secure Socket Tunneling Protocol","*Skype*","SNMP Trap","Store","*Smart Card*","Virtual Machine Monitoring","Windows Collaboration Computer Name Registration Service","*Windows Media Player*","Windows Peer to Peer Collaboration Foundation","Windows View 3D Preview","*Wireless*","*WFD*","*Xbox*","3D Builder","Captive Portal Flow","Take a Test","Wallet" -Action Block -Enabled True -Profile Any

    #Block multiple insecure protocols by pre-existing rules
    Set-NetFirewallRule -DisplayName "*IPv6*","*ICMP*","*SMB*","*UPnP*","*FTP*","*Telnet*" -Action Block -Enabled True -Profile Any

    #Block multiple ports with new rule
    New-NetFirewallRule -DisplayName "FTP, SSH, Telnet" -LocalPort 20-21 -Protocol TCP -Action Block -Enabled True -Direction Inbound
    New-NetFirewallRule -DisplayName "FTP, SSH, Telnet" -LocalPort 22 -Protocol TCP -Action Block -Enabled True -Direction Inbound
    New-NetFirewallRule -DisplayName "FTP, SSH, Telnet" -LocalPort 23 -Protocol TCP -Action Block -Enabled True -Direction Inbound
    New-NetFirewallRule -DisplayName "HTTP" -LocalPort 80 -Protocol TCP -Action Block -Enabled True -Direction Inbound

    #Block multiple protocols with new rule
    New-NetFirewallRule -DisplayName "ICMPv4" -Protocol ICMPv4 -Action Block -Enabled True -Direction Inbound -Profile Any
    New-NetFirewallRule -DisplayName "ICMPv4" -Protocol ICMPv4 -Action Block -Enabled True -Direction Outbound -Profile Any
    New-NetFirewallRule -DisplayName "ICMPv6" -Protocol ICMPv6 -Action Block -Enabled True -Direction Inbound -Profile Any
    New-NetFirewallRule -DisplayName "ICMPv6" -Protocol ICMPv6 -Action Block -Enabled True -Direction Outbound -Profile Any

    #Allow multiple ports with new rule
    New-NetFirewallRule -DisplayName "HTTPS" -LocalPort 443 -Protocol TCP -Action Allow -Enabled True -Direction Outbound
    New-NetFirewallRule -DisplayName "NTP" -LocalPort 123 -Protocol UDP -Action Allow -Enabled True -Direction Outbound
    New-NetFirewallRule -DisplayName "NTP" -LocalPort 123 -Protocol UDP -Action Allow -Enabled True -Direction Inbound

    #Allow multiple features with pre-existing rules
    Set-NetFirewallRule -DisplayName "*Defender*" -Enabled True -Action Allow -Profile Any
}

if ($option -eq 4){
    Install-Module -Name GroupPolicy -Force
    Install-WindowsFeature GPMC
    $computers = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name

    foreach ($computer in $computers) {Invoke-Command -ComputerName $computer -ScriptBlock ${function:CleantheGPO}}

    # Define variables
    $GPOName = "NewSimpleSecureGPO"
    $BackupPath = "C:\Users\Tanush\Desktop\E-citadel-troy-windows-scripts\Config Files\{BD711AA4-7448-4C04-920D-D8EDB69F05E5}"

    # Import the GroupPolicy module
    Import-Module GroupPolicy

    # Create a new GPO
    $NewGPO = New-GPO -Name $GPOName

    # Import settings from the backup
    Import-GPO -Path $BackupPath -TargetName $GPOName -BackupGpoName $GPOName
}

function CleantheGPO {

$GPOs = get-gpo -ALL
foreach ($GPO in $GPOs) {
    $GPO.GpoStatus = "AllSettingsDisabled"
    
    Write-Output "GPO $($GPO.DisplayName) status set to AllSettingsDisabled"
}
gpupdate /force
}

if ($option -eq 5){
# Function to check if the service's binary path is suspicious
function IsSuspiciousPath($path) {
    return ($path -like "C:\Users\*")
}

# Function to check if the service's binary is unsigned
function IsUnsigned($path) {
    try {
        $Signatures = Get-AuthenticodeSignature -FilePath $path
        return ($Signatures.Status -ne "Valid")
    }
    catch {
        return $true
    }
}

# Function to calculate the entropy of a string
function CalculateEntropy($input) {
    $inputChars = $input.ToCharArray()
    $charCount = $inputChars.Length
    $charFrequency = @{}

    foreach ($char in $inputChars) {
        $charFrequency[$char]++
    }

    [double]$entropy = 0

    foreach ($frequency in $charFrequency.Values) {
        $probability = $frequency / $charCount
        $entropy -= $probability * [Math]::Log($probability, 2)
    }

    return $entropy
}

# Function to check if the service has a high entropy name
function IsHighEntropyName($name) {
    $entropy = CalculateEntropy($name)
    return ($entropy -gt 3.5)
}

# Function to check if the service has a suspicious file extension
function HasSuspiciousExtension($path) {
    $suspiciousExtensions = @('.vbs', '.js', '.bat', '.cmd', '.scr')
    $extension = [IO.Path]::GetExtension($path)
    return ($suspiciousExtensions -contains $extension)
}

# Prompt the user to enable or disable checks more likely to result in false positives
$enableExtraChecks = Read-Host "Enable checks more likely to result in false positives? (yes/no)"
$extraChecks = $enableExtraChecks -eq "yes"

# Get all services on the local machine
$AllServices = Get-WmiObject -Class Win32_Service

# Create an empty array to store detected suspicious services
$DetectedServices = New-Object System.Collections.ArrayList

# Iterate through all services
foreach ($Service in $AllServices) {
    $BinaryPathName = $Service.PathName.Trim('"')

    # Check for suspicious characteristics
    $PathSuspicious = IsSuspiciousPath($BinaryPathName)
    $LocalSystemAccount = ($Service.StartName -eq "LocalSystem")
    $NoDescription = ([string]::IsNullOrEmpty($Service.Description))
    $Unsigned = IsUnsigned($BinaryPathName)

    $ShortName = $false
    $ShortDisplayName = $false
    $HighEntropyName = $false
    $HighEntropyDisplayName = $false
    $SuspiciousExtension = $false

    if ($extraChecks) {
        $ShortName = ($Service.Name.Length -le 5)
        $ShortDisplayName = ($Service.DisplayName.Length -le 5)
        $HighEntropyName = IsHighEntropyName($Service.Name)
        $HighEntropyDisplayName = IsHighEntropyName($Service.DisplayName)
        $SuspiciousExtension = HasSuspiciousExtension($BinaryPathName)
    }

    # If any of the suspicious characteristics are found, add the service to the list of detected services
    if ($PathSuspicious -or $LocalSystemAccount -or $NoDescription -or $Unsigned -or $ShortName -or $ShortDisplayName -or $HighEntropyName -or $HighEntropyDisplayName -or $SuspiciousExtension) {
        $DetectedServices.Add($Service) | Out-Null
    }
}

# Output the results
if ($DetectedServices.Count -gt 0) {
    Write-Host "Potentially Suspicious Services Detected"
    Write-Host "----------------------------------------"
    foreach ($Service in $DetectedServices) {
        Write-Host "Name: $($Service.Name) - Display Name: $($Service.DisplayName) - Status: $($Service.State) - StartName: $($Service.StartName) - Description: $($Service.Description) - Binary Path: $($Service.PathName.Trim('"'))"

        # Output verbose information about each suspicious characteristic
        if ($PathSuspicious) {
            Write-Host "`t- Running from a potentially suspicious path"
        }
        if ($LocalSystemAccount) {
            Write-Host "`t- Running with a LocalSystem account"
        }
        if ($NoDescription) {
            Write-Host "`t- No description provided"
        }
        if ($Unsigned) {
            Write-Host "`t- Unsigned executable"
        }
        if ($ShortName) {
            Write-Host "`t- Very short service name"
        }
        if ($ShortDisplayName) {
            Write-Host "`t- Very short display name"
        }
        if ($HighEntropyName) {
            Write-Host "`t- High entropy service name"
        }
        if ($HighEntropyDisplayName) {
            Write-Host "`t- High entropy display name"
        }
        if ($SuspiciousExtension) {
            Write-Host "`t- Suspicious file extension"
        }
        Write-Host ""
    }
} else {
    Write-Host "No potentially suspicious services detected."
}
}

if ($option -eq 6){
Get-ChildItem -Path "HKLM:\SAM\SAM\Domains\Account" -Recurse | ForEach-Object { $acl = Get-Acl $_.PSPath; $acl.SetAccessRuleProtection($false, $true); Set-Acl -Path $_.PSPath -AclObject $acl }

# Read the file
$lines = Get-Content "usersdo.txt"
$currentGroup = $null

foreach ($line in $lines) {
    # Check for 'END' to reset the current group
    if ($line -eq "END") {
        $currentGroup = $null
        continue
    }

    if (-not $currentGroup) {
        $currentGroup = $line
        # Check if the group exists
        try {
            $groupExists = Get-LocalGroup -Name $currentGroup -ErrorAction Stop
        } catch {
            Write-Host "Group '$currentGroup' not found. Creating new group."
            New-LocalGroup -Name $currentGroup -ErrorAction Stop | Out-Null
            continue
        }

        # Remove all users from the group if it exists
        Get-LocalGroupMember -Group $currentGroup -ErrorAction SilentlyContinue | Remove-LocalGroupMember -Group $currentGroup -ErrorAction SilentlyContinue
    } else {
        # Skip system accounts (starting with "NT")
        if ($line.StartsWith("NT")) {
            continue
        }

        # Check if user exists
        $userExists = Get-LocalUser -Name $line -ErrorAction SilentlyContinue
        if (-not $userExists) {
            # Create new user with default password
            try {
                $password = ConvertTo-SecureString "password" -AsPlainText -Force
                New-LocalUser -Name $line -Password $password -ErrorAction Stop | Out-Null
                Write-Host "User '$line' created."
            } catch {
                Write-Host "Error creating user '$line': $_"
                continue
            }
        }

        # Add user to the current group
        try {
            Add-LocalGroupMember -Group $currentGroup -Member $line -ErrorAction Stop
	    Enable-LocalUser -Name $line
        } catch {
            Write-Host "Error adding user '$line' to group '$currentGroup': $_"
        }
    }
}

}

if ($option -eq 7){
    Write-Host "Changing local passwords..." -ForegroundColor Gray
    try {
        $userList = @()
        $users = Get-LocalUser
        foreach ($user in $users) {
            $newPassword = -join ((33..126) | Get-Random -Count 16 | Foreach-Object {[char]$_})
            $user | Set-LocalUser -Password (ConvertTo-SecureString -AsPlainText $newPassword -Force)
            $user | Set-LocalUser -PasswordNeverExpires $false -UserMayChangePassword $true 
        
    
        }
    
    }
    catch {
        Write-Output "$Error[0] $_" | Out-File "C:\Program Files\ezScript\localPass"
        Write-Host "Writing error to file" -ForegroundColor DarkYellow
    }
    Write-Warning "Disabling Guest and Admin accounts"
    Get-LocalUser Guest | Disable-LocalUser
    Get-LocalUser Administrator | Disable-LocalUser
    Write-Warning "Renaming guest and admin account SuperBOIs && MiniBOIs"
    $adminAccount =Get-WMIObject Win32_UserAccount -Filter "Name='Administrator'"
    $result =$adminAccount.Rename("SuperBOIs")
    $guestAccount =Get-WMIObject Win32_UserAccount -Filter "Name='Guest'"
    $result =$guestAccount.Rename("MiniBOIs")
}

if ($option -eq 8){
    Import-Module ActiveDirectory

    # Read the file
    $lines = Get-Content "usersad.txt"
    $currentGroup = $null
    
    foreach ($line in $lines) {
        # Check for 'END' to reset the current group
        if ($line -eq "END") {
            $currentGroup = $null
            continue
        }
    
        if (-not $currentGroup) {
            $currentGroup = $line
            # Check if the group exists in AD
            try {
                $groupExists = Get-ADGroup -Identity $currentGroup -ErrorAction Stop
            } catch {
                Write-Host "AD group '$currentGroup' not found. Creating new group."
                New-ADGroup -Name $currentGroup -GroupScope Global -ErrorAction Stop | Out-Null
                continue
            }
    
            # Check and clear the ManagedBy attribute if it is another group
            if ($groupExists.ManagedBy) {
                $managedByObject = Get-ADObject -Identity $groupExists.ManagedBy -Properties objectClass -ErrorAction SilentlyContinue
                if ($managedByObject.objectClass -eq "group") {
                    Set-ADGroup -Identity $currentGroup -Clear ManagedBy
                    Write-Host "Cleared management delegation from group '$currentGroup' because it was managed by another group."
                }
            }
    
            # Remove all users from the group if it exists
            Get-ADGroupMember -Identity $currentGroup -ErrorAction SilentlyContinue | ForEach-Object {
                Remove-ADGroupMember -Identity $currentGroup -Members $_ -Confirm:$false -ErrorAction SilentlyContinue
            }
        } else {
            # Skip system accounts (starting with "NT")
            if ($line.StartsWith("NT")) {
                continue
            }
    
            # Check if user exists in AD
            try {
                $userExists = Get-ADUser -Identity $line -ErrorAction Stop
            } catch {
                # Create new AD user with default password
                $password = ConvertTo-SecureString "password" -AsPlainText -Force
                New-ADUser -Name $line -AccountPassword $password -Enabled $true -ErrorAction Stop | Out-Null
                Write-Host "AD user '$line' created."
            }
    
            # Add user to the current group
            try {
                Add-ADGroupMember -Identity $currentGroup -Members $line -ErrorAction Stop
            } catch {
                Write-Host "Error adding AD user '$line' to group '$currentGroup': $_"
            }
        }
    }
    
}

if ($option -eq 9){
    Service -Name "iphlpsvc" -Status stopped -StartupType disabled
    Stop-Service -Name "iphlpsvc"
    Service -Name "SNMPTRAP" -Status stopped -StartupType disabled
    Stop-Service -Name "SNMPTRAP"
    Write-Warning "Disabling ActiveX, Adobe Acrobat,Fax,HomeGroup Listener,HomeGroup Provider,IP helper,Remote Registry,Server,Teamviewer 10, SNMP, Telnet, T FTP, PS3 Media Server, FTP, LDAP, RDP, ICS, IIS, RPC Locator, Message Queuing, Telephony, HTTP Explorer, WWW Publishing"
    $services = "ActiveX","Adobe Acrobat","Fax","HomeGroup Listener","HomeGroup Provider","IP helper","Remote Registry","Server","Teamviewer 10","SNMP", "Telnet", "T FTP", "PS3 Media Server", "FTP", "LDAP", "RDP", "ICS", "IIS", "RPC Locator", "Message Queuing", "Telephony", "HTTP Explorer", "WWW Publishing"
    foreach($s in $services) {
        Set-Service $s -StartupType Disabled
        Stop-Service $s
    }
    Stop-Service W3SVC
    Set-Service W3SVC -StartupType Disabled
    Stop-Service Spooler
    Set-Service Spooler -StartupType Disabled
    Stop-Service RemoteRegistry 
    Set-Service RemoteRegistry -StartupType Disabled
    Stop-Service LanmanServer
    Set-Service LanmanServer -StartupType Disabled
    Stop-Service SNMPTRAP
    Set-Service SNMPTRAP -StartupType Disabled
    Stop-Service SSDPSRV
    Set-Service SSDPSRV -StartupType Disabled
    Stop-Service lmhosts
    Set-Service lmhosts -StartupType Disabled
    Stop-Service TapiSrv
    Set-Service TapiSrv -StartupType Disabled
    Stop-Service upnphost
    Set-Service upnphost -StartupType Disabled
    #Disable more unneeded/insecure services
	Set-Service -Status Stopped -StartupType Disabled -Name Browser
	Set-Service -Status Stopped -StartupType Disabled -Name bthserv
	Set-Service -Status Stopped -StartupType Disabled -Name Fax
	Set-Service -Status Stopped -StartupType Disabled -Name icssvc
	Set-Service -Status Stopped -StartupType Disabled -Name irmon
	Set-Service -Status Stopped -StartupType Disabled -Name lfsvc
	Set-Service -Status Stopped -StartupType Disabled -Name lltdsvc
	Set-Service -Status Stopped -StartupType Disabled -Name MapsBroker
	Set-Service -Status Stopped -StartupType Disabled -Name MSiSCSI
	Set-Service -Status Stopped -StartupType Disabled -Name p2pimsvc
	Set-Service -Status Stopped -StartupType Disabled -Name p2psvc
	Set-Service -Status Stopped -StartupType Disabled -Name PhoneSvc
	Set-Service -Status Stopped -StartupType Disabled -Name PlugPlay
	Set-Service -Status Stopped -StartupType Disabled -Name PNRPAutoReg
	Set-Service -Status Stopped -StartupType Disabled -Name PNRPsvc
	Set-Service -Status Stopped -StartupType Disabled -Name RasAuto
	Set-Service -Status Stopped -StartupType Disabled -Name RemoteAccess
	Set-Service -Status Stopped -StartupType Disabled -Name RemoteRegistry
	Set-Service -Status Stopped -StartupType Disabled -Name RpcLocator
	Set-Service -Status Stopped -StartupType Disabled -Name SessionEnv
	Set-Service -Status Stopped -StartupType Disabled -Name SharedAccess
	Set-Service -Status Stopped -StartupType Disabled -Name SNMPTRAP
	Set-Service -Status Stopped -StartupType Disabled -Name SSDPSRV
	Set-Service -Status Stopped -StartupType Disabled -Name TermService
	Set-Service -Status Stopped -StartupType Disabled -Name UmRdpService
	Set-Service -Status Stopped -StartupType Disabled -Name upnphost
	Set-Service -Status Stopped -StartupType Disabled -Name vmicrdv
	Set-Service -Status Stopped -StartupType Disabled -Name W32Time
	Set-Service -Status Stopped -StartupType Disabled -Name W3SVC
	Set-Service -Status Stopped -StartupType Disabled -Name wercplsupport
	Set-Service -Status Stopped -StartupType Disabled -Name WerSvc
	Set-Service -Status Stopped -StartupType Disabled -Name WinHttpAutoProxySvc
	Set-Service -Status Stopped -StartupType Disabled -Name WinRM
	Set-Service -Status Stopped -StartupType Disabled -Name WlanSvc
	Set-Service -Status Stopped -StartupType Disabled -Name WMPNetworkSvc
	Set-Service -Status Stopped -StartupType Disabled -Name WpnService
	Set-Service -Status Stopped -StartupType Disabled -Name WpnUserService*
	Set-Service -Status Stopped -StartupType Disabled -Name WwanSvc
	Set-Service -Status Stopped -StartupType Disabled -Name xbgm
	Set-Service -Status Stopped -StartupType Disabled -Name XblAuthManager
	Set-Service -Status Stopped -StartupType Disabled -Name XblGameSave
	Set-Service -Status Stopped -StartupType Disabled -Name XboxGipSvc
	Set-Service -Status Stopped -StartupType Disabled -Name XboxNetApiSvc
	Set-Service -Status Stopped -StartupType Disabled -Name PushToInstall
	Set-Service -Status Stopped -StartupType Disabled -Name spectrum
	Set-Service -Status Stopped -StartupType Disabled -Name icssvc
	Set-Service -Status Stopped -StartupType Disabled -Name wisvc
	Set-Service -Status Stopped -StartupType Disabled -Name StiSvc
	Set-Service -Status Stopped -StartupType Disabled -Name FrameServer
	Set-Service -Status Stopped -StartupType Disabled -Name WbioSrvc
	Set-Service -Status Stopped -StartupType Disabled -Name WFDSConSvc
	Set-Service -Status Stopped -StartupType Disabled -Name WebClient
	Set-Service -Status Stopped -StartupType Disabled -Name WMSVC
	Set-Service -Status Stopped -StartupType Disabled -Name WalletService
	Set-Service -Status Stopped -StartupType Disabled -Name UevAgentService
	Set-Service -Status Stopped -StartupType Disabled -Name UwfServcingSvc
	Set-Service -Status Stopped -StartupType Disabled -Name TabletInputService
	Set-Service -Status Stopped -StartupType Disabled -Name TapiSrv
	Set-Service -Status Stopped -StartupType Disabled -Name WiaRpc
	Set-Service -Status Stopped -StartupType Disabled -Name SharedRealitySvc
	Set-Service -Status Stopped -StartupType Disabled -Name SNMP
	Set-Service -Status Stopped -StartupType Disabled -Name SCPolicySvc
	Set-Service -Status Stopped -StartupType Disabled -Name ScDeviceEnum
	Set-Service -Status Stopped -StartupType Disabled -Name simptcp
	Set-Service -Status Stopped -StartupType Disabled -Name ShellHWDetection
	Set-Service -Status Stopped -StartupType Disabled -Name shpamsvc
	Set-Service -Status Stopped -StartupType Disabled -Name SensorService
	Set-Service -Status Stopped -StartupType Disabled -Name SensrSvc
	Set-Service -Status Stopped -StartupType Disabled -Name SensorDataService
	Set-Service -Status Stopped -StartupType Disabled -Name SstpSvc
	Set-Service -Status Stopped -StartupType Disabled -Name iprip
	Set-Service -Status Stopped -StartupType Disabled -Name RetailDemo
	Set-Service -Status Stopped -StartupType Disabled -Name RasMan
	Set-Service -Status Stopped -StartupType Disabled -Name RmSvc
	Set-Service -Status Stopped -StartupType Disabled -Name PrintNotify
	Set-Service -Status Stopped -StartupType Disabled -Name WpcMonSvc
	Set-Service -Status Stopped -StartupType Disabled -Name SEMgrSvc
	Set-Service -Status Stopped -StartupType Disabled -Name CscService
	Set-Service -Status Stopped -StartupType Disabled -Name NcaSVC
	Set-Service -Status Stopped -StartupType Disabled -Name NcbService
	Set-Service -Status Stopped -StartupType Disabled -Name NcdAutoSetup
	Set-Service -Status Stopped -StartupType Disabled -Name Netlogon
	Set-Service -Status Stopped -StartupType Disabled -Name NetTcpPortSharing
	Set-Service -Status Stopped -StartupType Disabled -Name NetTcpActivator
	Set-Service -Status Stopped -StartupType Disabled -Name NetMsmqActivator
	Set-Service -Status Stopped -StartupType Disabled -Name Wms
	Set-Service -Status Stopped -StartupType Disabled -Name WmsRepair
	Set-Service -Status Stopped -StartupType Disabled -Name SmsRouter
	Set-Service -Status Stopped -StartupType Disabled -Name MsKeyboardFilter
	Set-Service -Status Stopped -StartupType Disabled -Name ftpsvc
	Set-Service -Status Stopped -StartupType Disabled -Name AppVClient
	Set-Service -Status Stopped -StartupType Disabled -Name wlidsvc
	Set-Service -Status Stopped -StartupType Disabled -Name diagnosticshub.standardcollector.service
	Set-Service -Status Stopped -StartupType Disabled -Name MSMQTriggers
	Set-Service -Status Stopped -StartupType Disabled -Name MSMQ
	Set-Service -Status Stopped -StartupType Disabled -Name LxssManager
	Set-Service -Status Stopped -StartupType Disabled -Name LPDSVC
	Set-Service -Status Stopped -StartupType Disabled -Name lpxlatCfgSvc
	Set-Service -Status Stopped -StartupType Disabled -Name iphlpsvc
	Set-Service -Status Stopped -StartupType Disabled -Name IISADMIN
	Set-Service -Status Stopped -StartupType Disabled -Name vmicvss
	Set-Service -Status Stopped -StartupType Disabled -Name vmms
	Set-Service -Status Stopped -StartupType Disabled -Name vmictimesync
	Set-Service -Status Stopped -StartupType Disabled -Name vmicrdv
	Set-Service -Status Stopped -StartupType Disabled -Name vmicmsession
	Set-Service -Status Stopped -StartupType Disabled -Name vmcompute
	Set-Service -Status Stopped -StartupType Disabled -Name vmicheartbeat
	Set-Service -Status Stopped -StartupType Disabled -Name vmicshutdown
	Set-Service -Status Stopped -StartupType Disabled -Name vmicguestinterface
	Set-Service -Status Stopped -StartupType Disabled -Name vmickvpexchange
	Set-Service -Status Stopped -StartupType Disabled -Name HvHost
	Set-Service -Status Stopped -StartupType Disabled -Name EapHost
	Set-Service -Status Stopped -StartupType Disabled -Name dmwappushsvc
	Set-Service -Status Stopped -StartupType Disabled -Name TrkWks
	Set-Service -Status Stopped -StartupType Disabled -Name WdiSystemHost
	Set-Service -Status Stopped -StartupType Disabled -Name WdiServiceHost
	Set-Service -Status Stopped -StartupType Disabled -Name diagsvc
	Set-Service -Status Stopped -StartupType Disabled -Name DiagTrack
	Set-Service -Status Stopped -StartupType Disabled -Name NfsClnt
	Set-Service -Status Stopped -StartupType Disabled -Name CertPropSvc
	Set-Service -Status Stopped -StartupType Disabled -Name CaptureService_*
	Set-Service -Status Stopped -StartupType Disabled -Name camsvc
	Set-Service -Status Stopped -StartupType Disabled -Name PeerDistSvc
	Set-Service -Status Stopped -StartupType Disabled -Name BluetoothUserService_*
	Set-Service -Status Stopped -StartupType Disabled -Name BTAGService
	Set-Service -Status Stopped -StartupType Disabled -Name BthAvctpSvc
	Set-Service -Status Stopped -StartupType Disabled -Name tzautoupdate
	Set-Service -Status Stopped -StartupType Disabled -Name ALG
	Set-Service -Status Stopped -StartupType Disabled -Name AJRouter

 	$serviceNames = "BDESVC", "Winmgmt", "BFE", "CryptSvc", "DcomLaunch", "Dhcp", "Dnscache", "EventLog", "Group", "LanmanServer", "LanmanWorkstation", "MpsSvc", "nsi", "Power", "RpcEptMapper", "RpcSs", "SamSs", "SecurityHealthService", "Sense", "WdNisSvc", "Wecsvc", "WEPHOSTSVC", "WinDefend", "wuauserv", "WSearch", "TrustedInstaller", "msiserver", "FontCache", "Wecsvc", "Wcmsvc", "AudioSrv", "AudioEndpointBuilder", "vds", "ProfSvc", "UserManager", "UsoSvc", "Themes", "Schedule", "SgrmBroker", "SystemEventsBroker", "SENS", "OneSyncSvc_*", "SysMain", "sppsvc", "wscsvc", "PcaSvc", "Spooler", "WPDBusEnum", "ssh-agent", "NlaSvc", "LSM", "gpsvc", "EFS", "DPS", "DoSvc", "DcomLaunch", "DusmSvc", "CoreMessagingRegistrar", "CDPUserSvc_*", "CDPSvc", "EventSystem", "BrokerInfrastructure", "BITS", "AppHostSvc"

	# Loop through each service name
	foreach ($serviceName in $serviceNames) {
	    # Use this for recovery options
	    sc.exe failure $serviceName reset=0 actions=restart/60000/restart/60000/run/1000
	}
	#Enable neccesary services
	Set-Service -Status Running -StartupType Automatic -Name BDESVC
	Set-Service -Status Running -StartupType Automatic -Name BFE
	Set-Service -Status Running -StartupType Automatic -Name CryptSvc
	Set-Service -Status Running -StartupType Automatic -Name DcomLaunch
	Set-Service -Status Running -StartupType Automatic -Name Dhcp
	Set-Service -Status Running -StartupType Automatic -Name Dnscache
	Set-Service -Status Running -StartupType Automatic -Name EventLog
	Set-Service -Status Running -StartupType Automatic -Name Group
	Set-Service -Status Running -StartupType Automatic -Name LanmanServer
	Set-Service -Status Running -StartupType Automatic -Name LanmanWorkstation
	Set-Service -Status Running -StartupType Automatic -Name MpsSvc
	Set-Service -Status Running -StartupType Automatic -Name nsi
	Set-Service -Status Running -StartupType Automatic -Name Power
	Set-Service -Status Running -StartupType Automatic -Name RpcEptMapper
	Set-Service -Status Running -StartupType Automatic -Name RpcSs
	Set-Service -Status Running -StartupType Automatic -Name SamSs
	Set-Service -Status Running -StartupType Automatic -Name SecurityHealthService
	Set-Service -Status Running -StartupType Automatic -Name Sense
	Set-Service -Status Running -StartupType Automatic -Name WdNisSvc
	Set-Service -Status Running -StartupType Automatic -Name Wecsvc
	Set-Service -Status Running -StartupType Automatic -Name WEPHOSTSVC
	Set-Service -Status Running -StartupType Automatic -Name WinDefend
	Set-Service -Status Running -StartupType Automatic -Name wuauserv
	Set-Service -Status Running -StartupType Automatic -Name WSearch
	Set-Service -Status Running -StartupType Automatic -Name TrustedInstaller
	Set-Service -Status Running -StartupType Automatic -Name msiserver
	Set-Service -Status Running -StartupType Automatic -Name FontCache
	Set-Service -Status Running -StartupType Automatic -Name Wecsvc
	Set-Service -Status Running -StartupType Automatic -Name Wcmsvc
	Set-Service -Status Running -StartupType Automatic -Name AudioSrv
	Set-Service -Status Running -StartupType Automatic -Name AudioEndpointBuilder
	Set-Service -Status Running -StartupType Automatic -Name vds
	Set-Service -Status Running -StartupType Automatic -Name ProfSvc
	Set-Service -Status Running -StartupType Automatic -Name UserManager
	Set-Service -Status Running -StartupType Automatic -Name UsoSvc
	Set-Service -Status Running -StartupType Automatic -Name Themes
	Set-Service -Status Running -StartupType Automatic -Name Schedule
	Set-Service -Status Running -StartupType Automatic -Name SgrmBroker
	Set-Service -Status Running -StartupType Automatic -Name SystemEventsBroker
	Set-Service -Status Running -StartupType Automatic -Name SENS
	Set-Service -Status Running -StartupType Automatic -Name OneSyncSvc_*
	Set-Service -Status Running -StartupType Automatic -Name SysMain
	Set-Service -Status Running -StartupType Automatic -Name sppsvc
	Set-Service -Status Running -StartupType Automatic -Name wscsvc
	Set-Service -Status Running -StartupType Automatic -Name PcaSvc
	Set-Service -Status Running -StartupType Automatic -Name Spooler
	Set-Service -Status Running -StartupType Automatic -Name WPDBusEnum
	Set-Service -Status Running -StartupType Automatic -Name ssh-agent
	Set-Service -Status Running -StartupType Automatic -Name NlaSvc
	Set-Service -Status Running -StartupType Automatic -Name LSM
	Set-Service -Status Running -StartupType Automatic -Name gpsvc
	Set-Service -Status Running -StartupType Automatic -Name EFS
	Set-Service -Status Running -StartupType Automatic -Name DPS
	Set-Service -Status Running -StartupType Automatic -Name DoSvc
	Set-Service -Status Running -StartupType Automatic -Name DcomLaunch
	Set-Service -Status Running -StartupType Automatic -Name DusmSvc
	Set-Service -Status Running -StartupType Automatic -Name CoreMessagingRegistrar
	Set-Service -Status Running -StartupType Automatic -Name CDPUserSvc_*
	Set-Service -Status Running -StartupType Automatic -Name CDPSvc
	Set-Service -Status Running -StartupType Automatic -Name EventSystem
	Set-Service -Status Running -StartupType Automatic -Name BrokerInfrastructure
	Set-Service -Status Running -StartupType Automatic -Name BITS
	Set-Service -Status Running -StartupType Automatic -Name AppHostSvc
	Set-Service -Status Running -StartupType Automatic -Name Winmgmt

	#set manual services
	Set-Service -StartupType Manual -Name LicenseManager
	Set-Service -StartupType Manual -Name SDRSVC
	Set-Service -StartupType Manual -Name TokenBroker
	Set-Service -StartupType Manual -Name W3LOGSVC
	Set-Service -StartupType Manual -Name VSS
	Set-Service -StartupType Manual -Name UnistoreSvc_*
	Set-Service -StartupType Manual -Name UserDataSvc_*
	Set-Service -StartupType Manual -Name upnphost
	Set-Service -StartupType Manual -Name TimeBroker
	Set-Service -StartupType Manual -Name lmhosts
    Set-Service -StartupType Manual -Name dot3svc
	Set-Service -StartupType Manual -Name WaaSMedicSvc
	Set-Service -StartupType Manual -Name wmiApSrv
	Set-Service -StartupType Manual -Name TieringEngineService
	Set-Service -StartupType Manual -Name StorSvc
	Set-Service -StartupType Manual -Name StateRepository
	Set-Service -StartupType Manual -Name svsvc
	Set-Service -StartupType Manual -Name seclogon
	Set-Service -StartupType Manual -Name QWAVE
	Set-Service -StartupType Manual -Name PrintWorkflowUserSvc_*
	Set-Service -StartupType Manual -Name pla
	Set-Service -StartupType Manual -Name PerfHost
	Set-Service -StartupType Manual -Name defragsvc
	Set-Service -StartupType Manual -Name NetSetupSvc
	Set-Service -StartupType Manual -Name netprofm
	Set-Service -StartupType Manual -Name Netman
	Set-Service -StartupType Manual -Name InstallService
	Set-Service -StartupType Manual -Name smphost
	Set-Service -StartupType Manual -Name sqprv
	Set-Service -StartupType Manual -Name NgcCtnrSvc
	Set-Service -StartupType Manual -Name NgcSvc
	Set-Service -StartupType Manual -Name MessagingService_*
	Set-Service -StartupType Manual -Name wlpasvc
	Set-Service -StartupType Manual -Name KtmRm
	Set-Service -StartupType Manual -Name UI0Detect
	Set-Service -StartupType Manual -Name PolicyAgent
	Set-Service -StartupType Manual -Name IKEEXT
	Set-Service -StartupType Manual -Name hidserv
	Set-Service -StartupType Manual -Name hns
	Set-Service -StartupType Manual -Name GraphicsPerfSvc
	Set-Service -StartupType Manual -Name GraphicsPerfSvc
	Set-Service -StartupType Manual -Name FDResPub
	Set-Service -StartupType Manual -Name fdPHost
	Set-Service -StartupType Manual -Name fhsvc
	Set-Service -StartupType Manual -Name EntAppSvc
	Set-Service -StartupType Manual -Name embeddedmode
	Set-Service -StartupType Manual -Name DsRoleSvc
	Set-Service -StartupType Manual -Name MSDTC
	Set-Service -StartupType Manual -Name DevQueryBroker
	Set-Service -StartupType Manual -Name DevicesFlowUserSvc_*
	Set-Service -StartupType Manual -Name DevicePickerUserSvc_*
	Set-Service -StartupType Manual -Name DsmSVC
	Set-Service -StartupType Manual -Name DmEnrollmentSvc
	Set-Service -StartupType Manual -Name DeviceInstall
	Set-Service -StartupType Manual -Name DsSvc
	Set-Service -StartupType Manual -Name COMSysApp
	Set-Service -StartupType Manual -Name KeyIso
	Set-Service -StartupType Manual -Name ClipSVC
	Set-Service -StartupType Manual -Name c2wts
	Set-Service -StartupType Manual -Name wbegine
	Set-Service -StartupType Manual -Name aspnet_state
	Set-Service -StartupType Manual -Name AssignedAccessManagerSvc
	Set-Service -StartupType Manual -Name AppXSVC
	Set-Service -StartupType Manual -Name AppMgmt
	Set-Service -StartupType Manual -Name Appinfo
	Set-Service -StartupType Manual -Name AppIDSvc
	Set-Service -StartupType Manual -Name AppReadiness
	Set-Service -StartupType Manual -Name AxInstSV

	#unwanted but can't be disabled
	Set-Service -Status Stopped -StartupType Manual -Name BcastDVRUserService_*
	Set-Service -Status Stopped -StartupType Manual -Name DeviceAssociationService
	Set-Service -Status Stopped -StartupType Manual -Name VaultSvc
	Set-Service -Status Stopped -StartupType Manual -Name PimIndexMaintenanceSvc_*
   Write-Warning "If you lose points, just enable the services that are causing issues."
}

if ($option -eq 10){
    #flush DNS cache
    Write-Warning "Flushing DNS Cache"
    ipconfig /flushdns
    #finding hosts
    attrib -r -s C:\WINDOWS\system32\drivers\etc\hosts
    attrib +r +s C:\WINDOWS\system32\drivers\etc\hosts
}

if ($option -eq 11){

    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Vssadmin Removed" -ForegroundColor white
    vssadmin delete shadows /for=c: /all

    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Disable RDP" -ForegroundColor white
    #disable Remote stuff (not RDP)
    reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CachedLogonsCount /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v AllowTSConnections /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "AllowSignedFiles" /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "AllowUnsignedFiles" /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "DisablePasswordSaving" /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Conferencing" /v "NoRDS" /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" /v "AllowRemoteShellAccess" /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "AllowSignedFiles" /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "AllowUnsignedFiles" /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "CreateEncryptedOnlyTickets" /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "DisablePasswordSaving" /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowToGetHelp" /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowUnsolicited" /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fDenyTSConnections" /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client" /v "fEnableUsbBlockDeviceBySetupClass" /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client" /v "fEnableUsbNoAckIsochWriteToDevice" /t REG_DWORD /d 80 /f | Out-Null
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client" /v "fEnableUsbSelectDeviceByInterface" /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\RemoteAdminSettings" /v "Enabled" /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\RemoteDesktop" /v "Enabled" /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\UPnPFramework" /v "Enabled" /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "Shadow" /t REG_DWORD /d 0 /f | Out-Null

    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Updates" -ForegroundColor white
    #Windows automatic updates
    reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AutoInstallMinorUpdates /t REG_DWORD /d 1 /f | Out-Null
    reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoUpdate /t REG_DWORD /d 0 /f | Out-Null
    reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AUOptions /t REG_DWORD /d 4 /f | Out-Null
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 4 /f | Out-Null
    reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f | Out-Null
    reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v ElevateNonAdmins /t REG_DWORD /d 0 /f | Out-Null
    reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoWindowsUpdate /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKLM\SYSTEM\Internet Communication Management\Internet Communication" /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f | Out-Null
    reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f | Out-Null

    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "]  #Restrict CD ROM drive" -ForegroundColor white
    reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateCDRoms /t REG_DWORD /d 1 /f | Out-Null

    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "]  Disable remote access to floppy disk" -ForegroundColor white
    reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateFloppies /t REG_DWORD /d 1 /f | Out-Null

    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "]  Disable auto admin login" -ForegroundColor white
    reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f | Out-Null

    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "]  Clear page file" -ForegroundColor white
    reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f | Out-Null

    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "]  No Printer Drivers" -ForegroundColor white
    reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers /t REG_DWORD /d 1 /f | Out-Null

    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "]  LSASS.exe" -ForegroundColor white
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 00000008 /f| Out-Null
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f | Out-Null
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v auditbaseobjects /t REG_DWORD /d 1 /f | Out-Null
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v fullprivilegeauditing /t REG_DWORD /d 1 /f | Out-Null
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymous /t REG_DWORD /d 1 /f | Out-Null
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymoussam /t REG_DWORD /d 1 /f | Out-Null
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v disabledomaincreds /t REG_DWORD /d 1 /f | Out-Null
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v UseMachineId /t REG_DWORD /d 0 /f | Out-Null
    reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v dontdisplaylastusername /t REG_DWORD /d 1 /f | Out-Null
    reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdminOutboundCreds /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 8 /f | Out-Null
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v NoLMHash /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v SubmitControl /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v everyoneincludesanonymous /t REG_DWORD /d 0 /f | Out-Null
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v TokenLeakDetectDelaySecs /t REG_DWORD /d 30 /f | Out-Null
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictRemoteSAM /t REG_SZ /d "O:BAG:BAD:(A;;RC;;;BA)" /f | Out-Null
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LsaCfgFlags /t REG_DWORD /d 2 /f | Out-Null

    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "]  UAC" -ForegroundColor white
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" -/t REG_DWORD /d 5 /f | Out-Null
	reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "PromptOnSecureDesktop" /t REG_DWORD /d 1 /f | Out-Null
    reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f | Out-Null
    
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "]  Enable Installer Detection" -ForegroundColor white
    reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableInstallerDetection /t REG_DWORD /d 1 /f
    reg ADD HKLM\SOFTWARE\Microsot\Windows\CurrentVersion\Policies\System /v undockwithoutlogon /t REG_DWORD /d 0 /f
    reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v DisableCAD /t REG_DWORD /d 0 /
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v DisablePasswordChange /t REG_DWORD /d 1 /f
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireStrongKey /t REG_DWORD /d 1 /f
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireSignOrSeal /t REG_DWORD /d 1 /f
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SignSecureChannel /t REG_DWORD /d 1 /f
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SealSecureChannel /t REG_DWORD /d 1 /f
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v autodisconnect /t REG_DWORD /d 45 /f
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v enablesecuritysignature /t REG_DWORD /d 0 /f
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v requiresecuritysignature /t REG_DWORD /d 0 /f
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionPipes /t REG_MULTI_SZ /d "" /f
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionShares /t REG_MULTI_SZ /d "" /f
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths /v Machine /t REG_MULTI_SZ /d "" /f
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths /v Machine /t REG_MULTI_SZ /d "" /f
    reg ADD "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v EnabledV8 /t REG_DWORD /d 1 /f
    reg ADD "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 1 /f
    reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v DisablePasswordCaching /t REG_DWORD /d 1 /f
    reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonBadCertRecving /t REG_DWORD /d 1 /f
    reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnOnPostRedirect /t REG_DWORD /d 1 /f
    reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main" /v DoNotTrack /t REG_DWORD /d 1 /f
    reg ADD "HKCU\Software\Microsoft\Internet Explorer\Download" /v RunInvalidSignatures /t REG_DWORD /d 1 /f
    reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings" /v LOCALMACHINE_CD_UNLOCK /t REG_DWORD /d 1 /f
    reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonZoneCrossing /t REG_DWORD /d 1 /f
    reg ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v Hidden /t REG_DWORD /d 1 /f
    reg ADD "HKU\.DEFAULT\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d 506 /f
    reg ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v ShowSuperHidden /t REG_DWORD /d 1 /f
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\CrashControl /v CrashDumpEnabled /t REG_DWORD /d 0 /f
    reg ADD HKCU\SYSTEM\CurrentControlSet\Services\CDROM /v AutoRun /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d 255 /f

    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "]  Internet explorer phishing filter" -ForegroundColor white
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 1 /f

    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Block macros and other content execution" -ForegroundColor white
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\access\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\excel\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\excel\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\excel\security" /v "excelbypassencryptedmacroscan" /t REG_DWORD /d 0 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\ms project\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\ms project\security" /v "level" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\outlook\security" /v "level" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\powerpoint\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\powerpoint\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\publisher\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\visio\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\visio\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\word\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\word\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\word\security" /v "wordbypassencryptedmacroscan" /t REG_DWORD /d 0 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\common\security" /v "automationsecurity" /t REG_DWORD /d 3 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots" /v "Flags" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 4
    reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f


reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "CheckForSignaturesBeforeRunningScan" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableHeuristics" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "ScanWithAntiVirus" /t REG_DWORD /d 3 /f
setx /M MP_FORCE_USE_SANDBOX 1
Start-Process -FilePath "C:\Program Files\Windows Defender\MpCmdRun.exe" -ArgumentList "-SignatureUpdate"
Update-MpSignature
Add-MpPreference -AttackSurfaceReductionRules_Ids "56a863a9-875e-4185-98a7-b882c64b5ce5" -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids "d4f940ab-401b-4efc-aadc-ad5f3c50688a" -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids "01443614-cd74-433a-b99e-2ecdc07bfc25" -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids "5beb7efe-fd9a-4556-801d-275e5ffc04cc" -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids "d3e037e1-3eb8-44c8-a917-57927947596d" -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids "3b576869-a4ec-4529-8536-b80a7769e899" -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids "26190899-1602-49e8-8b27-eb1d0a1ce869" -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids "e6db77e5-3df2-4cf1-b95a-636979351e5b" -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids "d1e49aac-8f56-4280-b9ba-993a6d77406c" -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids "a8f5898e-1dc8-49a9-9878-85004b8a61e6" -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids "c1db55ab-c21a-4637-bb3f-a12568109d" -AttackSurfaceReductionRules_Actions Enabled
reg add "HKLM\SYSTEM\CurrentControlSet\Services\wuauserv" /v LaunchProtected  /t REG_DWORD /d 3 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\mpssvc" /v LaunchProtected  /t REG_DWORD /d 3 /f
Set-MpPreference -AllowDatagramProcessingOnWinServer $true
Set-MpPreference -AllowNetworkProtectionDownLevel $true
Set-MpPreference -AllowNetworkProtectionOnWinServer $true
Set-MpPreference -AllowSwitchToAsyncInspection $true
Set-MpPreference -AttackSurfaceReductionOnlyExclusions @()
Set-MpPreference -CheckForSignaturesBeforeRunningScan $true
Set-MpPreference -CloudBlockLevel HighPlus
Set-MpPreference -CloudExtendedTimeout 10
Set-MpPreference -ControlledFolderAccessAllowedApplications 10
Set-MpPreference -DisableArchiveScanning $false
Set-MpPreference -DisableAutoExclusions $true
Set-MpPreference -DisableBehaviorMonitoring $false
Set-MpPreference -DisableBlockAtFirstSeen $false
Set-MpPreference -DisableCacheMaintenance $false
Set-MpPreference -DisableCatchupFullScan $false
Set-MpPreference -DisableCatchupQuickScan $false
Set-MpPreference -DisableCpuThrottleOnIdleScans $false
Set-MpPreference -DisableDatagramProcessing $false
Set-MpPreference -DisableDnsOverTcpParsing $false
Set-MpPreference -DisableDnsParsing $false
Set-MpPreference -DisableEmailScanning $false
Set-MpPreference -DisableFtpParsing $false
Set-MpPreference -DisableGradualRelease $false
Set-MpPreference -DisableHttpParsing $false
Set-MpPreference -DisableInboundConnectionFiltering $false
Set-MpPreference -DisableIOAVProtection $false
Set-MpPreference -DisableNetworkProtectionPerfTelemetry $true
Set-MpPreference -DisablePrivacyMode $false
Set-MpPreference -DisableRdpParsing $false
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -DisableRemovableDriveScanning $false
Set-MpPreference -DisableRestorePoint $false
Set-MpPreference -DisableScanningMappedNetworkDrivesForFullScan $false
Set-MpPreference -DisableScanningNetworkFiles $false
Set-MpPreference -DisableScriptScanning $false
Set-MpPreference -DisableSmtpParsing $false
Set-MpPreference -DisableSshParsing $false
Set-MpPreference -DisableTlsParsing $false
Set-MpPreference -EnableControlledFolderAccess Enabled
Set-MpPreference -EnableDnsSinkhole $true
Set-MpPreference -EnableFileHashComputation $true
Set-MpPreference -EnableFullScanOnBatteryPower $true
Set-MpPreference -EnableLowCpuPriority $false
Set-MpPreference -HighThreatDefaultAction Quarantine
Set-MpPreference -IntelTDTEnabled 1
Set-MpPreference -LowThreatDefaultAction Quarantine
Set-MpPreference -ModerateThreatDefaultAction Quarantine
Set-MpPreference -OobeEnableRtpAndSigUpdate $true
Set-MpPreference -ProxyBypass @()
Set-MpPreference -PUAProtection Enabled
Set-MpPreference -QuarantinePurgeItemsAfterDelay 10
Set-MpPreference -RandomizeScheduleTaskTimes $True 
Set-MpPreference -RealTimeScanDirection 0
Set-MpPreference -ReportingAdditionalActionTimeOut 60
Set-MpPreference -ReportingCriticalFailureTimeOut 60
Set-MpPreference -ReportingNonCriticalTimeOut 60
Set-MpPreference -ScanAvgCPULoadFactor 10
Set-MpPreference -ScanScheduleDay 0
Set-MpPreference -SevereThreatDefaultAction Quarantine
Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $True
Set-MpPreference -UnknownThreatDefaultAction Quarantine

$sddlString = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"
$serviceKeys = Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services"
foreach ($key in $serviceKeys) {
    $serviceName = $key.PSChildName
    $command = "& $env:SystemRoot\System32\sc.exe sdset $serviceName `"$sddlString`""
    Invoke-Expression $command
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Successfully set SDDL for service: $serviceName"
    } else {
        Write-Host "Failed to set SDDL for service: $serviceName"
    }
}
Write-Host "SDDL setting process completed."
sc.exe sdset scmanager "D:(A;;CC;;;AU)(A;;CCLCRPRC;;;IU)(A;;CCLCRPRC;;;SU)(A;;CCLCRPWPRC;;;SY)(A;;KA;;;BA)(A;;CC;;;AC)S:(AU;FA;KA;;;WD)(AU;OIIOFA;GA;;;WD)" | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Reset SCM SDDL" -ForegroundColor white

## Enabling SEHOP
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v DisableExceptionChainValidation /t REG_DWORD /d 0 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Enabled SEHOP" -ForegroundColor white
## Starting Windows Defender service
if(!(Get-MpComputerStatus | Select-Object AntivirusEnabled)) {
    Start-Service WinDefend
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Started Windows Defender service" -ForegroundColor white
}
## Enabling Windows Defender sandboxing
cmd /c "setx /M MP_FORCE_USE_SANDBOX 1" | Out-Null
## Enabling a bunch of configuration settings
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "HideExclusionsFromLocalAdmins" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" /v "MpCloudBlockLevel" /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "CheckForSignaturesBeforeRunningScan" /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableHeuristics" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableArchiveScanning" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" /v "ForceDefenderPassiveMode" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" /v "MpEnablePus" /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Configured Windows Defender" -ForegroundColor white
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "PUAProtection" /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpyNetReporting" /t REG_DWORD /d 2 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Enabled Windows Defender cloud functionality" -ForegroundColor white
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" /v EnableNetworkProtection /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Enabled Windows Defender network protection" -ForegroundColor white
& 'C:\Program Files\Windows Defender\MpCmdRun.exe' -RemoveDefinitions -All | Out-Null
Update-MpSignature
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Updated Windows Defender signatures" -ForegroundColor white
try {
    Set-ProcessMitigation -PolicyFilePath (Join-Path -Path $ConfPath -ChildPath "def-eg-settings.xml") | Out-Null
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Configured Windows Defender Exploit Guard" -ForegroundColor white
} catch {
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "ERROR" -ForegroundColor red -NoNewLine; Write-Host "] Detected old Defender version, skipping configuring Exploit Guard" -ForegroundColor white
}
ForEach ($ex_extension in (Get-MpPreference).ExclusionExtension) {
    Remove-MpPreference -ExclusionExtension $ex_extension | Out-Null
}
ForEach ($ex_dir in (Get-MpPreference).ExclusionPath) {
    Remove-MpPreference -ExclusionPath $ex_dir | Out-Null
}
ForEach ($ex_proc in (Get-MpPreference).ExclusionProcess) {
    Remove-MpPreference -ExclusionProcess $ex_proc | Out-Null
}
ForEach ($ex_ip in (Get-MpPreference).ExclusionIpAddress) {
    Remove-MpPreference -ExclusionIpAddress $ex_ip | Out-Null
}
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Removed Defender exclusions" -ForegroundColor white
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v TamperProtection /t REG_DWORD /d 5 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Windows Defender has been abused" -ForegroundColor white

net accounts /UNIQUEPW:24 /MAXPWAGE:90 /MINPWAGE:30 /MINPWLEN:14 /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30
auditpol /set /category:"Account Logon" /success:enable | Out-Null
auditpol /set /category:"Account Logon" /failure:enable | Out-Null
auditpol /set /category:"Account Management" /success:enable | Out-Null
auditpol /set /category:"Account Management" /failure:enable | Out-Null
auditpol /set /category:"DS Access" /success:enable | Out-Null
auditpol /set /category:"DS Access" /failure:enable | Out-Null
auditpol /set /category:"Logon/Logoff" /success:enable | Out-Null
auditpol /set /category:"Logon/Logoff" /failure:enable | Out-Null
auditpol /set /category:"Object Access" /failure:enable | Out-Null
auditpol /set /category:"Policy Change" /success:enable | Out-Null
auditpol /set /category:"Policy Change" /failure:enable | Out-Null
auditpol /set /category:"Privilege Use" /success:enable | Out-Null
auditpol /set /category:"Privilege Use" /failure:enable | Out-Null
auditpol /set /category:"Detailed Tracking" /success:enable | Out-Null
auditpol /set /category:"Detailed Tracking" /failure:enable | Out-Null
auditpol /set /category:"System" /success:enable | Out-Null
auditpol /set /category:"System" /failure:enable | Out-Null
auditpol /set /category:* /success:enable | Out-Null
auditpol /set /category:* /failure:enable | Out-Null
auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"IPsec Driver" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Other System Events" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Logoff" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"IPsec Main Mode" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"IPsec Quick Mode" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"IPsec Extended Mode" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Network Policy Server" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"User / Device Claims" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Group Membership" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"File System" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Registry" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Kernel Object" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"SAM" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Application Generated" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Handle Manipulation" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"File Share" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Central Policy Staging" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Non Sensitive Privilege Use" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Other Privilege Use Events" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Process Termination" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"DPAPI Activity" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"RPC Events" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Plug and Play Events" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Token Right Adjusted Events" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Authorization Policy Change" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Filtering Platform Policy Change" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Other Policy Change Events" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Distribution Group Management" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Application Group Management" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Other Account Management Events" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Directory Service Replication" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Detailed Directory Service Replication" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Other Account Logon Events" /success:enable /failure:enable  | Out-Null
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable | Out-Null
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\EventLog\Security' -Name "AuditAccountLogon" -Value 2 | Out-Null
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\EventLog\Security' -Name "AuditAccountManage" -Value 2 | Out-Null
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\EventLog\Security' -Name "AuditDSAccess" -Value 2 | Out-Null
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\EventLog\Security' -Name "AuditLogonEvents" -Value 2 | Out-Null
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\EventLog\Security' -Name "AuditObjectAccess" -Value 2 | Out-Null
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\EventLog\Security' -Name "AuditPolicyChange" -Value 2 | Out-Null
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\EventLog\Security' -Name "AuditPrivilegeUse" -Value 2 | Out-Null
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\EventLog\Security' -Name "AuditProcessTracking" -Value 2 | Out-Null
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\EventLog\Security' -Name "AuditSystemEvents" -Value 2 | Out-Null
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\EventLog\Security' -Name "AuditKernelObject" -Value 2 | Out-Null
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\EventLog\Security' -Name "AuditSAM" -Value 2 | Out-Null
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\EventLog\Security' -Name "AuditSecuritySystemExtension" -Value 2 | Out-Null
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\EventLog\Security' -Name "AuditRegistry" -Value 2 | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audit Policy Applied" -ForegroundColor white
    

Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Enable auditing of file system object changes on all drives" -ForegroundColor white
    $drives = Get-PSDrive -PSProvider FileSystem | Where-Object {$_.DriveType -eq 'Fixed'}
    foreach ($drive in $drives) {
        $acl = Get-Acl -Path $drive.Root
        $auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule("Everyone", "CreateFiles", "Success")
        $acl.AddAuditRule($auditRule)
        Set-Acl -Path $drive.Root -AclObject $acl
    }

    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force | Out-Null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v "MinimumPIN" /t REG_DWORD /d "0x00000006" /f | Out-Null
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d "0x00000000" /f | Out-Null
	reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "SMB1" /t REG_DWORD /d "0x00000000" /f | Out-Null
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" /v "MaxSize" /t REG_DWORD /d "0x00008000" /f | Out-Null
	reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v "DisableIpSourceRouting" /t REG_DWORD /d "2" /f | Out-Null
	reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableIPSourceRouting" /t REG_DWORD /d "2" /f | Out-Null
	reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "LocalAccountTokenFilterPolicy" /t REG_DWORD /d "0x00000000" /f | Out-Null
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest" /v "UseLogonCredential" /t REG_DWORD /d "0x00000000" /f | Out-Null
	reg add "HKLM\SOFTWARE\Classes\batfile\shell\runasuser\" /v "SuppressionPolicy" /t REG_DWORD /d "0x00001000" /f | Out-Null
	reg add "HKLM\SOFTWARE\Classes\cmdfile\shell\runasusers" /v "SuppressionPolicy" /t REG_DWORD /d "0x00001000" /f | Out-Null
	reg add "HKLM\SOFTWARE\Classes\exefile\shell\runasuser" /v "SuppressionPolicy" /t REG_DWORD /d "0x00001000" /f | Out-Null
	reg add "HKLM\SOFTWARE\Classes\exefile\shell\runasusers" /v "SuppressionPolicy" /t REG_DWORD /d "0x00001000" /f | Out-Null
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" /v "AllowInsecureGuestAuth" /t REG_DWORD /d "0x00000000" /f | Out-Null
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections" /v "NC_ShowSharedAccessUI" /t REG_DWORD /d "0x00000000" /f | Out-Null
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" /v "EccCurves" /t REG_MULTI_SZ /d "NistP384 NistP256" /f | Out-Null
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" /v "fMinimizeConnections" /t REG_DWORD /d "1" /f | Out-Null
	reg add "HKLM\SOFTWARE\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" /v "fBlockNonDomain" /t REG_DWORD /d "1" /f | Out-Null
	reg add "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /v "AutoConnectAllowedOEM" /t REG_DWORD /d "0x00000000" /f | Out-Null
	reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v "ProcessCreationIncludeCmdLine_Enabled" /t REG_DWORD /d "1" /f | Out-Null
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" /v "AllowProtectedCreds" /t REG_DWORD /d "0x00000001" /f | Out-Null
	reg add "HKLM\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" /v "DriverLoadPolicy" /t REG_DWORD /d "8" /f | Out-Null
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" /v "NoGPOListChanges" /t REG_DWORD /d "0" /f | Out-Null
	reg add "HKLM\SYSTEM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v "DisableWebPnPDownload" /t REG_DWORD /d "1" /f | Out-Null
	reg add "HKLM\SYSTEM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoWebServices" /t REG_DWORD /d "1" /f | Out-Null
	reg add "HKLM\SYSTEM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v "DisableHTTPPrinting" /t REG_DWORD /d "1" /f | Out-Null
	reg add "HKLM\SYSTEM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DontDisplayNetworkSelectionUI" /t REG_DWORD /d "1" /f | Out-Null
	reg add "HKLM\SYSTEM\SOFTWARE\Policies\Microsoft\Windows\Systemh" /v "EnumerateLocalUsers" /t REG_DWORD /d "0" /f | Out-Null
	reg add "HKLM\SYSTEM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /v "DCSettingIndex" /t REG_DWORD /d "1" /f | Out-Null
	reg add "HKLM\SYSTEM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /v "ACSettingIndex" /t REG_DWORD /d "1" /f | Out-Null
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d "1" /f | Out-Null
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "RequirePlatformSecurityFeatures" /t REG_DWORD /d "3" /f | Out-Null
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "LsaCfgFlags" /t REG_DWORD /d "0x00000001" /f | Out-Null
	reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" /v "DevicePKInitEnabled" /t REG_DWORD /d "1" /f | Out-Null
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DontDisplayNetworkSelectionUI" /t REG_DWORD /d "1" /f | Out-Null
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowToGetHelp" /t REG_DWORD /d "0" /f | Out-Null
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" /v "RestrictRemoteClients" /t REG_DWORD /d "1" /f | Out-Null
	reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "MSAOptional" /t REG_DWORD /d "0x00000001" /f | Out-Null
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d "1" /f | Out-Null
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoAutoplayfornonVolume" /t REG_DWORD /d "1" /f | Out-Null
	reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d "1" /f | Out-Null
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "0x00000001" /f | Out-Null
	reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" /v "EnumerateAdministrators" /t REG_DWORD /d "0" /f | Out-Null
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "LimitEnhancedDiagnosticDataWindowsAnalytics" /t REG_DWORD /d "0x00000001" /f | Out-Null
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0x00000000" /f | Out-Null
	reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d "0x000000ff" /f | Out-Null
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v "DODownloadMode" /t REG_DWORD /d "0x00000000" /f | Out-Null
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d "0x00000001" /f | Out-Null
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "ShellSmartScreenLevel" /t REG_SZ /d "v1607 LTSB:" /f | Out-Null
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d "0x00000002" /f | Out-Null
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoDataExecutionPrevention" /t REG_DWORD /d "0" /f | Out-Null
	reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoHeapTerminationOnCorruption" /t REG_DWORD /d "0x00000000" /f | Out-Null
	reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "PreXPSP2ShellProtocolBehavior" /t REG_DWORD /d "0" /f | Out-Null
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" DisableCompression-Type DWORD -Value 1 -Force | Out-Null
	Set-SmbServerConfiguration -EncryptData $true -Force | Out-Null
	reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SitePerProcess" /t REG_DWORD /d "0x00000001" /f | Out-Null
	reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SSLVersionMin" /t REG_SZ /d "tls1.2^@" /f | Out-Null
	reg add "HKLM\Software\Policies\Microsoft\Edge" /v "NativeMessagingUserLevelHosts" /t REG_DWORD /d "0" /f | Out-Null
	reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SmartScreenEnabled" /t REG_DWORD /d "0x00000001" /f | Out-Null
	reg add "HKLM\Software\Policies\Microsoft\Edge" /v "PreventSmartScreenPromptOverride" /t REG_DWORD /d "0x00000001" /f | Out-Null
	reg add "HKLM\Software\Policies\Microsoft\Edge" /v "PreventSmartScreenPromptOverrideForFiles" /t REG_DWORD /d "0x00000001" /f | Out-Null
	reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SSLErrorOverrideAllowed" /t REG_DWORD /d "0" /f | Out-Null
	reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SmartScreenPuaEnabled" /t REG_DWORD /d "0x00000001" /f | Out-Null
	reg add "HKLM\Software\Policies\Microsoft\Edge" /v "AllowDeletingBrowserHistory" /t REG_DWORD /d "0x00000000" /f | Out-Null
	reg add "HKLM\Software\Policies\Microsoft\Edge\ExtensionInstallAllowlist\1" /t REG_SZ /d "odfafepnkmbhccpbejgmiehpchacaeak" /f | Out-Null
	reg add "HKLM\Software\Policies\Microsoft\Edge\ExtensionInstallForcelist\1" /t REG_SZ /d "odfafepnkmbhccpbejgmiehpchacaeak" /f | Out-Null
	reg add "HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Edge\Extensions\odfafepnkmbhccpbejgmiehpchacaeak" /v "update_url" /t REG_SZ /d "https://edge.microsoft.com/extensionwebstorebase/v1/crx" /f | Out-Null
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Chrome hardening settings" -ForegroundColor white
	reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AllowCrossOriginAuthPrompt" /t REG_DWORD /d 0 /f
	reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AlwaysOpenPdfExternally" /t REG_DWORD /d 0 /f
	reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AmbientAuthenticationInPrivateModesEnabled" /t REG_DWORD /d 0 /f
	reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AudioCaptureAllowed" /t REG_DWORD /d 1 /f
	reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AudioSandboxEnabled" /t REG_DWORD /d 1 /f
	reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DnsOverHttpsMode" /t REG_SZ /d on /f
	reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "ScreenCaptureAllowed" /t REG_DWORD /d 1 /f
	reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "SitePerProcess" /t REG_DWORD /d 1 /f
	reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "TLS13HardeningForLocalAnchorsEnabled" /t REG_DWORD /d 1 /f
	reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "VideoCaptureAllowed" /t REG_DWORD /d 1 /f
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Even more Chrome hardening settings" -ForegroundColor white
	reg add "HKLM\Software\Policies\Google\Chrome" /v "AdvancedProtectionAllowed" /t REG_DWORD /d "1" /f
	reg add "HKLM\Software\Policies\Google\Chrome" /v "RemoteAccessHostFirewallTraversal" /t REG_DWORD /d "0" /f
	reg add "HKLM\Software\Policies\Google\Chrome" /v "DefaultPopupsSetting" /t REG_DWORD /d "33554432" /f
	reg add "HKLM\Software\Policies\Google\Chrome" /v "DefaultGeolocationSetting" /t REG_DWORD /d "33554432" /f
	reg add "HKLM\Software\Policies\Google\Chrome" /v "DefaultSearchProviderName" /t REG_SZ /d "Google Encrypted" /f
	reg add "HKLM\Software\Policies\Google\Chrome" /v "DefaultSearchProviderSearchURL" /t REG_SZ /d "https://www.google.com/#q={searchTerms}" /f
	reg add "HKLM\Software\Policies\Google\Chrome" /v "DefaultSearchProviderEnabled" /t REG_DWORD /d "16777216" /f
	reg add "HKLM\Software\Policies\Google\Chrome" /v "AllowOutdatedPlugins" /t REG_DWORD /d "0" /f
	reg add "HKLM\Software\Policies\Google\Chrome" /v "BackgroundModeEnabled" /t REG_DWORD /d "0" /f
	reg add "HKLM\Software\Policies\Google\Chrome" /v "CloudPrintProxyEnabled" /t REG_DWORD /d "0" /f
	reg add "HKLM\Software\Policies\Google\Chrome" /v "MetricsReportingEnabled" /t REG_DWORD /d "0" /f
	reg add "HKLM\Software\Policies\Google\Chrome" /v "SearchSuggestEnabled" /t REG_DWORD /d "0" /f
	reg add "HKLM\Software\Policies\Google\Chrome" /v "ImportSavedPasswords" /t REG_DWORD /d "0" /f
	reg add "HKLM\Software\Policies\Google\Chrome" /v "IncognitoModeAvailability" /t REG_DWORD /d "16777216" /f
	reg add "HKLM\Software\Policies\Google\Chrome" /v "EnableOnlineRevocationChecks" /t REG_DWORD /d "16777216" /f
	reg add "HKLM\Software\Policies\Google\Chrome" /v "SavingBrowserHistoryDisabled" /t REG_DWORD /d "0" /f
	reg add "HKLM\Software\Policies\Google\Chrome" /v "DefaultPluginsSetting" /t REG_DWORD /d "50331648" /f
	reg add "HKLM\Software\Policies\Google\Chrome" /v "AllowDeletingBrowserHistory" /t REG_DWORD /d "0" /f
	reg add "HKLM\Software\Policies\Google\Chrome" /v "PromptForDownloadLocation" /t REG_DWORD /d "16777216" /f
	reg add "HKLM\Software\Policies\Google\Chrome" /v "DownloadRestrictions" /t REG_DWORD /d "33554432" /f
	reg add "HKLM\Software\Policies\Google\Chrome" /v "AutoplayAllowed" /t REG_DWORD /d "0" /f
	reg add "HKLM\Software\Policies\Google\Chrome" /v "SafeBrowsingExtendedReportingEnabled" /t REG_DWORD /d "0" /f
	reg add "HKLM\Software\Policies\Google\Chrome" /v "DefaultWebUsbGuardSetting" /t REG_DWORD /d "33554432" /f
    reg add "HKLM\Software\Policies\Google\Chrome" /v "AdsSettingForIntrusiveAdsSites" /t REG_DWORD /d 2 /f 
	reg add "HKLM\Software\Policies\Google\Chrome" /v "ChromeCleanupEnabled" /t REG_DWORD /d "0" /f
	reg add "HKLM\Software\Policies\Google\Chrome" /v "ChromeCleanupReportingEnabled" /t REG_DWORD /d "0" /f
	reg add "HKLM\Software\Policies\Google\Chrome" /v "EnableMediaRouter" /t REG_DWORD /d "0" /f
	reg add "HKLM\Software\Policies\Google\Chrome" /v "SSLVersionMin" /t REG_SZ /d "tls1.1" /f
	reg add "HKLM\Software\Policies\Google\Chrome" /v "UrlKeyedAnonymizedDataCollectionEnabled" /t REG_DWORD /d "0" /f
	reg add "HKLM\Software\Policies\Google\Chrome" /v "WebRtcEventLogCollectionAllowed" /t REG_DWORD /d "0" /f
	reg add "HKLM\Software\Policies\Google\Chrome" /v "NetworkPredictionOptions" /t REG_DWORD /d "33554432" /f
	reg add "HKLM\Software\Policies\Google\Chrome" /v "BrowserGuestModeEnabled" /t REG_DWORD /d "0" /f
	reg add "HKLM\Software\Policies\Google\Chrome" /v "ImportAutofillFormData" /t REG_DWORD /d "0" /f
	reg add "HKLM\Software\Policies\Google\Chrome\ExtensionInstallWhitelist" /v "1" /t REG_SZ /d "cjpalhdlnbpafiamejdnhcphjbkeiagm" /f
	reg add "HKLM\Software\Policies\Google\Chrome\ExtensionInstallForcelist" /v "1" /t REG_SZ /d "cjpalhdlnbpafiamejdnhcphjbkeiagm" /f
	reg add "HKLM\Software\Policies\Google\Chrome\URLBlacklist" /v "1" /t REG_SZ /d "javascript://*" /f
	reg add "HKLM\Software\Policies\Google\Update" /v "AutoUpdateCheckPeriodMinutes" /t REG_DWORD /d "1613168640" /f
	reg add "HKLM\Software\Policies\Google\Chrome\Recommended" /v "SafeBrowsingProtectionLevel" /t REG_DWORD /d "2" /f
	reg add "HKLM\Software\Policies\Google\Chrome\Recommended" /v "SyncDisabled" /t REG_DWORD /d "1" /f
	REG DELETE "HKLM\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" /va /f
	reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoStartBanner" /t REG_DWORD /d "1" /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "DisableCompression" /t REG_DWORD /d "1" /f
	Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
	Set-SmbServerConfiguration -EncryptData $true -Force
	del C:\Windows\System32\flshpnt.dll
	del C:\Windows\System32\drivers\WinDivert64.sys
	REG ADD "HKEY_CLASSES_ROOT\Microsoft.PowerShellScript.1\Shell" /ve /d "1" /f	

icacls $env:windir\system32\config\*.* /inheritance:e | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] HiveNightmare mitigations in place" -ForegroundColor white
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers" /v CopyFilesPolicy /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers" /v RegisterSpoolerRemoteRpcEndPoint /t REG_DWORD /d 2 /f | Out-Null
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /f | Out-Null
reg add "HKLM\System\CurrentControlSet\Control\Print" /v RpcAuthnLevelPrivacyEnabled /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] PrintNightmare mitigations in place" -ForegroundColor white

# Credential Delegation settings
## Enabling support for Restricted Admin/Remote Credential Guard
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" /v AllowProtectedCreds /t REG_DWORD /d 1 /f | Out-Null

## Enabling Credential Delegation (Restrict Credential Delegation)
reg add "HKLM\Software\Policies\Microsoft\Windows\CredentialsDelegation" /v RestrictedRemoteAdministration /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\Software\Policies\Microsoft\Windows\CredentialsDelegation" /v RestrictedRemoteAdministrationType /t REG_DWORD /d 3 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Credential Delegation settings set" -ForegroundColor white

# User Account Control (UAC)
## Enabling Restricted Admin mode
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v FilterAdministratorToken /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableUIADesktopToggle /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorUser /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableInstallerDetection /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ValidateAdminCodeSignatures /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableSecureUIAPaths /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableVirtualization /t REG_DWORD /d 1 /f | Out-Null
## Applying UAC restrictions to local accounts on network logons
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] UAC set up" -ForegroundColor white



# Disabling WDigest, removing storing plain text passwords in LSASS
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v Negotiate /t REG_DWORD /d 0 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] WDigest disabled" -ForegroundColor white

# Disabling autologon
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Autologon disabled" -ForegroundColor white

## Setting screen saver grace period
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v ScreenSaverGracePeriod /t REG_DWORD /d 0 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Screen saver grace period set to 0 seconds" -ForegroundColor white

# Caching logons
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CachedLogonsCount /t REG_SZ /d 0 /f | Out-Null
# Clear cached credentials [TEST]
# cmdkey /list | ForEach-Object{if($_ -like "*Target:*" -and $_ -like "*microsoft*"){cmdkey /del:($_ -replace " ","" -replace "Target:","")}}
# Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Cached credentials cleared, set to store none" -ForegroundColor white

# NTLM Settings
## Could impact share access (configured to only send NTLMv2, refuse LM & NTLM) - CVE-2019-1040
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LMCompatibilityLevel /t REG_DWORD /d 5 /f | Out-Null
## Allowing Local System to use computer identity for NTLM
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v UseMachineId /t REG_DWORD /d 1 /f | Out-Null
## Preventing null session fallback for NTLM
reg add "HKLM\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0" /v allownullsessionfallback /t REG_DWORD /d 0 /f | Out-Null
## Setting NTLM SSP server and client to require NTLMv2 and 128-bit encryption
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v NTLMMinServerSec /t REG_DWORD /d 537395200 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v NTLMMinClientSec /t REG_DWORD /d 537395200 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Configured NTLM settings" -ForegroundColor white

# System security
## Disable loading of test signed kernel-drivers
bcdedit.exe /set TESTSIGNING OFF | Out-Null
bcdedit.exe /set loadoptions ENABLE_INTEGRITY_CHECKS | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Loading of test-signed kernel drivers disabled" -ForegroundColor white
## Enabling driver signature enforcement
bcdedit.exe /set nointegritychecks off | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Driver signatures enforced" -ForegroundColor white
## Enable DEP for all processes
bcdedit.exe /set "{current}" nx AlwaysOn | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Enabled DEP for all processes" -ForegroundColor white
## Disabling crash dump generation
reg add "HKLM\SYSTEM\CurrentControlSet\control\CrashControl" /v "CrashDumpEnabled" /t REG_DWORD /d 0 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Disabled Crash dump generation" -ForegroundColor white
## Enabling automatic reboot after system crash
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v AutoReboot /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Enabled automatic reboot after system crash" -ForegroundColor white
## Stopping Windows Installer from always installing w/elevated privileges
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated /t REG_DWORD /d 0 /f | Out-Null
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated /t REG_DWORD /d 0 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Set Windows Installer to install without elevated privileges" -ForegroundColor white
## Requiring a password on wakeup
powercfg -SETACVALUEINDEX SCHEME_BALANCED SUB_NONE CONSOLELOCK 1 | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Enabled password required on wakeup" -ForegroundColor white

# Explorer/file settings
## Changing file associations to make sure they have to be executed manually
cmd /c ftype htafile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
cmd /c ftype wshfile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
cmd /c ftype wsffile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
cmd /c ftype batfile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
cmd /c ftype jsfile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
cmd /c ftype jsefile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
cmd /c ftype vbefile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
cmd /c ftype vbsfile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Set file associations" -ForegroundColor white
## Disabling 8.3 filename creation
reg add "HKLM\System\CurrentControlSet\Control\FileSystem" /v NtfsDisable8dot3NameCreation /t REG_DWORD /d 1 /f | Out-Null
## Removing "Run As Different User" from context menus
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoStartBanner /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Classes\batfile\shell\runasuser"	/v SuppressionPolicy /t REG_DWORD /d 4096 /f | Out-Null
reg add "HKLM\SOFTWARE\Classes\cmdfile\shell\runasuser"	/v SuppressionPolicy /t REG_DWORD /d 4096 /f | Out-Null
reg add "HKLM\SOFTWARE\Classes\exefile\shell\runasuser"	/v SuppressionPolicy /t REG_DWORD /d 4096 /f | Out-Null
reg add "HKLM\SOFTWARE\Classes\mscfile\shell\runasuser" /v SuppressionPolicy /t REG_DWORD /d 4096 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Removed 'Run As Different User' from context menus" -ForegroundColor white
## Enabling visibility of hidden files, showing file extensions
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoFolderOptions" /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\NOHIDDEN" /v "CheckedValue" /t REG_DWORD /d 2 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\NOHIDDEN" /v "DefaultValue" /t REG_DWORD /d 2 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\SHOWALL" /v "CheckedValue" /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\SHOWALL" /v "DefaultValue" /t REG_DWORD /d 2 /f | Out-Null
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f | Out-Null
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d 1 /f | Out-Null
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Enabled hidden file and file extension visibility" -ForegroundColor white
## Disabling autorun
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoAutoplayfornonVolume /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoAutorun /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f | Out-Null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Disabled autorun" -ForegroundColor white
## Enabling DEP and heap termination on corruption for File Explorer
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoDataExecutionPrevention /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoHeapTerminationOnCorruption /t REG_DWORD /d 0 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Enabled DEP and heap termination for Explorer" -ForegroundColor white
## Enabling shell protocol protected mode
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v PreXPSP2ShellProtocolBehavior /t REG_DWORD /d 0 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Enabled shell protocol protected mode" -ForegroundColor white
## Strengthening default permissions of internal system objects
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v ProtectionMode /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Enabled strengthening of default object permissions" -ForegroundColor white

# DLL funsies
## Enabling Safe DLL search mode
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v SafeDllSearchMode /t REG_DWORD /d 1 /f | Out-Null
## Blocking DLL loading from remote folders
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v CWDIllegalInDllSearch /t REG_DWORD /d 2 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Enabled safe DLL search mode and blocked loading from unsafe folders" -ForegroundColor white
## Blocking AppInit_DLLs
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v LoadAppInit_DLLs /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" /v LoadAppInit_DLLs /t REG_DWORD /d 0 /f | Out-Null
# reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v RequireSignedAppInit_DLLs /t REG_DWORD /d 1 /f
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Disabled APPInit DLL loading" -ForegroundColor white

# ----------- Misc registry settings ------------
## Disabling remote access to registry paths
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths" /v Machine /t REG_MULTI_SZ /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths" /v Machine /t REG_MULTI_SZ /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Disabled remote access to registry paths" -ForegroundColor white
## Not processing RunOnce List (located at HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce, in HKCU, and Wow6432Node)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v DisableLocalMachineRunOnce /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v DisableLocalMachineRunOnce /t REG_DWORD /d 1 /f | Out-Null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v DisableLocalMachineRunOnce /t REG_DWORD /d 1 /f | Out-Null
reg add "HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v DisableLocalMachineRunOnce /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Disabled processing of RunOnce keys" -ForegroundColor white

# ----------- Misc keyboard and language fixing ------------
## Setting font registry keys
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI (TrueType)" /t REG_SZ /d "segoeui.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Black (TrueType)" /t REG_SZ /d "seguibl.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Black Italic (TrueType)" /t REG_SZ /d "seguibli.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Bold (TrueType)" /t REG_SZ /d "segoeuib.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Bold Italic (TrueType)" /t REG_SZ /d "segoeuiz.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Emoji (TrueType)" /t REG_SZ /d "seguiemj.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Historic (TrueType)" /t REG_SZ /d "seguihis.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Italic (TrueType)" /t REG_SZ /d "segoeuii.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Light (TrueType)" /t REG_SZ /d "segoeuil.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Light Italic (TrueType)" /t REG_SZ /d "seguili.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Semibold (TrueType)" /t REG_SZ /d "seguisb.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Semibold Italic (TrueType)" /t REG_SZ /d "seguisbi.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Semilight (TrueType)" /t REG_SZ /d "seguisli.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Semilight Italic (TrueType)" /t REG_SZ /d "seguisl.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Symbol (TrueType)" /t REG_SZ /d "seguisym.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe UI Variable (TrueType)" /t REG_SZ /d "segoeui.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe MDL2 Assets (TrueType)" /t REG_SZ /d "segmdl2.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe Print (TrueType)" /t REG_SZ /d "segoepr.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe Print Bold (TrueType)" /t REG_SZ /d "segoeprb.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe Script (TrueType)" /t REG_SZ /d "segoesc.ttf" /f | Out-Null
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /v "Segoe Script Bold (TrueType)" /t REG_SZ /d "segoescb.ttf" /f | Out-Null
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\FontSubstitutes" /v "Segoe UI" /f | Out-Null
reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Font Management" /v "Auto Activation Mode" /t REG_DWORD /d 1 /f | Out-Null
reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Font Management" /v "InstallAsLink" /t REG_DWORD /d 0 /f | Out-Null
reg delete "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Font Management" /v "Inactive Fonts" /f | Out-Null
reg delete "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Font Management" /v "Active Languages" /f | Out-Null
reg delete "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Font Management\Auto Activation Languages" /f | Out-Null
## Setting keyboard language to english
Remove-ItemProperty -Path 'HKCU:\Keyboard Layout\Preload' -Name * -Force | Out-Null
reg add "HKCU\Keyboard Layout\Preload" /v 1 /t REG_SZ /d "00000409" /f | Out-Null
## Setting default theme
Start-Process -Filepath "C:\Windows\Resources\Themes\aero.theme"
# Setting UI lang to english
reg add "HKCU\Control Panel\Desktop" /v PreferredUILanguages /t REG_SZ /d en-US /f | Out-Null
reg add "HKLM\Software\Policies\Microsoft\MUI\Settings" /v PreferredUILanguages /t REG_SZ /d en-US /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Font, Themes, and Languages set to default" -ForegroundColor white

# ----------- Ease of access (T1546.008) ------------
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d 506 /f | Out-Null
reg add "HKCU\Control Panel\Accessibility\ToggleKeys" /v Flags /t REG_SZ /d 58 /f | Out-Null
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v Flags /t REG_SZ /d 122 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" /v ShowTabletKeyboard /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows Embedded\EmbeddedLogon" /v BrandingNeutral /t REG_DWORD /d 8 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Configured Ease of Access registry keys" -ForegroundColor white

TAKEOWN /F C:\Windows\System32\sethc.exe /A | Out-Null
ICACLS C:\Windows\System32\sethc.exe /grant administrators:F | Out-Null
Remove-Item C:\Windows\System32\sethc.exe -Force | Out-Null

TAKEOWN /F C:\Windows\System32\Utilman.exe /A | Out-Null
ICACLS C:\Windows\System32\Utilman.exe /grant administrators:F | Out-Null
Remove-Item C:\Windows\System32\Utilman.exe -Force | Out-Null

TAKEOWN /F C:\Windows\System32\osk.exe /A | Out-Null
ICACLS C:\Windows\System32\osk.exe /grant administrators:F | Out-Null
Remove-Item C:\Windows\System32\osk.exe -Force | Out-Null

TAKEOWN /F C:\Windows\System32\Narrator.exe /A | Out-Null
ICACLS C:\Windows\System32\Narrator.exe /grant administrators:F | Out-Null
Remove-Item C:\Windows\System32\Narrator.exe -Force | Out-Null

TAKEOWN /F C:\Windows\System32\Magnify.exe /A | Out-Null
ICACLS C:\Windows\System32\Magnify.exe /grant administrators:F | Out-Null
Remove-Item C:\Windows\System32\Magnify.exe -Force | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Removed vulnerable accessibility features" -ForegroundColor white


# ----------- Service security ------------
## Stopping psexec with the power of svchost
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\PSEXESVC.exe" /v Debugger /t REG_SZ /d "svchost.exe" /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Added psexec mitigation" -ForegroundColor white
## Disabling offline files
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CSC" /v Start /t REG_DWORD /d 4 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Disabled offline files" -ForegroundColor white
## Disabling UPnP
reg add "HKLM\SOFTWARE\Microsoft\DirectPlayNATHelp\DPNHUPnP" /v UPnPMode /t REG_DWORD /d 2 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Disabled UPnP" -ForegroundColor white
## Disabling DCOM cuz why not
reg add "HKLM\Software\Microsoft\OLE" /v EnableDCOM /t REG_SZ /d N /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Disabled DCOM" -ForegroundColor white
## I hate print spooler
if ((Get-Service -Name spooler).Status -eq "Running") {
    Stop-Service -Name spooler -Force -PassThru | Set-Service -StartupType Disabled | Out-Null
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Shut down and disabled Print Spooler" -ForegroundColor white
}

## Secure channel settings
### Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'
reg add "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v RequireSignOrSeal /t REG_DWORD /d 1 /f | Out-Null
### Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'
reg add "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v SealSecureChannel /t REG_DWORD /d 1 /f | Out-Null
### Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'
reg add "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v SignSecureChannel /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Enabled digital signing and encryption of secure channel data" -ForegroundColor white
### Disabling weak encryption protocols
#### Encryption - Ciphers: AES only - IISCrypto (recommended options)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128" /v Enabled /t REG_DWORD /d 0xffffffff /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256" /v Enabled /t REG_DWORD /d 0xffffffff /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56" /v Enabled /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL" /v Enabled /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128" /v Enabled /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128" /v Enabled /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128" /v Enabled /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128" /v Enabled /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128" /v Enabled /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128" /v Enabled /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128" /v Enabled /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168" /v Enabled /t REG_DWORD /d 0 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Configured SChannel encryption ciphers" -ForegroundColor white
#### Encryption - Hashes: All allowed - IISCrypto (recommended options)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5" /v Enabled /t REG_DWORD /d 0x0 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA" /v Enabled /t REG_DWORD /d 0x0 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA256" /v Enabled /t REG_DWORD /d 0xffffffff /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA384" /v Enabled /t REG_DWORD /d 0xffffffff /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA512" /v Enabled /t REG_DWORD /d 0xffffffff /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Configured SChannel hashing algorithms" -ForegroundColor white
#### Encryption - Key Exchanges: All allowed
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" /v Enabled /t REG_DWORD /d 0xffffffff /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" /v ServerMinKeyBitLength /t REG_DWORD /d 0x00001000 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\ECDH" /v Enabled /t REG_DWORD /d 0xffffffff /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS" /v Enabled /t REG_DWORD /d 0xffffffff /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Configured SChannel key exchange algorithms" -ForegroundColor white
#### Encryption - Protocols: TLS 1.0 and higher - IISCrypto (recommended options)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client" /v Enabled /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client" /v DisabledByDefault /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server" /v Enabled /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server" /v DisabledByDefault /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client" /v Enabled /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client" /v DisabledByDefault /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server" /v Enabled /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server" /v DisabledByDefault /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" /v Enabled /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" /v DisabledByDefault /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" /v Enabled /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" /v DisabledByDefault /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" /v Enabled /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" /v DisabledByDefault /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" /v Enabled /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" /v DisabledByDefault /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" /v Enabled /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" /v DisabledByDefault /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" /v Enabled /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" /v DisabledByDefault /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" /v Enabled /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" /v DisabledByDefault /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" /v Enabled /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" /v DisabledByDefault /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" /v Enabled /t REG_DWORD /d 0xffffffff /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" /v DisabledByDefault /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" /v Enabled /t REG_DWORD /d 0xffffffff /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" /v DisabledByDefault /t REG_DWORD /d 0 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Configured SChannel encryption protocols (TLS 1.2)" -ForegroundColor white
#### Encryption - Cipher Suites (order) - All cipher included to avoid application problems
reg add "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" /v Functions /t REG_SZ /d "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA256,TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_3DES_EDE_CBC_SHA,TLS_RSA_WITH_NULL_SHA256,TLS_RSA_WITH_NULL_SHA,TLS_PSK_WITH_AES_256_GCM_SHA384,TLS_PSK_WITH_AES_128_GCM_SHA256,TLS_PSK_WITH_AES_256_CBC_SHA384,TLS_PSK_WITH_AES_128_CBC_SHA256,TLS_PSK_WITH_NULL_SHA384,TLS_PSK_WITH_NULL_SHA256" /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Configured SChannel cipher suites" -ForegroundColor white

## SMB protections
### Disable SMB compression (CVE-2020-0796 - SMBGhost)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v DisableCompression /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Disabled SMB compression" -ForegroundColor white
### Disabling SMB1 server-side processing (Win 7 and below)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Disabled SMB server-side processing (Win 7 and below)" -ForegroundColor white
### Disabling SMB1 client driver
reg add "HKLM\SYSTEM\CurrentControlSet\Services\MrxSmb10" /v Start /t REG_DWORD /d 4 /f | Out-Null
### Disabling client-side processing of SMBv1 protocol (pre-Win8.1/2012R2)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation" /v DependOnService /t REG_MULTI_SZ /d "Bowser\0MRxSMB20\0NSI" /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Disabled SMBv1 client-side processing" -ForegroundColor white
### Enabling SMB2/3 and encryption (modern Windows)
Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force | Out-Null
Set-SmbServerConfiguration -EncryptData $true -Force | Out-Null
### Enabling SMB2/3 (Win 7 and below)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Services\LanmanServer\Parameters" /v SMB2 /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Enabled SMBv2/3 and data encryption" -ForegroundColor white
### Disabling sending of unencrypted passwords to third-party SMB servers
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v EnablePlainTextPassword /t REG_DWORD /d 0 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Disabled sending unencrypted password to third-party SMB servers" -ForegroundColor white
### Disallowing guest logon
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v AllowInsecureGuestAuth /t REG_DWORD /d 0 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Disabled guest logins for SMB" -ForegroundColor white
### Enable SMB signing
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Enabled SMB signing" -ForegroundColor white
## Restricting access to null session pipes and shares
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v RestrictNullSessAccess /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v NullSessionPipes /t REG_MULTI_SZ /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v NullSessionShares /t REG_MULTI_SZ /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Disabled access to null session pipes and shares" -ForegroundColor white
## Disabling SMB admin shares (Server)
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareServer /t REG_DWORD /d 0 /f | Out-Null
## Disabling SMB admin shares (Workstation)
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareWks /t REG_DWORD /d 0 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Disabled SMB administrative shares" -ForegroundColor white
## Hide computer from browse list
reg add "HKLM\System\CurrentControlSet\Services\Lanmanserver\Parameters" /v "Hidden" /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Hidden computer from share browse list" -ForegroundColor white
## Microsoft-Windows-SMBServer\Audit event 3000 shows attempted connections [TEST]
Set-SmbServerConfiguration -AuditSmb1Access $true -Force | Out-Null

## RPC settings
### Disabling RPC usage from a remote asset interacting with scheduled tasks
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule" /v DisableRpcOverTcp /t REG_DWORD /d 1 /f | Out-Null
### Disabling RPC usage from a remote asset interacting with services
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" /v DisableRemoteScmEndpoints /t REG_DWORD /d 1 /f | Out-Null
### Restricting unauthenticated RPC clients
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" /v RestrictRemoteClients /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Configured RPC settings" -ForegroundColor white

## Printer NIGHTMARE NIGHTMARE NIGHTMARE
### Disabling downloading of print drivers over HTTP
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v DisableWebPnPDownload /t REG_DWORD /d 1 /f | Out-Null
### Disabling printing over HTTP
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v DisableHTTPPrinting /t REG_DWORD /d 1 /f | Out-Null
### Preventing regular users from installing printer drivers
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Configured printer registry keys" -ForegroundColor white

## Limiting BITS transfer
reg add "HKLM\Software\Policies\Microsoft\Windows\BITS" /v EnableBITSMaxBandwidth /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\Software\Policies\Microsoft\Windows\BITS" /v MaxTransferRateOffSchedule /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\Software\Policies\Microsoft\Windows\BITS" /v MaxDownloadTime /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Limited BITS transfer speeds" -ForegroundColor white

## Enforcing LDAP client signing (always)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LDAP" /v LDAPClientIntegrity /t REG_DWORD /d 2 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Enabled enforcement of LDAP client signing" -ForegroundColor white

## Prevent insecure encryption suites for Kerberos
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" /v "SupportedEncryptionTypes" /t REG_DWORD /d 2147483640 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Enabled stronger encryption types for Kerberos" -ForegroundColor white

# ----------- Networking settings ------------
## Restrict Internet Communication of several Windows features [TEST]
# reg add "HKLM\SOFTWARE\Policies\Microsoft\InternetManagement" /v "RestrictCommunication" /t REG_DWORD /d 1 /f | Out-Null

# T1557 - Countering poisoning via WPAD - Disabling WPAD
# reg add "HKLM\SYSTEM\CurrentControlSet\Services\WinHTTPAutoProxySvc" /v Start /t REG_DWORD /d 4 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" /v DisableWpad /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Disabled WPAD" -ForegroundColor white
# T1557.001 - Countering poisoning via LLMNR/NBT-NS/MDNS
## Disabling LLMNR
reg add "HKLM\Software\policies\Microsoft\Windows NT\DNSClient" /f | Out-Null
reg add "HKLM\Software\policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Disabled LLMNR" -ForegroundColor white
## Disabling smart multi-homed name resolution
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v DisableSmartNameResolution /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v DisableParallelAandAAAA /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Disabled SMHNR" -ForegroundColor white
## Disabling NBT-NS via registry for all interfaces (might break something)
$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\"
Get-ChildItem $regkey | ForEach-Object { Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 | Out-Null }
## Disabling NetBIOS broadcast-based name resolution
reg add "HKLM\System\CurrentControlSet\Services\NetBT\Parameters" /v NodeType /t REG_DWORD /d 2 /f | Out-Null
## Enabling ability to ignore NetBIOS name release requests except from WINS servers
reg add "HKLM\System\CurrentControlSet\Services\NetBT\Parameters" /v NoNameReleaseOnDemand /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Disabled NBT-NS" -ForegroundColor white
## Disabling mDNS
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v EnableMDNS /t REG_DWORD /d 0 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Disabled mDNS" -ForegroundColor white

## Flushing DNS cache
ipconfig /flushdns | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Flushed DNS cache" -ForegroundColor white

## Disabling ipv6
reg add "HKLM\SYSTEM\CurrentControlSet\Services\tcpip6\Parameters" /v DisabledComponents /t REG_DWORD /d 255 /f | Out-null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Disabled IPv6" -ForegroundColor white

## Disabling source routing for IPv4 and IPv6
reg add "HKLM\SYSTEM\CurrentControlSet\Services\tcpip\Parameters" /v DisableIPSourceRouting /t REG_DWORD /d 2 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Services\tcpip6\Parameters" /v DisableIPSourceRouting /t REG_DWORD /d 2 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Disabled IP source routing" -ForegroundColor white
## Disable password saving for dial-up (lol)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\RasMan\Parameters" /v DisableSavePassword /t REG_DWORD /d 1 /f | Out-Null
## Disable automatic detection of dead network gateways
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v EnableDeadGWDetect /t REG_DWORD /d 0 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Disabled automatic detection of dead gateways" -ForegroundColor white
## Enable ICMP redirect using OSPF
reg add "HKLM\SYSTEM\CurrentControlSet\Services\tcpip\Parameters" /v EnableICMPRedirect /t REG_DWORD /d 0 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Enabled OSPF ICMP redirection" -ForegroundColor white
## Setting how often keep-alive packets are sent (ms)
#reg add "HKLM\SYSTEM\CurrentControlSet\Services\tcpip\Parameters" /v KeepAliveTime /t REG_DWORD /d 300000 /f | Out-Null
#Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Configured keep-alive packet interval" -ForegroundColor white
## Disabling IRDP
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v PerformRouterDiscovery /t REG_DWORD /d 0 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Disabled IRDP" -ForegroundColor white
# Disabling IGMP
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v IGMPLevel /t REG_DWORD /d 0 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Disabled IGMP" -ForegroundColor white
## Setting SYN attack protection level
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v SynAttackProtect /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Configured SYN attack protection level" -ForegroundColor white
## Setting SYN-ACK retransmissions when a connection request is not acknowledged
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v TcpMaxConnectResponseRetransmissions /t REG_DWORD /d 2 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Configured SYN-ACK retransmissions" -ForegroundColor white
## Block remote commands 
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\OLE" /v EnableDCOM /t REG_SZ /d N /F
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Disabled DCOM" -ForegroundColor white
## All in one security onliner I lover uwu 
Set-Processmitigation -System -Enable DEP,EmulateAtlThunks,BottomUp,HighEntropy,SEHOP,SEHOPTelemetry,TerminateOnError,CFG
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Enabled DEP,EmulateAtlThunks,BottomUp,HighEntropy,SEHOP,SEHOPTelemetry,TerminateOnError,CFG" -ForegroundColor white

## VBS SCRIPT BLL DRIZY
reg add "HKCU\SOFTWARE\Microsoft\Windows Script Host\Settings" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows Script Host\Settings" /v ActiveDebugging /t REG_SZ /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows Script Host\Settings" /v DisplayLogo /t REG_SZ /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows Script Host\Settings" /v SilentTerminate /t REG_SZ /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows Script Host\Settings" /v UseWINSAFER /t REG_SZ /d 1 /f
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] VBS SCRIPTS DONT" -ForegroundColor white

reg add "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /v ACSettingIndex /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /v DCSettingIndex /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fAllowToGetHelp /t REG_DWORD /d 0 /f
## Require encrypted RPC connections to Remote Desktop
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fEncryptRPCTraffic /t REG_DWORD /d 1 /f

wmic /interactive:off nicconfig where TcpipNetbiosOptions=0 call SetTcpipNetbios 2
wmic /interactive:off nicconfig where TcpipNetbiosOptions=1 call SetTcpipNetbios 2
Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol
powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2
powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root
reg add "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel" /v MyComputer /t REG_SZ /d "Disabled" /f
reg add "HKLM\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel" /v LocalIntranet /t REG_SZ /d "Disabled" /f
reg add "HKLM\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel" /v Internet /t REG_SZ /d "Disabled" /f
reg add "HKLM\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel" /v TrustedSites /t REG_SZ /d "Disabled" /f
reg add "HKLM\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel" /v UntrustedSites /t REG_SZ /d "Disabled" /f
netsh int tcp set global timestamps=disabled
fsutil behavior set disable8dot3 1
fsutil behavior set disablelastaccess 0

# Get all drive letters
$drives = Get-PSDrive -PSProvider 'FileSystem'

# Iterate through each drive and disable quota
foreach ($drive in $drives) {
    # Construct the command
    $command = "fsutil quota disable " + $drive.Root
    # Execute the command
    Invoke-Expression $command
    Write-Host "Quotas disabled on drive:" $drive.Root
}


# Disables logging of SSL keys
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL' -Name 'KeyLogging' -Value '0'

bcdedit on
bcdedit /set disableelamdrivers yes
bcdedit /set testsigning off
bcdedit /set nx AlwaysOn
#bcdedit /set sos yes
#bcdedit /set lastknowngood on
#bcdedit /set nocrashautoreboot on
#bcdedit /set safebootalternateshell on
#bcdedit /set winpe no
#bcdedit /set tscsyncpolicy Default 
#bcdedit /set testsigning off
#bcdedit /set testsigning off
#bcdedit /set maxgroup on 
#bcdedit /set onecpu on
#bcdedit /set pae ForceDisable 
#bcdedit /set xsavedisable 0
#bcdedit /event ON
#bcdedit /set disabledynamictick yes  
#bcdedit /set forcelegacyplatform no 
#bcdedit /set halbreakpoint yes 
#bcdedit /set bootlog on
#bcdedit /set hypervisorlaunchtype auto
#bcdedit /set nointegritychecks off
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" /v "\\*\SYSVOL" /t REG_SZ /d "RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" /v "\\*\NETLOGON" /t REG_SZ /d "RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v SaveZoneInformation /t REG_DWORD /d 2 /f


}

if ($option -eq 14){

# Getting scheduled tasks
Get-ScheduledTask | Select-Object TaskName | Set-Content -Encoding UTF8 .\scheduledTasks.txt

# Sorting scheduledTasks.txt
Get-Content .\scheduledTasks.txt | Sort-Object | Get-Unique | Set-Content -Encoding UTF8 .\passthrough.txt
Get-Content .\passthrough.txt | Set-Content -Encoding UTF8 .\scheduledTasks.txt

# Getting Standard Windows info out of scheduledTasks.txt
$lines = Get-Content .\scheduledTasks.txt

for ($i=0; $i -lt $lines.Length; $i++) {
    $lines[$i] = $lines[$i].Substring(11)
    $lines[$i] = $lines[$i].Substring(0, $lines[$i].Length-1)
}

Write-Output $lines | Set-Content .\scheduledTasks.txt

# Get a diff of the two files
Compare-Object (Get-Content .\scheduledTasks.txt) (Get-Content .\scheduledTasksWhitelist.txt) | Where-Object {$_.SideIndicator -eq "<="} 
}

if ($option -eq 15){
# Prompt for the location of the user in Active Directory
$user = Read-Host -Prompt 'Give the location of the User in AD for example CN=Users,DC=lakewood,DC=local'

# Update various user properties
Get-ADUser -Filter 'Name -like "*"' -SearchBase $user -Properties DisplayName | ForEach-Object {
    Set-ADUser $_ -TrustedForDelegation $false -PasswordNeverExpires $false -PasswordNotRequired $false -CannotChangePassword $true -AllowReversiblePasswordEncryption $false
}
Get-ADUser -Filter 'Name -like "*"' -SearchBase $user -Properties DisplayName | ForEach-Object {
    Set-ADAccountControl $_ -DoesNotRequirePreAuth $false -AllowReversiblePasswordEncryption $false -TrustedForDelegation $false -TrustedToAuthForDelegation $false -UseDESKeyOnly $false -AccountNotDelegated $true
}

# Adjust encryption types for users
Get-ADUser -Filter 'msDS-SupportedEncryptionTypes -band 0x4' -Properties msDS-SupportedEncryptionTypes |
    ForEach-Object {
        $NewEncTyp = $_.'msDS-SupportedEncryptionTypes' - 0x4
        Set-ADUser -Identity $_ -replace @{'msDS-SupportedEncryptionTypes'=$NewEncTyp}
    }

# Remove sidhistory from users
Get-ADUser -SearchBase $user -Filter {sidhistory -like '*'} -properties sidhistory | ForEach-Object {
    Set-ADUser $_ -remove @{sidhistory=$_.sidhistory.value}
}

# Variable to hold all group names
$groups = Get-ADGroup -Filter *

# Remove sidhistory from groups
$groups | ForEach-Object {
    $group = Get-ADGroup $_ -Properties sidhistory
    if ($group.sidhistory) {
        Set-ADGroup $group -Remove @{sidhistory=$group.sidhistory.value}
    }
}

}

if ($option -eq 17){

# Define the path
$folderPath = "C:\Windows\System32"

# Get the current ACL of the folder
$acl = Get-Acl $folderPath

# Define access rule for System
$systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")

# Define access rule for Administrators
$adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")

# Define access rule for TrustedInstaller
$trustedInstallerRule = New-Object System.Security.AccessControl.FileSystemAccessRule("NT SERVICE\TrustedInstaller", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")

# Define access rule for CREATOR OWNER
$creatorOwnerRule = New-Object System.Security.AccessControl.FileSystemAccessRule("CREATOR OWNER", "FullControl", "ContainerInherit,ObjectInherit", "InheritOnly", "Allow")

# Define access rule for All Application Packages
$appPackagesRule = New-Object System.Security.AccessControl.FileSystemAccessRule("ALL APPLICATION PACKAGES", "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")

# Define access rule for All Restricted Application Packages
$restrictedAppPackagesRule = New-Object System.Security.AccessControl.FileSystemAccessRule("ALL RESTRICTED APPLICATION PACKAGES", "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")

# Define access rule to deny Everyone
$everyoneDenyRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "FullControl", "ContainerInherit,ObjectInherit", "None", "Deny")

# Define access rule to deny Users
$usersDenyRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Users", "FullControl", "ContainerInherit,ObjectInherit", "None", "Deny")

# Add the access rules to the ACL
$acl.SetAccessRule($systemRule)
$acl.SetAccessRule($adminRule)
$acl.SetAccessRule($trustedInstallerRule)
$acl.SetAccessRule($creatorOwnerRule)
$acl.SetAccessRule($appPackagesRule)
$acl.SetAccessRule($restrictedAppPackagesRule)
$acl.SetAccessRule($everyoneDenyRule)
$acl.SetAccessRule($usersDenyRule)

# Set the modified ACL back to the folder
Set-Acl -Path $folderPath -AclObject $acl

# Propagate the ACL to all child items
Get-ChildItem -Path $folderPath -Recurse | Set-Acl -AclObject $acl


}

if ($option -eq 18){
Add-WindowsFeature Adcs-Cert-Authority -IncludeManagementTools
Install-AdcsCertificationAuthority -CAtype EnterpriseRootCA
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v "LDAPServerIntegrity" /t DWORD /d "2" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v "LdapEnforceChannelBinding" /t DWORD /d "2"
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" /v "16 LDAP Interface Events" /t DWORD /d "2"

}

if ($option -eq 19){
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DNS\Parameters" /v "TcpReceivePacketSize" /t REG_DWORD /d 0xFF00 /f
net stop DNS
net start DNS
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" /v SupportedEncryptionTypes /t REG_DWORD /d 2147483640 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v DisableSmartNameResolution /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v DisableParallelAandAAAA /t REG_DWORD /d 1 /f
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters" -Name MaximumUdpPacketSize -Type DWord -Value 0x4C5 -Force
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters" /v MaximumUdpPacketSize /t REG_DWORD /d 0x4C5 /f

Set-DnsServerRRL -Mode Enable -Force
Set-DnsServerResponseRateLimiting -ResetToDefault -Force
Set-DnsServerDiagnostics -EnableLoggingForPluginDllEvent $true
Set-DhcpServerv4DnsSetting -NameProtection $True
Set-DhcpServerv4DnsSetting -DisableDnsPtrRRUpdate 1
Set-DhcpServerv4DnsSetting -DynamicUpdates "Never" -DeleteDnsRRonLeaseExpiry $True
Set-DhcpServerv4DnsSetting -UpdateDnsRRForOlderClients $False
Set-mppreference -DisableDnsOverTcpParsing $False
Set-mppreference -DisableDnsParsing $False
Set-mppreference -EnableDnsSinkhole $True
Set-DnsServerRecursion -Enable $false
Set-DnsServerRecursion -SecureResponse $true

net stop DNS
net start DNS
dnscmd /config /enablednssec 1
dnscmd /config /retrieveroottrustanchors
dnscmd /config /addressanswerlimit 5
dnscmd /config /bindsecondaries 0
dnscmd /config /bootmethod 3
dnscmd /config /defaultagingstate 1
dnscmd /config /defaultnorefreshinterval 0xA8
dnscmd /config /defaultrefreshinterval  0xA8
dnscmd /config /disableautoreversezones  1
dnscmd /config /disablensrecordsautocreation 1
dnscmd /config /dspollinginterval 30
dnscmd /config /dstombstoneinterval 30
dnscmd /config /ednscachetimeout  604,800
dnscmd /config /enableglobalnamessupport 0
dnscmd /config /enableglobalqueryblocklist 1
dnscmd /config /globalqueryblocklist isatap wpad
dnscmd /config /eventloglevel 4
dnscmd /config /forwarddelegations 1
dnscmd /config /forwardingtimeout 0x5
dnscmd /config /globalneamesqueryorder 1
dnscmd /config /EnableVersionQuery 0
dnscmd /config /isslave 0
dnscmd /config /localnetpriority 0
dnscmd /config /logfilemaxsize 0xFFFFFFFF
# dp later dnscmd /config /logfilepath  
dnscmd /config /logipfilterlist 
dnscmd /config /loglevel 0xFFFF
dnscmd /config /maxcachesize 10000
dnscmd /config /maxcachettl 0x15180
dnscmd /config /maxnegativecachettl 0x384
dnscmd /config /namecheckflag 2
dnscmd /config /norecursion 0
dnscmd /config /recursionretry  0x3
dnscmd /config /AllowUpdate 2
dnscmd /config /recursionretry  0xF
dnscmd /config /roundrobin  1  
# dnscmd /config /rpcprotocol 0x2 
dnscmd /config /scavenginginterval 0x0
dnscmd /config /secureresponses 0
dnscmd /config /sendport 0x0
dnscmd /config /strictfileparsing  1
dnscmd /config /updateoptions 0x30F  
dnscmd /config /writeauthorityns  0
dnscmd /config /xfrconnecttimeout    0x1E
dnscmd /config /allowupdate 2
dnscmd /config /enableednsprobes 0
dnscmd /config /localnetprioritynetmask 0x0000ffff
dnscmd /config /openaclonproxyupdates 0
Dnscmd /config /DisableNSRecordsAutoCreation 1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters" /v TcpReceivePacketSize /t REG_DWORD /d 0xFF00 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters" /v MaximumUdpPacketSize /t REG_DWORD /d 0x4C5 /f | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] CVE-2020-1350 and CVE-2020-25705 mitigations in place" -ForegroundColor white
dnscmd /config /enableglobalqueryblocklist 1 | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Enabled global query block list for DNS" -ForegroundColor white
Set-DnsServerRRL -Mode Enable -Force | Out-Null
Set-DnsServerResponseRateLimiting -ResetToDefault -Force | Out-Null
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Response rate limiting enabled" -ForegroundColor white
net stop DNS
net start DNS
}

if ($option -eq 20){

}

if ($option -eq 21){
Import-Module .\new-hardeningkitty\HardeningKitty.psm1
Invoke-HardeningKitty -Mode HailMary -Log -Report -FileFindingList .\new-hardeningkitty\lists\finding_list_0x6d69636b_machine.csv -SkipMachineInformation -SkipRestorePoint
Invoke-HardeningKitty -Mode HailMary -Log -Report -FileFindingList .\new-hardeningkitty\lists\finding_list_0x6d69636b_user.csv -SkipMachineInformation -SkipRestorePoint 
Invoke-HardeningKitty -Mode HailMary -Log -Report -FileFindingList .\new-hardeningkitty\lists\finding_list_cis_microsoft_windows_server_2019_1809_1.2.1_user.csv -SkipMachineInformation -SkipRestorePoint 
Invoke-HardeningKitty -Mode HailMary -Log -Report -FileFindingList .\new-hardeningkitty\lists\finding_list_cis_microsoft_windows_server_2019_1809_1.2.1_machine.csv -SkipMachineInformation -SkipRestorePoint 
Invoke-HardeningKitty -Mode HailMary -Log -Report -FileFindingList .\new-hardeningkitty\lists\finding_list_dod_microsoft_windows_server_2019_member_stig_v2r1_user.csv -SkipMachineInformation -SkipRestorePoint
Invoke-HardeningKitty -Mode HailMary -Log -Report -FileFindingList .\new-hardeningkitty\lists\finding_list_dod_microsoft_windows_server_2019_member_stig_v2r1_machine.csv -SkipMachineInformation -SkipRestorePoint 
Invoke-HardeningKitty -Mode HailMary -Log -Report -FileFindingList .\new-hardeningkitty\lists\finding_list_dod_microsoft_windows_server_2019_dc_stig_v2r1_machine.csv -SkipMachineInformation -SkipRestorePoint
Invoke-HardeningKitty -Mode HailMary -Log -Report -FileFindingList .\new-hardeningkitty\lists\finding_list_dod_microsoft_windows_server_2019_dc_stig_v2r1_user.csv -SkipMachineInformation -SkipRestorePoint 
Invoke-HardeningKitty -Mode HailMary -Log -Report -FileFindingList .\new-hardeningkitty\lists\finding_list_dod_windows_defender_antivirus_stig_v2r1.csv -SkipMachineInformation -SkipRestorePoint 
Invoke-HardeningKitty -Mode HailMary -Log -Report -FileFindingList .\new-hardeningkitty\lists\finding_list_dod_windows_firewall_stig_v1r7.csv -SkipMachineInformation -SkipRestorePoint 
}

if ($option -eq 22){
Import-Module .\new-hardeningkitty\HardeningKitty.psm1
Invoke-HardeningKitty -Mode HailMary -Log -Report -FileFindingList .\new-hardeningkitty\lists\finding_list_0x6d69636b_machine.csv -SkipMachineInformation -SkipRestorePoint
Invoke-HardeningKitty -Mode HailMary -Log -Report -FileFindingList .\new-hardeningkitty\lists\finding_list_0x6d69636b_user.csv -SkipMachineInformation -SkipRestorePoint 
Invoke-HardeningKitty -Mode HailMary -Log -Report -FileFindingList .\new-hardeningkitty\lists\finding_list_cis_microsoft_windows_10_enterprise_21h2_machine.csv -SkipMachineInformation -SkipRestorePoint 
Invoke-HardeningKitty -Mode HailMary -Log -Report -FileFindingList .\new-hardeningkitty\lists\finding_list_cis_microsoft_windows_10_enterprise_21h2_user.csv -SkipMachineInformation -SkipRestorePoint 
Invoke-HardeningKitty -Mode HailMary -Log -Report -FileFindingList .\new-hardeningkitty\lists\finding_list_dod_microsoft_windows_10_stig_v2r1_machine.csv -SkipMachineInformation -SkipRestorePoint
Invoke-HardeningKitty -Mode HailMary -Log -Report -FileFindingList .\new-hardeningkitty\lists\finding_list_dod_microsoft_windows_10_stig_v2r1_user.csv -SkipMachineInformation -SkipRestorePoint 
Invoke-HardeningKitty -Mode HailMary -Log -Report -FileFindingList .\new-hardeningkitty\lists\finding_list_dod_windows_defender_antivirus_stig_v2r1.csv -SkipMachineInformation -SkipRestorePoint 
Invoke-HardeningKitty -Mode HailMary -Log -Report -FileFindingList .\new-hardeningkitty\lists\finding_list_dod_windows_firewall_stig_v1r7.csv -SkipMachineInformation -SkipRestorePoint 
}

if ($option -eq 23){
   dism /online /disable-feature /featurename:TelnetClient
   dism /online /disable-feature /featurename:TelnetServer
   dism /online /disable-feature /featurename:"SMB1Protocol"
   Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
}

if ($option -eq 24){
    #Enable Remote stuff 
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v AllowTSConnections /t REG_DWORD /d 1 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 0 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "AllowSignedFiles" /t REG_DWORD /d 1 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "AllowUnsignedFiles" /t REG_DWORD /d 0 /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "DisablePasswordSaving" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Conferencing" /v "NoRDS" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" /v "AllowRemoteShellAccess" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "AllowSignedFiles" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "AllowUnsignedFiles" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "CreateEncryptedOnlyTickets" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "DisablePasswordSaving" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowToGetHelp" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowUnsolicited" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fDenyTSConnections" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client" /v "fEnableUsbBlockDeviceBySetupClass" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client" /v "fEnableUsbNoAckIsochWriteToDevice" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client" /v "fEnableUsbSelectDeviceByInterface" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v "SecurityLayer" /t REG_DWORD /d 2 /f
    reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v "MinEncryptionLevel" /t REG_DWORD /d 4 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\RemoteAdminSettings" /v "Enabled" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\RemoteDesktop" /v "Enabled" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\UPnPFramework" /v "Enabled" /t REG_DWORD /d 1 /f
}

if ($option -eq 25){

}

if ($option -eq 26){
# Ensure WebAdministration and IISAdministration modules are imported
Import-Module WebAdministration
Import-Module IISAdministration

# Check if the Web-Server feature is installed
if ((Get-WindowsFeature Web-Server).InstallState -eq "Installed") {
    # Set application pool identity type to LocalSystem (4) for all app pools
    Foreach ($item in (Get-ChildItem IIS:\AppPools)) {
        $tempPath = "IIS:\AppPools\" + $item.name
        Set-ItemProperty -Path $tempPath -Name processModel.identityType -Value 4
    }

    # Disable directory browsing for all sites
    Foreach ($item in (Get-ChildItem IIS:\Sites)) {
        $tempPath = "IIS:\Sites\" + $item.name
        Set-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -PSPath $tempPath -Value False
    }

    # Allow PowerShell to modify anonymousAuthentication settings
    Set-WebConfiguration //System.WebServer/Security/Authentication/anonymousAuthentication -Metadata overrideMode -Value Allow -PSPath IIS:/

    # Disable anonymous authentication for all sites
    Foreach ($item in (Get-ChildItem IIS:\Sites)) {
        $tempPath = "IIS:\Sites\" + $item.name
        Set-WebConfiguration -Filter /system.webServer/security/authentication/anonymousAuthentication $tempPath -Value 0
    }

    # Deny PowerShell the ability to modify anonymousAuthentication settings
    Set-WebConfiguration //System.WebServer/Security/Authentication/anonymousAuthentication -Metadata overrideMode -Value Deny -PSPath IIS:/

    # Delete custom error pages
    $sysDrive = $Env:Path.Substring(0, 3)
    $tempPath = (Get-WebConfiguration "//httperrors/error").prefixLanguageFilePath | Select-Object -First 1
    $sysDrive += $tempPath.Substring($tempPath.IndexOf('\') + 1)
    Get-ChildItem -Path $sysDrive -Include *.* -File -Recurse | ForEach-Object { $_.Delete() }
}

# Set various web application and site security settings
# Ensure forms authentication requires SSL
Add-WebConfigurationProperty -Filter "/system.webServer/security/authentication/forms" -Name "requireSSL" -Value $true

# Ensure forms authentication is set to use cookies
Add-WebConfigurationProperty -Filter "/system.webServer/security/authentication/forms" -Name "cookieless" -Value "UseCookies"

# Ensure cookie protection mode is configured for forms authentication
Add-WebConfigurationProperty -Filter "/system.webServer/security/authentication/forms" -Name "protection" -Value "All"

# Ensure passwordFormat is not set to clear
Add-WebConfigurationProperty -Filter "/system.web/membership/providers/add[@name='ProviderName']" -Name "passwordFormat" -Value "Hashed"

# Ensure credentials are not stored in configuration files
$webapps = Get-WebApplication
foreach ($webapp in $webapps) {
    $physicalPath = $webapp.physicalPath
    $webConfigPath = "$physicalPath\web.config"
    if (Test-Path $webConfigPath) {
        $webConfig = [xml](Get-Content $webConfigPath)
        $credentialsElement = $webConfig.SelectSingleNode("/configuration/system.web/httpRuntime/@enablePasswordRetrieval")
        if ($credentialsElement -ne $null) {
            $credentialsElement.ParentNode.RemoveChild($credentialsElement)
            $webConfig.Save($webConfigPath)
            Write-Host "Removed 'credentials' element from $webConfigPath"
        }
    }
}

# Additional security configurations
Add-WebConfigurationProperty -Filter "/system.webServer/deployment" -Name "Retail" -Value "True"
Set-WebConfigurationProperty -Filter "/system.web/compilation" -Name "debug" -Value "False"
Set-WebConfigurationProperty -Filter "/system.webServer/httpErrors" -Name "errorMode" -Value "DetailedLocalOnly"
Set-WebConfigurationProperty -Filter "/system.web/trace" -Name "enabled" -Value "false"
Add-WebConfigurationProperty -Filter "/configuration/system.web/sessionState" -Name "mode" -Value "InProc"
Add-WebConfigurationProperty -Filter "/configuration/system.web/sessionState" -Name "cookieName" -Value "MyAppSession"
Add-WebConfigurationProperty -Filter "/configuration/system.web/sessionState" -Name "cookieless" -Value "UseCookies"
Add-WebConfigurationProperty -Filter "/configuration/system.web/sessionState" -Name "timeout" -Value "20"
Add-WebConfigurationProperty -Filter "/configuration/system.web/machineKey" -Name "validation" -Value "3DES"
Add-WebConfigurationProperty -Filter "/configuration/system.web/machineKey" -Name "validation" -Value "SHA1"
Add-WebConfigurationProperty -Filter "/configuration/system.web/trust" -Name "level" -Value "Full"
Set-WebConfigurationProperty -Filter "system.webServer/httpProtocol/customHeaders/add[@name='X-Powered-By']" -PSPath "IIS:\Sites\Default Web Site" -Name "." -Value $null
Add-WebConfigurationProperty -Filter "/system.webServer/httpProtocol/customHeaders" -Name "remove" -Value @{name="X-Powered-By";}
Add-WebConfigurationProperty -Filter "/system.webServer/httpProtocol/customHeaders" -Name "add" -Value @{name="Server";value="";}
Set-WebConfigurationProperty -Filter "/system.webServer/security/requestFiltering/requestLimits" -Name "maxAllowedContentLength" -Value 104857600
Set-WebConfigurationProperty -Filter "/system.webServer/security/requestFiltering/requestLimits" -Name "maxUrl" -Value 8192
Set-WebConfigurationProperty -Filter "/system.webServer/security/requestFiltering/requestLimits" -Name "maxQueryString" -Value 2048
Set-WebConfigurationProperty -Filter "/system.webServer/security/requestFiltering/allowDoubleEscaping" -Name "enabled" -Value "False"
Set-WebConfigurationProperty -Filter "/system.webServer/security/requestFiltering/denyUrlSequences" -Name "add" -Value @{sequence="%2525"}
Set-WebConfigurationProperty -Filter "/system.webServer/security/requestFiltering" -Name "allowVerb" -Value @{verb="TRACE"; allowed="False"}
Set-WebConfigurationProperty -Filter "/system.webServer/security/requestFiltering/fileExtensions" -Name "allowUnlisted" -Value "False"
Set-WebConfigurationProperty -Filter "/system.webServer/handlers/*" -Name "permissions" -Value "Read,Script"
Add-WebConfigurationProperty -Filter "/system.webServer/isapiCgiRestriction" -Name "notListedIsapisAllowed" -Value "False"
Add-WebConfigurationProperty -Filter "/system.webServer/isapiCgiRestriction" -Name "notListedCgisAllowed" -Value "False"
Set-WebConfigurationProperty -Filter "/system.webServer/security/dynamicIpSecurity" -Name "enabled" -Value "True"
Add-Item -ItemType Directory -Path "C:\NewLogLocation"
Add-WebConfigurationProperty -Filter "/system.applicationHost/sites/siteDefaults/logFile" -Name "directory" -Value "C:\NewLogLocation"
Restart-Service W3SVC
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -Filter "system.applicationHost/sites/siteDefaults/Logfile" -Name "logExtFileFlags" -Value "Date,Time,ClientIP,UserName,ServerIP,Method,UriStem,UriQuery,HttpStatus,Win32Status,BytesSent,BytesRecv,TimeTaken,ServerPort,UserAgent,Cookie,Referer,ProtocolVersion,Host,HttpSubStatus"
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -Filter "system.applicationHost/sites/siteDefaults/tracing/traceFailedRequestsLogging" -Name "enabled" -Value "True"

# FTP Hardening
reg add 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\FTP\Server' /v "AllowAnonymousTLS" /t REG_DWORD /d 0 /f 
reg add 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\FTP\Server' /v "MaxFailedAttempts" /t REG_DWORD /d 3 /f 

Write-Host "Script execution complete."


Read-Host "Ensure SSLv2 is Disabled 7.3.    Ensure SSLv3 is Disabled7.4.    Ensure TLS 1.0 is Disabled7.5.    Ensure TLS 1.1 is Disabled" 
reg add  'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' /v "Enabled" /t REG_DWORD /d 0 /f
reg add 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' /v "Enabled" /t REG_DWORD /d 0 /f
reg add  'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' /v "Enabled" /t REG_DWORD /d 0 /f
reg add 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' /v "Enabled" /t REG_DWORD /d 0 /f
Read-Host "Ensure TLS 1.2 is Enabled"
reg add  'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' /v "Enabled" /t REG_DWORD /d 1 /f
Read-Host "ensure NULL, DES, and RC4 cipher suites are disabled"
reg add 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL' /v "Enabled" /t REG_DWORD /d 0 /f
reg add 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56' /v "Enabled" /t REG_DWORD /d 0 /f
reg add  'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128' /v "Enabled" /t REG_DWORD /d 0 /f
Read-Host "ensure AES 128/128 cipher suite is disabled and AES 256/256 cipher suite is enabled,"
reg add 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128' /v "Enabled" /t REG_DWORD /d 0 /f
reg add 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256' /v "Enabled" /t REG_DWORD /d 1 /f
reg add 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL' /v 'EnabledCipherSuites' /t REG_DWORD /d "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA256,TLS_RSA_WITH_AES_128_CBC_SHA256" /f
} 


if ($option -eq 27){
Import-Module .\PersistenceSniper.psm1
Find-AllPersistence

}

if ($option -eq 28){
$progressPreference = 'silentlyContinue'
Write-Information "Downloading WinGet and its dependencies..."
Invoke-WebRequest -Uri https://aka.ms/getwinget -OutFile Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle
Invoke-WebRequest -Uri https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx -OutFile Microsoft.VCLibs.x64.14.00.Desktop.appx
Invoke-WebRequest -Uri https://github.com/microsoft/microsoft-ui-xaml/releases/download/v2.7.3/Microsoft.UI.Xaml.2.7.x64.appx -OutFile Microsoft.UI.Xaml.2.7.x64.appx
Add-AppxPackage Microsoft.VCLibs.x64.14.00.Desktop.appx
Add-AppxPackage Microsoft.UI.Xaml.2.7.x64.appx
Add-AppxPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle
    Start-Process -FilePath ".\NirsoftTools\UpdateHub-x64.exe"
}

if ($option -eq 29){
Get-BPaModel
Write-Host "input the Id section make sure too not to mess up spelling, and pick which ones you want to run"
$ans = New-Object -TypeName 'System.Collections.ArrayList';
	while ($true) {
    		$input = Read-Host "Enter a value (press Enter to exit):"
   		if ([string]::IsNullOrEmpty($input)) {
        		break
    		}
    	$ans.Add($input)
    	Write-Host "to end loop simply do not input anything"
    	}
for ($var = 0; $var -le $ans.count; $var++) {
	Invoke-BPAModel -ModelId $ans[$var]
	Get-BpaResult $ans[$var]
}
}

if ($option -eq 30){
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy" -Name "Enabled" -Value "1"
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSSQLServer\MSSQLServer" /v "LoginMode" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQLServer\Filestream" /v "EnableLevel" /t REG_DWORD /d 0 /f
}

if ($option -eq 31){
Move-Item -Path ".\powershell.exe.config" -Destination "C:\Windows\System32\WindowsPowerShell\v1.0" -f
Set-ExecutionPolicy AllSigned
Write-Host "Set ExecutionPolicy to AllSigned"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name "__PSLockdownPolicy" -Value 4
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v "EnableScriptBlockLogging" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v "EnableTranscripting" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v "OutputDirectory" /t SZ /d "C:\Windows\System32" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v "EnableInvocationHeader " /t REG_DWORD /d 1 /f
Move-Item -Path ".\powershell_ise.exe.config" -Destination "C:\Windows\System32\WindowsPowerShell\v1.0" -f
}

if ($option -eq 32) {
# Requires running with Administrator privileges

# Get the list of users from the SAM registry
$users = Get-ItemProperty -Path "HKLM:\SAM\SAM\Domains\Account\Users\*" -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -ne 'Names' }

foreach ($user in $users) {
    # Get the binary data from the 'F' value
    $fValue = $user.F

    # Check if the data at the 0030 offset contains the bytes corresponding to F4 01
    # The 0030 offset in PowerShell is 48 in decimal, and we need two bytes from there
    if ($fValue[48] -eq 0xF4 -and $fValue[49] -eq 0x01) {
        Write-Host "Potential RID hijacking detected for user with key: $($user.PSChildName)"
    }
}

}

if ($option -eq 33) {
$taskSchedulerRegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"
$tasks = Get-ChildItem -Path $taskSchedulerRegPath -Recurse
$hiddenTasks = @()

foreach ($task in $tasks) {
    if (-not $task.Property -contains "Id") {
        continue
    }
    try {
        $taskProperties = Get-ItemProperty -Path $task.PSPath
        if (-not $taskProperties.PSObject.Properties.Name -contains "SD") {
            $hiddenTasks += $task.PSChildName
        }
        if ($taskProperties.PSObject.Properties.Name -contains "Index" -and $taskProperties."Index" -eq 0) {
            $hiddenTasks += $task.PSChildName
        }
    } catch {
        Write-Host "Error encountered processing task: $($task.PSChildName). Error: $_"
    }
}

# Display the results
if ($hiddenTasks.Count -gt 0) {
    Write-Host "Hidden tasks detected:"
    $hiddenTasks | ForEach-Object { Write-Host $_ }
} else {
    Write-Host "No hidden tasks detected."
}

}

if ($option -eq 34) {
    bitsadmin /list /allusers
    Write-Host "Please Check for malious bitsadmin tasks, run bitsadmin /reset to clean jobs"
}

if ($option -eq 35) {
# Define the path
$folderPath = Read-Host "please enter a location for this command, all objects in said folder will only give acess to system and admin, while denying everyone, make sure to do this for all major folders"

# Get the current ACL of the folder
$acl = Get-Acl $folderPath

# Clear any existing access rules (optional, use with caution)
#$acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) }

# Define access rule for System
$systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("System", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")

# Define access rule for Administrators
$adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")

# Define access rule for System
$Everyonerule= New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "Modify", "ContainerInherit,ObjectInherit", "None", "Deny")


# Add the access rules to the ACL
$acl.SetAccessRule($systemRule)
$acl.SetAccessRule($adminRule)
$acl.SetAccessRule($Everyonerule)
# Set the modified ACL back to the folder
Set-Acl -Path $folderPath -AclObject $acl

# Propagate the ACL to all child items
Get-ChildItem -Path $folderPath -Recurse | Set-Acl -AclObject $acl

}

if ($option -eq 36) {

    Function Write-Results {
        Param (
                [Parameter(Position=0,Mandatory=$true)]
                [string]$Path,
    
                [Parameter(Position=1,Mandatory=$true)]
                [string]$Domain
            )
    
        $Acl = Get-Acl -Path $Path
        Write-Host $Domain -ForegroundColor DarkRed -BackgroundColor White
        Write-Host ($Path.Substring($Path.IndexOf(":") + 1)) -ForegroundColor DarkRed -BackgroundColor White
        Write-Output -InputObject $Acl.Access
    }
    Function Set-Auditing {
        Param (
            [Parameter(Position=0,Mandatory=$true)]
            [string]$Domain,
    
            [Parameter(Position=1,Mandatory=$true)]
            [AllowEmptyString()]
            [String]$ObjectCN,
    
            [Parameter(Position=2,Mandatory=$true)]
            [System.DirectoryServices.ActiveDirectoryAuditRule[]]$Rules
        )
    
        $DN = (Get-ADDomain -Identity $Domain).DistinguishedName
        [String[]]$Drives = Get-PSDrive | Select-Object -ExpandProperty Name
    
        $TempDrive = "tempdrive"
    
        if ($Drives.Contains($TempDrive)) {
            Write-Host "An existing PSDrive exists with name $TempDrive, temporarily removing" -ForegroundColor Yellow
            $OldDrive = Get-PSDrive -Name $TempDrive
            Remove-PSDrive -Name $TempDrive
        }
    
        $Drive = New-PSDrive -Name $TempDrive -Root "" -PSProvider ActiveDirectory -Server $Domain
        Push-Location -Path "$Drive`:\"
    
        if ($ObjectCN -eq "") {
            $ObjectDN = $DN
        } else {
            $ObjectDN = $ObjectCN + "," + $DN
        }
    
        $ObjectToChange = Get-ADObject -Identity $ObjectDN -Server $Domain
        $Path = $ObjectToChange.DistinguishedName
    
        try {
            $Acl = Get-Acl -Path $Path -Audit
    
            if ($Acl -ne $null) {
                foreach ($Rule in $Rules) {
                    $Acl.AddAuditRule($Rule)
                }
                Set-Acl -Path $Path -AclObject $Acl
                # Write-Results -Path $Path -Domain $Domain
            } else {
                Write-Warning "Could not retrieve the ACL for $Path"
            }
        } catch [System.Exception] {
            Write-Warning $_.ToString()
        }
        Pop-Location
    
        Remove-PSDrive $Drive
    
        if ($OldDrive -ne $null) {
            Write-Host "Recreating original PSDrive" -ForegroundColor Yellow
            New-PSDrive -Name $OldDrive.Name -PSProvider $OldDrive.Provider -Root $OldDrive.Root | Out-Null
            $OldDrive = $null
        }
    }
    Function New-EveryoneAuditRuleSet {
        $Everyone = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)
    
        $EveryoneFail = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
            [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
            [System.Security.AccessControl.AuditFlags]::Failure,
            [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)
    
        $EveryoneSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
            @([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
            [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl,
            [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner),
            [System.Security.AccessControl.AuditFlags]::Success,
            [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)
    
        [System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = @($EveryoneFail, $EveryoneSuccess)
    
        Write-Output -InputObject $Rules
    }
    Function New-DomainControllersAuditRuleSet {
        $Everyone = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)
    
        $EveryoneFail = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
            [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
            [System.Security.AccessControl.AuditFlags]::Failure,
            [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)
    
        $EveryoneWriteDaclSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
            [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl,
            [System.Security.AccessControl.AuditFlags]::Success,
            [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)
    
        $EveryoneWritePropertySuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
            [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
            [System.Security.AccessControl.AuditFlags]::Success,
            [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All)
    
        [System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = @($EveryoneFail, $EveryoneWriteDaclSuccess, $EveryoneWritePropertySuccess)
    
        Write-Output -InputObject $Rules
    }
    Function New-InfrastructureObjectAuditRuleSet {
        $Everyone = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)
    
        $EveryoneFail = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
            [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
            [System.Security.AccessControl.AuditFlags]::Failure,
            [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)
    
        #$objectguid = "cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd" #Guid for change infrastructure master extended right if it was needed
        $EveryoneSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
            @([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
            [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight),
            [System.Security.AccessControl.AuditFlags]::Success,
            [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)
    
        [System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = @($EveryoneFail, $EveryoneSuccess)
    
        Write-Output -InputObject $Rules
    }
    Function New-PolicyContainerAuditRuleSet {
        $Everyone = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)
    
        $EveryoneFail = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
            [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
            [System.Security.AccessControl.AuditFlags]::Failure,
            [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All)
    
        $EveryoneSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
            @([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
            [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl),
            [System.Security.AccessControl.AuditFlags]::Success,
            [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents)
    
        [System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = @($EveryoneFail, $EveryoneSuccess)
    
        Write-Output -InputObject $Rules
    }
    Function New-DomainAuditRuleSet {
        Param (
            [Parameter(Position=0,ValueFromPipeline=$true,Mandatory=$true)]
            [System.Security.Principal.SecurityIdentifier]$DomainSID
        )
    
        $Everyone = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)
        $DomainUsers = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::AccountDomainUsersSid, $DomainSID)
        $Administrators = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $DomainSID)
    
        $EveryoneFail = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
            [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
            [System.Security.AccessControl.AuditFlags]::Failure,
            [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)
    
        $DomainUsersSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($DomainUsers,
            [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
            [System.Security.AccessControl.AuditFlags]::Success,
            [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)
    
        $AdministratorsSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Administrators,
            [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
            [System.Security.AccessControl.AuditFlags]::Success,
            [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)
    
        $EveryoneSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
            @([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
            [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl,
            [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner),
            [System.Security.AccessControl.AuditFlags]::Success,
            [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)
    
        [System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = @($EveryoneFail, $DomainUsersSuccess, $AdministratorsSuccess, $EveryoneSuccess)
    
        Write-Output -InputObject $Rules
    }
    
    Function New-RIDManagerAuditRuleSet {
        $Everyone = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)
    
        $EveryoneFail = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
            [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
            [System.Security.AccessControl.AuditFlags]::Failure,
            [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)
    
        $EveryoneSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
            @([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
            [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight),
            [System.Security.AccessControl.AuditFlags]::Success,
            [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)
    
        [System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = @($EveryoneFail, $EveryoneSuccess)
    
        Write-Output -InputObject $Rules
    }
    # ----------- DC security ------------
    if ($DC) {
        # CVE-2020-1472 - ZeroLogon
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v FullSecureChannelProtection /t REG_DWORD /d 1 /f | Out-Null
        reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v vulnerablechannelallowlist /f | Out-Null
        # Enable netlogon debug logging - %windir%\debug\netlogon.log - watch for event IDs 5827 & 5828
        nltest /DBFlag:2080FFFF | Out-Null
        Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] ZeroLogon mitigations in place" -ForegroundColor white
    
        # CVE-2021-42287/CVE-2021-42278 (SamAccountName / nopac)
        Set-ADDomain -Identity $env:USERDNSDOMAIN -Replace @{"ms-DS-MachineAccountQuota"="0"} | Out-Null
        Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] nopac mitigations in place" -ForegroundColor white
    
        # Enforcing LDAP server signing (always)
        reg add "HKLM\System\CurrentControlSet\Services\NTDS\Parameters" /v "LDAPServerIntegrity" /t REG_DWORD /d 2 /f | Out-Null
        Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Enabled enforcement of signing for LDAP server" -ForegroundColor white
        # Enabling extended protection for LDAP authentication (always)
        reg add "HKLM\System\CurrentControlSet\Services\NTDS\Parameters" /v LdapEnforceChannelBinding /t REG_DWORD /d 2 /f | Out-Null
        Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Enabled extended protection for LDAP authentication" -ForegroundColor white
    
        # Only allowing DSRM Administrator account to be used when ADDS is stopped
        reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v DsrmAdminLogonBehavior /t REG_DWORD /d 1 /f | Out-Null
        Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Configured DSRM administator account usage" -ForegroundColor white
    
        # Disable unauthenticated LDAP
        $RootDSE = Get-ADRootDSE
        $ObjectPath = 'CN=Directory Service,CN=Windows NT,CN=Services,{0}' -f $RootDSE.ConfigurationNamingContext
        Set-ADObject -Identity $ObjectPath -Add @{ 'msDS-Other-Settings' = 'DenyUnauthenticatedBind=1'}
        Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Disabled unauthenticated LDAP" -ForegroundColor white
    
        # Setting max connection time
        [string]$DomainDN = Get-ADDomain -Identity (Get-ADForest -Current LoggedOnUser -Server $env:COMPUTERNAME).RootDomain -Server $env:COMPUTERNAME | Select-Object -ExpandProperty DistinguishedName
        [System.Int32]$MaxConnIdleTime = 180
        [string]$SearchBase = "CN=Query-Policies,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration," + $DomainDN
        [Microsoft.ActiveDirectory.Management.ADEntity]$Policies = get-adobject -SearchBase $SearchBase -Filter 'ObjectClass -eq "queryPolicy" -and Name -eq "Default Query Policy"' -Properties *
        $AdminLimits = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]$Policies.lDAPAdminLimits
    
        for ($i = 0; $i -lt $AdminLimits.Count; $i++) {
            if ($AdminLimits[$i] -match "MaxConnIdleTime=*") {
                break
            }
        }
        if ($i -lt $AdminLimits.Count) {
            $AdminLimits[$i] = "MaxConnIdleTime=$MaxConnIdleTime"
        } else {
            $AdminLimits.Add("MaxConnIdleTime=$MaxConnIdleTime")
        }
        Set-ADObject -Identity $Policies -Clear lDAPAdminLimits
        foreach ($Limit in $AdminLimits) {
            Set-ADObject -Identity $Policies -Add @{lDAPAdminLimits=$Limit}
        }
        Write-Output -InputObject (Get-ADObject -Identity $Policies -Properties * | Select-Object -ExpandProperty lDAPAdminLimits | Where-Object {$_ -match "MaxConnIdleTime=*"})
        Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Configured maximum time for LDAP connections" -ForegroundColor white
    
        # Setting dsHeuristics (disable anon LDAP)
        $DN = ("CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration," + (Get-ADDomain -Identity (Get-ADForest -Current LocalComputer).RootDomain).DistinguishedName)
        $DirectoryService = Get-ADObject -Identity $DN -Properties dsHeuristics
        [string]$Heuristic = $DirectoryService.dsHeuristics
    
        [array]$Array = @()
        if (($Heuristic -ne $null) -and ($Heuristic -ne [System.String]::Empty) -and ($Heuristic.Length -ge 7)) {
            $Array = $Heuristic.ToCharArray()
            $Array[6] = "0";
        } else {
            $Array = "0000000"
        }
    
        [string]$Heuristic = "$Array".Replace(" ", [System.String]::Empty)
        if ($Heuristic -ne $null -and $Heuristic -ne [System.String]::Empty) {
            Set-ADObject -Identity $DirectoryService -Replace @{dsHeuristics = $Heuristic}
        }
        $Result = Get-ADObject -Identity $DirectoryService -Properties dsHeuristics | Select-Object -ExpandProperty dsHeuristics
        if ($Result -ne $null) {
            Write-Output ("dsHeuristics: " + $Result)
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Disabled anonymous LDAP" -ForegroundColor white
        } else {
            Write-Warning "dsHeuristics is not set"
        }
    
        # Resetting NTDS folder and file permissions
        $BuiltinAdministrators = New-Object Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
        $System = New-Object Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
        $CreatorOwner = New-Object Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::CreatorOwnerSid, $null)
        $LocalService = New-Object Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalServiceSid, $null)
    
        $AdministratorAce = New-Object System.Security.AccessControl.FileSystemAccessRule($BuiltinAdministrators,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            @([System.Security.AccessControl.InheritanceFlags]::ObjectInherit, [System.Security.AccessControl.InheritanceFlags]::ContainerInherit),
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
    
        $SystemAce = New-Object System.Security.AccessControl.FileSystemAccessRule($System,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            @([System.Security.AccessControl.InheritanceFlags]::ObjectInherit, [System.Security.AccessControl.InheritanceFlags]::ContainerInherit),
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
    
        $CreatorOwnerAce = New-Object System.Security.AccessControl.FileSystemAccessRule($CreatorOwner,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            @([System.Security.AccessControl.InheritanceFlags]::ObjectInherit, [System.Security.AccessControl.InheritanceFlags]::ContainerInherit),
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
    
        $LocalServiceAce = New-Object System.Security.AccessControl.FileSystemAccessRule($LocalService,
            @([System.Security.AccessControl.FileSystemRights]::AppendData, [System.Security.AccessControl.FileSystemRights]::CreateDirectories),
            [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
    
        $NTDS = Get-ItemProperty -Path "HKLM:\\System\\CurrentControlSet\\Services\\NTDS\\Parameters"
        $DSA = $NTDS.'DSA Database File'
        $Logs = $NTDS.'Database log files path'
        $DSA = $DSA.Substring(0, $DSA.LastIndexOf("\"))
    
        $ACL1 = Get-Acl -Path $DSA
        foreach ($Rule in $ACL1.Access) {
            $ACL1.RemoveAccessRule($Rule) | Out-Null
        }
        $ACL1.AddAccessRule($AdministratorAce)
        $ACL1.AddAccessRule($SystemAce)
    
        Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "INFO" -ForegroundColor yellow -NoNewLine; Write-Host "] Setting $DSA ACL" -ForegroundColor white
    
        # need to change perms on folder to set file perms correctly
        Set-Acl -Path $DSA -AclObject $ACL1
        Get-ChildItem -Path $DSA | ForEach-Object {
            $Acl = Get-Acl -Path $_.FullName
            foreach ($Rule in $Acl.Access) {
                if (-not $Rule.IsInherited) {
                    $Acl.RemoveAccessRule($Rule) | Out-Null
                }
            }
            Set-Acl -Path $_.FullName -AclObject $Acl
        }
    
        # $Logs = path to the NTDS folder, so this fixes perms on that
        $ACL2 = Get-Acl -Path $Logs
        foreach ($Rule in $ACL2.Access) {
            $ACL2.RemoveAccessRule($Rule) | Out-Null
        }
        $ACL2.AddAccessRule($AdministratorAce)
        $ACL2.AddAccessRule($SystemAce)
        $ACL2.AddAccessRule($LocalServiceAce)
        $ACL2.AddAccessRule($CreatorOwnerAce)
    
        Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "INFO" -ForegroundColor yellow -NoNewLine; Write-Host "] Setting $Logs ACL" -ForegroundColor white
    
        Set-Acl -Path $Logs -AclObject $ACL2
        Get-ChildItem -Path $Logs | ForEach-Object {
            $Acl = Get-Acl -Path $_.FullName
            foreach ($Rule in $Acl.Access) {
                if (-not $Rule.IsInherited) {
                    $Acl.RemoveAccessRule($Rule) | Out-Null
                }
            }
            Set-Acl -Path $_.FullName -AclObject $Acl
        }
    
        # surely this will not break things
        $Domain = (Get-ADDomain -Current LocalComputer).DNSRoot
    
        # Set RID Manager Auditing
        [System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = New-RIDManagerAuditRuleSet
        Set-Auditing -Domain $Domain -Rules $Rules -ObjectCN "CN=RID Manager$,CN=System"
        Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Enabled RID Manager auditing" -ForegroundColor white
    
        [System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = New-PolicyContainerAuditRuleSet
        Set-Auditing -Domain $Domain -Rules $Rules -ObjectCN "CN=Policies,CN=System"
        Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Enabled GPO auditing" -ForegroundColor white
    
        [System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = New-DomainAuditRuleSet -DomainSID (Get-ADDomain -Identity $Domain | Select-Object -ExpandProperty DomainSID)
        Set-Auditing -Domain $Domain -Rules $Rules -ObjectCN ""
        Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Enabled auditing on Domain object" -ForegroundColor white
    
        [System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = New-InfrastructureObjectAuditRuleSet
        Set-Auditing -Domain $Domain -Rules $Rules -ObjectCN "CN=Infrastructure"
        Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Enabled auditing on Infrastructure object" -ForegroundColor white
    
        [System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = New-DomainControllersAuditRuleSet
        Set-Auditing -Domain $Domain -Rules $Rules -ObjectCN "OU=Domain Controllers"
        Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Enabled auditing on Domain Controllers object" -ForegroundColor white
    
        [System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = New-EveryoneAuditRuleSet
        Set-Auditing -Domain $Domain -Rules $Rules -ObjectCN "CN=AdminSDHolder,CN=System"
        Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Enabled auditing on AdminSDHolder object" -ForegroundColor white
    

    }
    
}

if ($option -eq 37) {
Import-Module PowerShellAI
$env:OpenAIKey = "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"
}

if ($option -eq 38) {
# Get the current username
$currentUserName = [Environment]::UserName

# Define the Users directory
$usersPath = "C:\Users"

# Get all directories in the Users directory
$directories = Get-ChildItem -Path $usersPath -Directory

foreach ($dir in $directories) {
    # Skip if the directory is the current user's or other important system directories
    if ($dir.Name -ne $currentUserName) {
        # Construct the folder path
        $folderPath = Join-Path -Path $usersPath -ChildPath $dir.Name
        
        # Get all items in the directory
        $items = Get-ChildItem -Path $folderPath -Recurse -Force
        
        foreach ($item in $items) {
            try {
                # Remove item forcefully and silently (suppress confirmation prompt)
                Remove-Item $item.FullName -Force -Recurse -ErrorAction Stop
            } catch {
                # Write out error message if there's an issue
                Write-Host "An error occurred while trying to remove items in the $dir"
            }
        }
    }
}
$items = Get-ChildItem -Path "C:\Users\Default" -Recurse -Force
        
foreach ($item in $items) {
    try {
        # Remove item forcefully and silently (suppress confirmation prompt)
        Remove-Item $item.FullName -Force -Recurse -ErrorAction Stop
    } catch {
        # Write out error message if there's an issue
        Write-Host "An error occurred while trying to remove items in the default"
    }

Write-Host "Cleanup completed."


}
}

if ($option -eq 39) {

    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v DisabledComponents /t REG_DWORD /d 0xff /f
    netsh rpc filter delete filter filterkey=all
    Write-Host "Go Do RPC Manually"
    $filePath = "C:\Windows\System32\flshpnt.dll"
    $registryPath = "HKLM:\SOFTWARE\Microsoft\Netsh"

    # Remove the file if it exists
    if (Test-Path $filePath) {
        Remove-Item $filePath
    }   

if (-Not (Test-Path $filePath)) {
    Write-Output "$filePath removed successfully."
    
    $registryEntries = Get-ItemProperty -Path $registryPath
    foreach ($entry in $registryEntries.PSObject.Properties) {
        if ($entry.Name -ne "(Default)" -and $entry.Value -eq "flshpnt.dll") {
            Remove-ItemProperty -Path $registryPath -Name $entry.Name
            Write-Output "$($entry.Name) removed from registry."
        }
    }
} else {
    Write-Output "Failed to remove $filePath."
}

$allowedDlls = @("ifmon.dll", "rasmontr.dll", "authfwcfg.dll", "dhcpcmonitor.dll", "dot3cfg.dll", "fwcfg.dll", "hnetmon.dll", "netiohlp.dll", "nettrace.dll", "nshhttp.dll", "nshipsec.dll", "nshwfp.dll", "p2pnetsh.dll", "rpcnsh.dll", "WcnNetsh.dll", "whhelper.dll", "wlancfg.dll", "wshelper.dll", "wwancfg.dll")

$registryEntries = Get-ItemProperty -Path $registryPath

foreach ($entry in $registryEntries.PSObject.Properties) {
    if ($entry.Name -ne "(Default)" -and -Not ($allowedDlls -contains $entry.Value)) {
        Remove-ItemProperty -Path $registryPath -Name $entry.Name
        Write-Output "Removed $($entry.Name) from registry as it's not in the allowed list."
    }
}


}

if ($option -eq 40) {

    .\Listdlls.exe listdlls -u

    Read-Host "did you read through all the unsigned dlls?"


    try {
        $userInput = Read-Host "Enter the directory paths, separated by a comma (,)"
        $directories = $userInput.Split(",").Trim()  
        
        if ($directories.Count -eq 0) {
            throw "No directory paths provided."
        }
    
        # Define the file extensions to check
        $fileExtensions = @("*.dll", "*.exe", "*.ps1", "*.bat", "*.cmd")  # Add other extensions if needed
        
        $sigcheckPath = ".\SysinternalsSuite\sigcheck.exe"
        
        if (!(Test-Path $sigcheckPath)) {
            throw "Sigcheck tool at path '$sigcheckPath' not found."
        }
        
        $outputFile = ".\UnsignedFiles.txt"
        
        if (Test-Path $outputFile) {
            Remove-Item $outputFile
        }
        
        foreach ($directory in $directories) {
            if (Test-Path $directory) {
                foreach ($extension in $fileExtensions) {
                    try {
                        $files = Get-ChildItem -Path $directory -Filter $extension -Recurse -ErrorAction Stop
                    } catch {
                        Write-Host "Error retrieving files with extension '$extension' in directory '$directory': $_"
                        continue
                    }
        
                    foreach ($file in $files) {
                        try {
                            $signature = Get-AuthenticodeSignature $file.FullName
                        } catch {
                            Write-Host "Error checking digital signature of the file '$($file.FullName)': $_"
                            continue
                        }
        
                        try {
                            $sigcheckResult = & $sigcheckPath -accepteula -nobanner -a -h -i -e -u -vr -vt $file.FullName
                        } catch {
                            Write-Host "Error executing sigcheck on the file '$($file.FullName)': $_"
                            continue
                        }
        
                        if ($signature.Status -ne "Valid" -or $sigcheckResult -match "not signed") {
                            $outputMessage = "$($file.FullName) is not signed or the signature is not valid."
                            $outputMessage | Out-File -Append -FilePath $outputFile
                            Write-Host $outputMessage  

                            $signature | Out-File -Append -FilePath $outputFile
                            $sigcheckResult | Out-File -Append -FilePath $outputFile

                            Write-Host $signature
                            Write-Host $sigcheckResult
                        }
                    }
                }
            } else {
                Write-Host "The directory $directory does not exist."
            }
        }
        

        if (Test-Path $outputFile) {
            Write-Host "Files without a valid signature have been listed in $outputFile"
        } else {
            Write-Host "All files have a valid signature."
        }
    } catch {
        Write-Host "An unexpected error occurred: $_"
    }
    
}
