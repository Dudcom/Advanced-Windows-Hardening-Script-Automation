

if (![bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")) {
    $confirmAdmin = Write-Host "Note: Powershell has detected that you are not running as Administrator." -ForegroundColor Red
    pause
}

#Determine Service Type
$ad = Read-Host -Prompt "Are you AD? Type 'AD' if so, else continue"
if ($ad -ceq "AD") {
    $ad = $true
    Write-Host "Configuring for AD Server..." -ForegroundColor Green
} else {
    $ad = $false
    Write-Host "Configuring for non AD Server..." -ForegroundColor Green
}

#Create Output Folder
$output = "$env:USERPROFILE\Desktop\ScriptOut"
mkdir $output -ErrorAction SilentlyContinue
mkdir $output\Scripts -ErrorAction SilentlyContinue
Start-Transcript -Path "$output\powershell_log.log"

#Move Scripts to VM
pushd "\\vmware-host\Shared Folders\shared"
copy media.bat $output\Scripts
copy localusers.ps1 $output\Scripts
copy lspconf.bat $output\Scripts
copy prefs.js $output\Scripts
copy Minimum10.sdb $output\Scripts
copy Maximum10.sdb $output\Scripts
copy revertLSP.bat $output\Scripts
robocopy "GPO\{852B35E5-4845-4E3B-8F09-C369A8F0A64D}" "$output\Scripts\{852B35E5-4845-4E3B-8F09-C369A8F0A64D}" /e /NFL /NDL /NJH /NJS /nc /ns /np
copy GPO\LGPO.exe $output\Scripts
copy resetGPO.bat $output\Scripts
#copy setGPO.bat $output\Scripts
if ($ad) {
    copy adusersold.bat $output\Scripts
    copy adusersold.ps1 $output\Scripts
    copy adusers.ps1 $output\Scripts
}
popd

#See Running Connections and Tasks
cd $env:USERPROFILE\Desktop
netstat -anbo | Out-File -FilePath "$output\netstat.txt"
Get-Process | Format-List Name,Path,Description,Company,FileVersion | Out-File -File "$output\tasks.txt"

#Find Media Files
Start-Process $output\Scripts\media.bat -WindowStyle Minimized

#Open README
try {
    .\"CyberPatriot README.lnk"
} catch {
    $readme = Read-Host "Enter the readme file name (from the Desktop)"
    start ".\$readme"
}

#Show Hidden Files
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v Hidden /t REG_DWORD /d 1 /f
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v ShowSuperHidden /t REG_DWORD /d 1 /f
taskkill /f /im explorer.exe
Start-Sleep 2
start explorer.exe

#Group Policy stuff
md $output\gpeditBackup
md $output\gpeditBackup\Machine
md $output\gpeditBackup\User
Copy-Item $env:SYSTEMROOT\System32\GroupPolicy\* -Destination "$output\gpeditBackup" -Recurse -Force

#Copy Forensics Questions to Output
$throwaway = Read-Host "Continue if the forensics question solution methods won't be tarnished"
md $output\Forensics
Copy-Item .\"Forensics *" -Destination $output\Forensics

#Show Tasks
cd $env:SYSTEMROOT\System32
explorer .\tasks
Get-ChildItem -Path .\GroupPolicy\* -Include registry.pol -Recurse | Remove-Item -Verbose
Start-Sleep 1
if ($ad) {
    Backup-GPO -All -Path $output\gpeditBackup
    Get-GPO -All | %{$_.GpoStatus="AllSettingsDisabled"}
    Start-Sleep 1
    gpmc.msc
}
gpedit.msc
Write-Host "Double check startup and shutdown scripts" -ForegroundColor Yellow
gpupdate /force
Start-Sleep 3
Set-Service -Name mpssvc -StartupType Automatic -Status Running
Start-Sleep 2
control update
Start-Sleep 3
netsh advfirewall export $output\f.wfw
Write-Host "Don't forget 'Give me updates for other Microsoft products...'" -ForegroundColor Yellow
netsh advfirewall reset
netsh advfirewall set allprofiles state on
auditpol /set /Category:* /success:enable /failure:enable

cd $env:USERPROFILE\Desktop
if ($ad) {
    start powershell $output\Scripts\adusers.ps1
    pause
    dsa.msc
} else {
    start powershell $output\Scripts\localusers.ps1
    pause
    lusrmgr
}

systempropertiesremote

Write-Host "Friendly reminder to also configure features alongside programs, ex: install Internet Explorer or uninstall whatever" -ForegroundColor Yellow
appwiz
taskmgr
pause

start powershell "netstat -anbo; Read-Host"

Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
fsmgmt.msc

secedit /export /cfg $output\lspbackup.inf

netplwiz
Write-Host "About to set a bunch of reg settings..."
pause

# Registry time :)
$sid = Get-LocalUser -Name $env:USERNAME | Select SID | %{$_.SID.Value}
reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f
reg add HKU\$sid\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers /v DisableAutoplay /t REG_DWORD /d 1 /f
reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v fEncryptRPCTraffic /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v UserAuthentication /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v MinEncryptionLevel /t REG_DWORD /d 3 /f
reg add HKLM\System\CurrentControlSet\Control\LSA /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v ScreenSaverGracePeriod /t REG_DWORD /d 0 /f
if ((Get-WmiObject Win32_OperatingSystem).Caption -like "*Server*") {
    reg add "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" /v IsInstalled /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}" /v IsInstalled /t REG_DWORD /d 1 /f
}

wf

inetcpl
net config server /hidden:yes
notepad C:\Windows\System32\drivers\etc\hosts

#Disable IPv6 Services --> Does not disable IPv6 interface
netsh interface teredo set state disabled
netsh interface ipv6 6to4 set state state=disabled undoonstop=disabled
netsh interface ipv6 isatap set state state=disabled

#Netsh Dump
Write-Host "Creating a netsh dump file..."
netsh dump > $output\netshoutput.txt

#install Programs
Write-Host "Install Programs..."
$downloads = (New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
Invoke-WebRequest "https://download.mozilla.org/?product=firefox-stub&amp;os=win&amp;lang=en-US" -OutFile $downloads\mozilla.exe
Start-Sleep 3
Invoke-WebRequest "https://downloads.malwarebytes.com/file/mb-windows" -OutFile $downloads\malwarebytes.exe
Start-Sleep 3
start "https://www.avast.com/en-us/download-thank-you.php?product=FAV-PPC&locale=en-us&ppc=a&direct=1"
Start-Sleep 3

$throwaway = Read-Host "Make sure all are downloaded before you continue"
cd (New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
& ".\mozilla"
Start-Sleep 3
& ".\malwarebytes"
Start-Sleep 3
& ".\avast_free_antivirus_setup_online"

#Configure Firefox
$throwaway = Read-Host "Make sure Firefox is installed before you continue"
$folders = Get-ChildItem -Path $env:APPDATA\Mozilla\Firefox\Profiles
$src = "$output\Scripts\prefs.js"
$folders | %{copy $src $env:APPDATA\Mozilla\Firefox\Profiles\$_}

Stop-Transcript

Write-Host "Do not forget to add a new user if necessary, check media/archives, run program updates, set program settings, do GPO? etc" -ForegroundColor Magenta
Write-Host "Note: LSP has been skipped. Update first, then configure LSP in ScriptOut" -ForegroundColor Yellow
Write-Host "Script has completed." -ForegroundColor Green