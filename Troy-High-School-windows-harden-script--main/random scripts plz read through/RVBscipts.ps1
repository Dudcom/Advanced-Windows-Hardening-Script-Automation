$option = Read-Host '
1. Firewall 
2. Local Sys
3. DC sys 
4. Crit services local sys
5. Crit services CD 
6. AVs install + autorun sniper 
 '
if ($option -eq 1){
#copied from main.ps1 with some slight modifications in allowing services
Write-Warning "Setting up firewall and configuring..."
    #Disable every pre-existing rule
    Set-NetFirewallRule * -Enabled False -Action NotConfigured
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


#Block multiple Windows features by pre-existing rules
Set-NetFirewallRule -DisplayGroup "AllJoyn Router","*BranchCache*","Cast to Device functionality","Connect","Cortana","Delivery Optimization","DIAL protocol server","Feedback Hub","File and Printer Sharing","Get Office","Groove Music","HomeGroup","iSCSI Service","mDNS","Media Center Extenders","Microsoft Edge","Microsoft Photos","Microsoft Solitaire Collection","Movies & TV","MSN Weather","Network Discovery","OneNote","*Wi-Fi*","Paint 3D","Proximity Sharing","*Remote*","Secure Socket Tunneling Protocol","*Skype*","SNMP Trap","Store","*Smart Card*","Virtual Machine Monitoring","Windows Collaboration Computer Name Registration Service","*Windows Media Player*","Windows Peer to Peer Collaboration Foundation","Windows View 3D Preview","*Wireless*","*WFD*","*Xbox*","3D Builder","Captive Portal Flow","Take a Test","Wallet" -Action Block -Enabled True -Profile Any

#Block multiple insecure protocols by pre-existing rules
Set-NetFirewallRule -DisplayName "*IPv6*","*ICMP*","*SMB*","*UPnP*","*FTP*","*Telnet*" -Action Block -Enabled True -Profile Any

#Block multiple ports with new rule
New-NetFirewallRule -DisplayName "FTP, SSH, Telnet" -LocalPort 20-21 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "FTP, SSH, Telnet" -LocalPort 22 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "FTP, SSH, Telnet" -LocalPort 23 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "HTTP" -LocalPort 80 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "TorPark onion routing" -LocalPort 81 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "TorPark control" -LocalPort 82 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "RTelnet" -LocalPort 107 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "RTelnet" -LocalPort 107 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "DHCPv6" -LocalPort 546-547 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "DHCPv6" -LocalPort 546-547 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Flash" -LocalPort 843 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "B.net (Free HK)" -LocalPort 1119 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "B.net (Free HK)" -LocalPort 1119 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Kazaa" -LocalPort 1214 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Kazaa" -LocalPort 1214 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "WASTE" -LocalPort 1337 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Civ" -LocalPort 1492 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Garena" -LocalPort 1513 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Garena" -LocalPort 1513 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "iSketch" -LocalPort 1626-1627 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Defunct RADIUS Ports" -LocalPort 1645-1646 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Windward" -LocalPort 1707 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Windward" -LocalPort 1707 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "America's Army" -LocalPort 1716 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Microsoft Media Services" -LocalPort 1755 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Microsoft Media Services" -LocalPort 1755 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "SSDP" -LocalPort 1900 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Macro Flash" -LocalPort 1935 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Macro Flash" -LocalPort 1935 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Netop" -LocalPort 1970 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Netop" -LocalPort 1970 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Civ 4" -LocalPort 2033 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Civ 4" -LocalPort 2033 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Warzone 2100" -LocalPort 2100 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Apple Notifs" -LocalPort 2195 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Apple Notifs Feedback" -LocalPort 2196 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "ArmA/Halo" -LocalPort 2302-2305 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "AIM/Ghost" -LocalPort 2351-2368 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Ultima Online" -LocalPort 2593 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Ultima Online" -LocalPort 2593 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Ultima Online 2" -LocalPort 2599 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Ultima Online 2" -LocalPort 2599 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "iSync" -LocalPort 3004 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Xbox LIVE" -LocalPort 3074 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Xbox LIVE" -LocalPort 3074 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "iSCSI" -LocalPort 3260 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "iSCSI" -LocalPort 3260 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "RDP" -LocalPort 3389 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "RDP" -LocalPort 3389 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "PlayStation" -LocalPort 3479-3480 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "PlayStation" -LocalPort 3479-3480 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Cyc" -LocalPort 3645 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Cyc" -LocalPort 3645 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "BF4" -LocalPort 3659 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Blizzard games/Club Penguin" -LocalPort 3724 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Blizzard games/Club Penguin" -LocalPort 3724 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "WarMUX" -LocalPort 3826 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "WarMUX" -LocalPort 3826 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Warframe" -LocalPort 3960 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Warframe again" -LocalPort 3962 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "OpenTTD" -LocalPort 3978-3979 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "OpenTTD" -LocalPort 3978-3979 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Diablo 2" -LocalPort 4000 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Diablo 2" -LocalPort 4000 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Microsoft Ants" -LocalPort 4001 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Amazon Echo" -LocalPort 4070 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Amazon Echo" -LocalPort 4070 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Microsoft Remote Web Workplace admin" -LocalPort 4125 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Apprentice" -LocalPort 4747 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Many things" -LocalPort 5000 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Many things" -LocalPort 5000 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "LoL" -LocalPort 5000-5500 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Neverwinter Nights" -LocalPort 5121 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Apple Notif 2" -LocalPort 5223 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Outlaws" -LocalPort 5310 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "PostgreSQL" -LocalPort 5432 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Freeciv" -LocalPort 5556 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Freeciv" -LocalPort 5556 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "TeamViewer" -LocalPort 5938 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "TeamViewer" -LocalPort 5938 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "More b.net/CP 2 (Free HK)" -LocalPort 6112 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "More b.net/CP 2 (Free HK)" -LocalPort 6112 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "B.net/Club penguin 3" -LocalPort 6113 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "BitTorrent" -LocalPort 6881-6887 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "BitTorrent" -LocalPort 6881-6887 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "BitTorrent" -LocalPort 6888 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "BitTorrent" -LocalPort 6888 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "BitTorrent" -LocalPort 6889-6900 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "BitTorrent" -LocalPort 6889-6900 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Windows Live Messenger" -LocalPort 6891-6900 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Windows Live Messenger" -LocalPort 6891-6900 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "BitTorrent" -LocalPort 6901 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "BitTorrent" -LocalPort 6901 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "BitTorrent" -LocalPort 6902-6968 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "BitTorrent" -LocalPort 6902-6968 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "BitTorrent tracker" -LocalPort 6969 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "HTTP Bittorrent" -LocalPort 7000 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Enemy Territory: Quake Wars" -LocalPort 7133 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Tibia" -LocalPort 7171 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "WatchMe" -LocalPort 7272 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "WatchMe" -LocalPort 7272 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Rise: The Vieneo Province" -LocalPort 7473 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Saratoga FTP" -LocalPort 7542 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Saratoga FTP" -LocalPort 7542 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Killing Floor" -LocalPort 7707-7708 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Killing Floor" -LocalPort 7717 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Just Cause 2, Terraria, GTA:SA" -LocalPort 7777 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Just Cause 2, Terraria, GTA:SA" -LocalPort 7777 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Unreal Tournament" -LocalPort 7777-7788 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Unreal Tournament" -LocalPort 7777-7788 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Killing Floor" -LocalPort 8075 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "MapleStory" -LocalPort 8484 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "QBittorrent" -LocalPort 9000 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Tor" -LocalPort 9030 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Tor" -LocalPort 9050-9051 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Clash of Clans" -LocalPort 9339 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Club Penguin" -LocalPort 9875 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "CrossFire" -LocalPort 10009 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "CrossFire" -LocalPort 10009 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Touhou" -LocalPort 10080 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Lock On: Modern Air Combat" -LocalPort 10308 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Lock On: Modern Air Combat" -LocalPort 10308 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "SWAT 4" -LocalPort 10480 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "SWAT 4" -LocalPort 10480 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Farming Simulator 2011" -LocalPort 10823 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Savage: Battle for Newerth" -LocalPort 11235 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Savage: Battle for Newerth" -LocalPort 11235 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "OpenRCT2" -LocalPort 11753 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 12012-12013 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 12012-12013 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Second Life" -LocalPort 12035 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Second Life" -LocalPort 12043 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Second Life" -LocalPort 12046 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Cube World" -LocalPort 12345 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Cube World" -LocalPort 12345 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Second Life" -LocalPort 13000-13050 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "CrossFire (again)" -LocalPort 13008 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "CrossFire (again)" -LocalPort 13008 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Battlefield 1942" -LocalPort 14567 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Battlefield Vietnam" -LocalPort 15567 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "XPilot" -LocalPort 15345 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "XPilot" -LocalPort 15345 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Project Zomboid" -LocalPort 16261 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Project Zomboid" -LocalPort 16261 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Battlefield 2" -LocalPort 16567 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Worms" -LocalPort 17011 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Monero P2P" -LocalPort 18080 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18200 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18200 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18201 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18201 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18206 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18206 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18300-18301 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18300-18301 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18306 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18306 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Bitcoin" -LocalPort 18333 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18400-18401 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18400-18401 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18505-18506 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18505-18506 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "X-BEAT" -LocalPort 18605-18606 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "X-BEAT" -LocalPort 18605-18606 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Minecraft: Bedrock Edition" -LocalPort 19132-19133 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Killing Floor" -LocalPort 20560 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Killing Floor" -LocalPort 20560 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "0 A.D. Empires Ascendant" -LocalPort 20595 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Duke Nukem 3D" -LocalPort 23513 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Duke Nukem 3D" -LocalPort 23513 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "StepMania: Online: DDR" -LocalPort 24842 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "StepMania: Online: DDR" -LocalPort 24842 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Minecraft" -LocalPort 25565 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Minecraft" -LocalPort 25565 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Minecraft" -LocalPort 25575 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Quake, EVE Online, Xonotic" -LocalPort 26000 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Quake, EVE Online, Xonotic" -LocalPort 26000 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "EVE Online" -LocalPort 26900-26901 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "QuakeWorld" -LocalPort 27000-27006 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Steam" -LocalPort 27000-27015 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Unturned" -LocalPort 27015-27018 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Steam" -LocalPort 27015-27030 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Steam" -LocalPort 27015-27030 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Magicka" -LocalPort 27016 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Magicka" -LocalPort 27016 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Steam" -LocalPort 27031 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Steam" -LocalPort 27036-27037 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Steam" -LocalPort 27036-27037 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "QuakeWorld" -LocalPort 27500-27900 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Quake II" -LocalPort 27901-27910 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "OpenArena" -LocalPort 27950 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Enemy Territoy, Quake III, Quake Live" -LocalPort 27960-27969 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Starsiege: Tribes" -LocalPort 28001 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Starsiege: Tribes" -LocalPort 28001 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Rust" -LocalPort 28015 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "AssaultCube Reloaded" -LocalPort 28770-28771 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Cube 2: Sauerbraten" -LocalPort 28785-28786 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Killing Floor" -LocalPort 28852 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Killing Floor" -LocalPort 28852 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Nintendo Wi-Fi" -LocalPort 28910 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Nintendo Wi-Fi" -LocalPort 28910 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Call of Duty" -LocalPort 28960 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Call of Duty" -LocalPort 28960 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Perfect World" -LocalPort 29000 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Perfect World" -LocalPort 29000 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Jedi Knight" -LocalPort 29070 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Jedi Knight" -LocalPort 29070 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Nintendo Wi-Fi" -LocalPort 29900-29901 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Nintendo Wi-Fi" -LocalPort 29900-29901 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Nintendo Wi-Fi" -LocalPort 29920 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Nintendo Wi-Fi" -LocalPort 29920 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "TetriNET" -LocalPort 31457 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Ace of Spades" -LocalPort 32887 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Infestation: Survivor Stories" -LocalPort 34000 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Factorio" -LocalPort 34197 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Runescape" -LocalPort 43594-43595 -Protocol TCP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Runescape" -LocalPort 43594-43595 -Protocol UDP -Action Block -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "Mu Online" -LocalPort 44405 -Protocol TCP -Action Block -Enabled True -Direction Inbound

New-NetFirewallRule -DisplayName "FTP, SSH, Telnet" -LocalPort 20-21 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "FTP, SSH, Telnet" -LocalPort 22 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "FTP, SSH, Telnet" -LocalPort 23 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "HTTP" -LocalPort 80 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "TorPark onion routing" -LocalPort 81 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "TorPark control" -LocalPort 82 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "RTelnet" -LocalPort 107 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "RTelnet" -LocalPort 107 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "DHCPv6" -LocalPort 546-547 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "DHCPv6" -LocalPort 546-547 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Flash" -LocalPort 843 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "B.net (Free HK)" -LocalPort 1119 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "B.net (Free HK)" -LocalPort 1119 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Kazaa" -LocalPort 1214 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Kazaa" -LocalPort 1214 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "WASTE" -LocalPort 1337 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Civ" -LocalPort 1492 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Garena" -LocalPort 1513 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Garena" -LocalPort 1513 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "iSketch" -LocalPort 1626-1627 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Defunct RADIUS Ports" -LocalPort 1645-1646 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Windward" -LocalPort 1707 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Windward" -LocalPort 1707 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "America's Army" -LocalPort 1716 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Microsoft Media Services" -LocalPort 1755 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Microsoft Media Services" -LocalPort 1755 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "SSDP" -LocalPort 1900 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Macro Flash" -LocalPort 1935 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Macro Flash" -LocalPort 1935 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Netop" -LocalPort 1970 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Netop" -LocalPort 1970 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Civ 4" -LocalPort 2033 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Civ 4" -LocalPort 2033 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Warzone 2100" -LocalPort 2100 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Apple Notifs" -LocalPort 2195 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Apple Notifs Feedback" -LocalPort 2196 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "ArmA/Halo" -LocalPort 2302-2305 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "AIM/Ghost" -LocalPort 2351-2368 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Ultima Online" -LocalPort 2593 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Ultima Online" -LocalPort 2593 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Ultima Online 2" -LocalPort 2599 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Ultima Online 2" -LocalPort 2599 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "iSync" -LocalPort 3004 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Xbox LIVE" -LocalPort 3074 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Xbox LIVE" -LocalPort 3074 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "iSCSI" -LocalPort 3260 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "iSCSI" -LocalPort 3260 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "RDP" -LocalPort 3389 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "RDP" -LocalPort 3389 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "PlayStation" -LocalPort 3479-3480 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "PlayStation" -LocalPort 3479-3480 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Cyc" -LocalPort 3645 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Cyc" -LocalPort 3645 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "BF4" -LocalPort 3659 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Blizzard games/Club Penguin" -LocalPort 3724 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Blizzard games/Club Penguin" -LocalPort 3724 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "WarMUX" -LocalPort 3826 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "WarMUX" -LocalPort 3826 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Warframe" -LocalPort 3960 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Warframe again" -LocalPort 3962 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "OpenTTD" -LocalPort 3978-3979 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "OpenTTD" -LocalPort 3978-3979 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Diablo 2" -LocalPort 4000 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Diablo 2" -LocalPort 4000 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Microsoft Ants" -LocalPort 4001 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Amazon Echo" -LocalPort 4070 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Amazon Echo" -LocalPort 4070 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Microsoft Remote Web Workplace admin" -LocalPort 4125 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Apprentice" -LocalPort 4747 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Many things" -LocalPort 5000 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Many things" -LocalPort 5000 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "LoL" -LocalPort 5000-5500 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Neverwinter Nights" -LocalPort 5121 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Apple Notif 2" -LocalPort 5223 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Outlaws" -LocalPort 5310 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "PostgreSQL" -LocalPort 5432 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Freeciv" -LocalPort 5556 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Freeciv" -LocalPort 5556 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "TeamViewer" -LocalPort 5938 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "TeamViewer" -LocalPort 5938 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "More b.net/CP 2 (Free HK)" -LocalPort 6112 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "More b.net/CP 2 (Free HK)" -LocalPort 6112 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "B.net/Club penguin 3" -LocalPort 6113 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "BitTorrent" -LocalPort 6881-6887 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "BitTorrent" -LocalPort 6881-6887 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "BitTorrent" -LocalPort 6888 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "BitTorrent" -LocalPort 6888 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "BitTorrent" -LocalPort 6889-6900 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "BitTorrent" -LocalPort 6889-6900 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Windows Live Messenger" -LocalPort 6891-6900 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Windows Live Messenger" -LocalPort 6891-6900 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "BitTorrent" -LocalPort 6901 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "BitTorrent" -LocalPort 6901 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "BitTorrent" -LocalPort 6902-6968 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "BitTorrent" -LocalPort 6902-6968 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "BitTorrent tracker" -LocalPort 6969 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "HTTP Bittorrent" -LocalPort 7000 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Enemy Territory: Quake Wars" -LocalPort 7133 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Tibia" -LocalPort 7171 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "WatchMe" -LocalPort 7272 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "WatchMe" -LocalPort 7272 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Rise: The Vieneo Province" -LocalPort 7473 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Saratoga FTP" -LocalPort 7542 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Saratoga FTP" -LocalPort 7542 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Killing Floor" -LocalPort 7707-7708 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Killing Floor" -LocalPort 7717 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Just Cause 2, Terraria, GTA:SA" -LocalPort 7777 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Just Cause 2, Terraria, GTA:SA" -LocalPort 7777 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Unreal Tournament" -LocalPort 7777-7788 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Unreal Tournament" -LocalPort 7777-7788 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Killing Floor" -LocalPort 8075 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "MapleStory" -LocalPort 8484 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "QBittorrent" -LocalPort 9000 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Tor" -LocalPort 9030 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Tor" -LocalPort 9050-9051 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Clash of Clans" -LocalPort 9339 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Club Penguin" -LocalPort 9875 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "CrossFire" -LocalPort 10009 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "CrossFire" -LocalPort 10009 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Touhou" -LocalPort 10080 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Lock On: Modern Air Combat" -LocalPort 10308 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Lock On: Modern Air Combat" -LocalPort 10308 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "SWAT 4" -LocalPort 10480 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "SWAT 4" -LocalPort 10480 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Farming Simulator 2011" -LocalPort 10823 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Savage: Battle for Newerth" -LocalPort 11235 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Savage: Battle for Newerth" -LocalPort 11235 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "OpenRCT2" -LocalPort 11753 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 12012-12013 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 12012-12013 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Second Life" -LocalPort 12035 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Second Life" -LocalPort 12043 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Second Life" -LocalPort 12046 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Cube World" -LocalPort 12345 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Cube World" -LocalPort 12345 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Second Life" -LocalPort 13000-13050 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "CrossFire (again)" -LocalPort 13008 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "CrossFire (again)" -LocalPort 13008 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Battlefield 1942" -LocalPort 14567 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Battlefield Vietnam" -LocalPort 15567 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "XPilot" -LocalPort 15345 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "XPilot" -LocalPort 15345 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Project Zomboid" -LocalPort 16261 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Project Zomboid" -LocalPort 16261 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Battlefield 2" -LocalPort 16567 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Worms" -LocalPort 17011 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Monero P2P" -LocalPort 18080 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18200 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18200 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18201 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18201 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18206 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18206 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18300-18301 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18300-18301 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18306 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18306 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Bitcoin" -LocalPort 18333 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18400-18401 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18400-18401 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18505-18506 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Audition Online Dance Battle" -LocalPort 18505-18506 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "X-BEAT" -LocalPort 18605-18606 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "X-BEAT" -LocalPort 18605-18606 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Minecraft: Bedrock Edition" -LocalPort 19132-19133 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Killing Floor" -LocalPort 20560 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Killing Floor" -LocalPort 20560 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "0 A.D. Empires Ascendant" -LocalPort 20595 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Duke Nukem 3D" -LocalPort 23513 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Duke Nukem 3D" -LocalPort 23513 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "StepMania: Online: DDR" -LocalPort 24842 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "StepMania: Online: DDR" -LocalPort 24842 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Minecraft" -LocalPort 25565 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Minecraft" -LocalPort 25565 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Minecraft" -LocalPort 25575 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Quake, EVE Online, Xonotic" -LocalPort 26000 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Quake, EVE Online, Xonotic" -LocalPort 26000 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "EVE Online" -LocalPort 26900-26901 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "QuakeWorld" -LocalPort 27000-27006 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Steam" -LocalPort 27000-27015 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Unturned" -LocalPort 27015-27018 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Steam" -LocalPort 27015-27030 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Steam" -LocalPort 27015-27030 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Magicka" -LocalPort 27016 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Magicka" -LocalPort 27016 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Steam" -LocalPort 27031 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Steam" -LocalPort 27036-27037 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Steam" -LocalPort 27036-27037 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "QuakeWorld" -LocalPort 27500-27900 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Quake II" -LocalPort 27901-27910 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "OpenArena" -LocalPort 27950 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Enemy Territoy, Quake III, Quake Live" -LocalPort 27960-27969 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Starsiege: Tribes" -LocalPort 28001 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Starsiege: Tribes" -LocalPort 28001 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Rust" -LocalPort 28015 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "AssaultCube Reloaded" -LocalPort 28770-28771 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Cube 2: Sauerbraten" -LocalPort 28785-28786 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Killing Floor" -LocalPort 28852 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Killing Floor" -LocalPort 28852 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Nintendo Wi-Fi" -LocalPort 28910 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Nintendo Wi-Fi" -LocalPort 28910 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Call of Duty" -LocalPort 28960 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Call of Duty" -LocalPort 28960 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Perfect World" -LocalPort 29000 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Perfect World" -LocalPort 29000 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Jedi Knight" -LocalPort 29070 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Jedi Knight" -LocalPort 29070 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Nintendo Wi-Fi" -LocalPort 29900-29901 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Nintendo Wi-Fi" -LocalPort 29900-29901 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Nintendo Wi-Fi" -LocalPort 29920 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Nintendo Wi-Fi" -LocalPort 29920 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "TetriNET" -LocalPort 31457 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Ace of Spades" -LocalPort 32887 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Infestation: Survivor Stories" -LocalPort 34000 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Factorio" -LocalPort 34197 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Runescape" -LocalPort 43594-43595 -Protocol TCP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Runescape" -LocalPort 43594-43595 -Protocol UDP -Action Block -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "Mu Online" -LocalPort 44405 -Protocol TCP -Action Block -Enabled True -Direction Outbound

#Block multiple protocols with new rule
New-NetFirewallRule -DisplayName "ICMPv4" -Protocol ICMPv4 -Action Block -Enabled True -Direction Inbound -Profile Any
New-NetFirewallRule -DisplayName "ICMPv4" -Protocol ICMPv4 -Action Block -Enabled True -Direction Outbound -Profile Any
New-NetFirewallRule -DisplayName "ICMPv6" -Protocol ICMPv6 -Action Block -Enabled True -Direction Inbound -Profile Any
New-NetFirewallRule -DisplayName "ICMPv6" -Protocol ICMPv6 -Action Block -Enabled True -Direction Outbound -Profile Any

#Allow multiple ports with new rule
New-NetFirewallRule -DisplayName "HTTPS" -LocalPort 443 -Protocol TCP -Action Allow -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "NTP" -LocalPort 123 -Protocol UDP -Action Allow -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "NTP" -LocalPort 123 -Protocol UDP -Action Allow -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "SSH" -LocalPort 22 -Protocol TCP -Action Allow -Enabled True -Direction Outbound
New-NetFirewallRule -DisplayName "DNS" -LocalPort 53 -Protocol UDP -Action Allow -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "DNS" -LocalPort 53 -Protocol TCP -Action Allow -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "SMB" -LocalPort 445 -Protocol TCP -Action Allow -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "SQL default instance" -LocalPort 1433 -Protocol TCP -Action Allow -Enabled True -Direction Inbound
New-NetFirewallRule -DisplayName "SQL browser" -LocalPort 1434 -Protocol UDP -Action Allow -Enabled True -Direction Inbound



#Allow multiple features with pre-existing rules
Set-NetFirewallRule -DisplayName "*Defender*" -Enabled True -Action Allow -Profile Any
}
if ($option -eq 2){}
if ($option -eq 3){}
if ($option -eq 4){
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 1
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'SecurityLayer' -Value 2
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthEncryptionLevel' -Value 2
Disable-NetFirewallRule -DisplayGroup "Remote Desktop"
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'PortNumber' -Value 3389
}
if ($option -eq 5){
#https://github.com/zahav/powershell-iis-hardening
Read-Host 'SMB HARDENING'
dism /online /disable-feature /featurename:"SMB1Protocol"
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
#smb lateral movement
Set-MpPreference -AttackSurfaceReductionRules_Ids D1E49AAC-8F56-4280-B9BA-993A6D -AttackSurfaceReductionRules_Actions Enabled
#Encrypt SMB Passwords
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "SMB1" /t REG_DWORD /d "0x00000000" /f
Set-SmbServerConfiguration -EncryptData $true -Force
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "DisableCompression" /t REG_DWORD /d "1" /f
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Set-SmbServerConfiguration -EncryptData $true -Force

Read-Host 'IIS HARDENING'
#IIS PowerShell
#---------------------------------------------------------------------------------------------------------------------------------------
Import-Module WebAdministration
Import-Module IISAdministration
#Set application privelages to minimum
Foreach($item in (Get-ChildItem IIS:\AppPools)) { $tempPath="IIS:\AppPools\"; $tempPath+=$item.name; Set-ItemProperty -Path $tempPath -name processModel.identityType -value 4}
#Disable Directory Browse
Foreach($item in (Get-ChildItem IIS:\Sites)) { $tempPath="IIS:\Sites\"; $tempPath+=$item.name; Set-WebConfigurationProperty -filter /system.webServer/directoryBrowse -name enabled -PSPath $tempPath -value False}
#Allow Powershell to Write the anonymousAuthentication value
Set-WebConfiguration //System.WebServer/Security/Authentication/anonymousAuthentication -metadata overrideMode -value Allow -PSPath IIS:/
#Disable Anonymous Authenitcation
Foreach($item in (Get-ChildItem IIS:\Sites)) { $tempPath="IIS:\Sites\"; $tempPath+=$item.name; Set-WebConfiguration -filter /system.webServer/security/authentication/anonymousAuthentication $tempPath -value 0}
#Deny Powershell to Write the anonymousAuthentication value
Set-WebConfiguration //System.WebServer/Security/Authentication/anonymousAuthentication -metadata overrideMode -value Deny -PSPath IIS:/
#Delete Custom Error Pages
$sysDrive=$Env:Path.Substring(0,3); $tempPath=((Get-WebConfiguration "//httperrors/error").prefixLanguageFilePath | Select-Object -First 1) ; $sysDrive+=$tempPath.Substring($tempPath.IndexOf('\')+1); Get-ChildItem -Path $sysDrive -Include *.* -File -Recurse | foreach { $_.Delete()}
Read-Host 'Ensure forms authentication requires SSL'
Add-WebConfigurationProperty -Filter "/system.webServer/security/authentication/forms" -Name "requireSSL" -Value $true
Read-Host ' Ensure forms authentication is set to use cookies'
Add-WebConfigurationProperty -Filter "/system.webServer/security/authentication/forms" -Name "cookieless" -Value "UseCookies"
Read-Host ' Ensure cookie protection mode is configured for forms authentication'
Add-WebConfigurationProperty -Filter "/system.webServer/security/authentication/forms" -Name "protection" -Value "All"
Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/<website name>' -filter 'system.web/authentication/forms' -name 'protection' -value 'All'
#another way to do the same command use this if the other one doesn't work 

Read-Host ' Ensure passwordFormat is not set to clear'
Add-WebConfigurationProperty -Filter "/system.web/membership/providers/add[@name='ProviderName']" -Name "passwordFormat" -Value "Hashed"
Read-Host ' Ensure credentials are not stored in configuration files'
# Get all web applications
$webapps = Get-WebApplication

# Loop through each web application
foreach ($webapp in $webapps) {
    # Get the physical path of the web application
    $physicalPath = $webapp.physicalPath

    # Get the web.config file path
    $webConfigPath = "$physicalPath\web.config"

    # Check if the web.config file exists
    if (Test-Path $webConfigPath) {
        # Load the web.config file as an XML document
        $webConfig = [xml](Get-Content $webConfigPath)

        # Check if the 'credentials' element exists
        $credentialsElement = $webConfig.SelectSingleNode("/configuration/system.web/httpRuntime/@enablePasswordRetrieval")
        if ($credentialsElement -ne $null) {
            # Remove the 'credentials' element from the web.config file
            $credentialsElement.ParentNode.RemoveChild($credentialsElement)

            # Save the changes to the web.config file
            $webConfig.Save($webConfigPath)

            Write-Host "Removed 'credentials' element from $webConfigPath"
        }
    }
}

Write-Host "Script execution complete."
Read-Host "Ensure 'deployment method retail' is set"
Add-WebConfigurationProperty -Filter "/system.webServer/deployment" -Name "Retail" -Value "True"
Read-Host "Ensure 'debug' is turned off"
Set-WebConfigurationProperty -Filter "/system.web/compilation" -Name "debug" -Value "False"
Read-Host "Ensure IIS HTTP detailed errors are hidden from displaying remotely"
Set-WebConfigurationProperty -Filter "/system.webServer/httpErrors" -Name "errorMode" -Value "DetailedLocalOnly"
Read-Host "Ensure ASP.NET stack tracing is not enabled"
Set-WebConfigurationProperty -Filter "/system.web/trace" -Name "enabled" -Value "false"
Read-Host "Ensure 'httpcookie' mode is configured for session state"
Add-WebConfigurationProperty -Filter "/configuration/system.web/sessionState" -Name "mode" -Value "InProc"
Add-WebConfigurationProperty -Filter "/configuration/system.web/sessionState" -Name "cookieName" -Value "MyAppSession"
Add-WebConfigurationProperty -Filter "/configuration/system.web/sessionState" -Name "cookieless" -Value "UseCookies"
Add-WebConfigurationProperty -Filter "/configuration/system.web/sessionState" -Name "timeout" -Value "20"
#Ensure 'MachineKey validation method - .Net 3.5' is configured
Add-WebConfigurationProperty -Filter "/configuration/system.web/machineKey" -Name "validation" -Value "3DES"
#Ensure 'MachineKey validation method - .Net 4.5' is configured
Add-WebConfigurationProperty -Filter "/configuration/system.web/machineKey" -Name "validation" -Value "SHA1"
# Ensure global .NET trust level is configured
Add-WebConfigurationProperty -Filter "/configuration/system.web/trust" -Name "level" -Value "Full"
#Ensure X-Powered-By Header is removed
# Remove the X-Powered-By header from the default web site
$val1 = Read-Host "enter the path of the webserver"
Set-WebConfigurationProperty -Filter "system.webServer/httpProtocol/customHeaders/add[@name='X-Powered-By']" -PSPath "IIS:\Sites\Default Web Site" -Name "." -Value $null

Add-WebConfigurationProperty -Filter "/system.webServer/httpProtocol/customHeaders" -Name "remove" -Value @{name="X-Powered-By";}
#Ensure Server Header is removed
Add-WebConfigurationProperty -Filter "/system.webServer/httpProtocol/customHeaders" -Name "add" -Value @{name="Server";value="";}
#Ensure 'maxAllowedContentLength' is configured (100M)
Set-WebConfigurationProperty -Filter "/system.webServer/security/requestFiltering/requestLimits" -Name "maxAllowedContentLength" -Value 104857600
#Ensure 'maxURL request filter' is configured
Set-WebConfigurationProperty -Filter "/system.webServer/security/requestFiltering/requestLimits" -Name "maxUrl" -Value 8192
#Ensure 'MaxQueryString request filter' is configured
Set-WebConfigurationProperty -Filter "/system.webServer/security/requestFiltering/requestLimits" -Name "maxQueryString" -Value 2048
#Ensure non-ASCII characters in URLs are not allowed
Set-WebConfigurationProperty -Filter "/system.webServer/security/requestFiltering/allowDoubleEscaping" -Name "enabled" -Value "False"
#Ensure Double-Encoded requests will be rejected
Set-WebConfigurationProperty -Filter "/system.webServer/security/requestFiltering/denyUrlSequences" -Name "add" -Value @{sequence="%2525"}
#Ensure 'HTTP Trace Method' is disabled
Set-WebConfigurationProperty -Filter "/system.webServer/security/requestFiltering" -Name "allowVerb" -Value @{verb="TRACE"; allowed="False"}
#Ensure Unlisted File Extensions are not allowed
Set-WebConfigurationProperty -Filter "/system.webServer/security/requestFiltering/fileExtensions" -Name "allowUnlisted" -Value "False"
#Ensure Handler is not granted Write and Script/Execute
Set-WebConfigurationProperty -Filter "/system.webServer/handlers/*" -Name "permissions" -Value "Read,Script"
#Ensure ‘notListedIsapisAllowed’ is set to false
Add-WebConfigurationProperty -Filter "/system.webServer/isapiCgiRestriction" -Name "notListedIsapisAllowed" -Value "False"
#Ensure ‘notListedCgisAllowed’ is set to false
Add-WebConfigurationProperty -Filter "/system.webServer/isapiCgiRestriction" -Name "notListedCgisAllowed" -Value "False"
#Ensure ‘Dynamic IP Address Restrictions’ is enabled
Set-WebConfigurationProperty -Filter "/system.webServer/security/dynamicIpSecurity" -Name "enabled" -Value "True"
#Ensure Default IIS web log location is moved
Add-Item -ItemType Directory -Path "C:\NewLogLocation"
Add-WebConfigurationProperty -Filter "/system.applicationHost/sites/siteDefaults/logFile" -Name "directory" -Value "C:\NewLogLocation"
Restart-Service W3SVC
#Ensure Advanced IIS logging is enabled
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/sites/siteDefaults/Logfile" -name "logExtFileFlags" -value "Date,Time,ClientIP,UserName,ServerIP,Method,UriStem,UriQuery,HttpStatus,Win32Status,BytesSent,BytesRecv,TimeTaken,ServerPort,UserAgent,Cookie,Referer,ProtocolVersion,Host,HttpSubStatus"
#Ensure ‘ETW Logging’ is enabled
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/sites/siteDefaults/tracing/traceFailedRequestsLogging" -name "enabled" -value "True"
Read-Host "FTP HARDENING"
#Ensure FTP requests are encrypted
reg add 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\FTP\Server' /v "AllowAnonymousTLS" /t REG_DWORD /d 0 /f 
#Ensure FTP Logon attempt restrictions is enabled
reg add 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\FTP\Server' -Name "MaxFailedAttempts" -Value 3

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

if ($option -eq 6){}
