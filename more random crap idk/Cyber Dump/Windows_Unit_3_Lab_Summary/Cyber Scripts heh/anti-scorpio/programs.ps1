$output_u = "$env:USERPROFILE\Desktop\ScriptOut\Programs"
mkdir $output_u -ErrorAction SilentlyContinue
Start-Transcript -Path "$output_u\programs_log.log"

$sh = New-Object -ComObject WScript.Shell
$url = $sh.CreateShortcut('C:\CyberPatriot\README.url').TargetPath
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
    Stop-Transcript
    exit
}

$url | Out-File -FilePath $output_u\url.txt
$regex = "Employees should also have access to the latest stable version of"
$matches = $HTML.RawContent | select-string -AllMatches $regex
if (!$matches) {
    Write-Host "Parsing error, please do manually"
    pause
    Stop-Transcript
    exit
}

$text = $matches.ToString().Split(".")
$regex = "for official company use"
$programs = $text | select-string -AllMatches $regex
$programs = $programs.toString().Split(" ")
$temp = $programs | Select-String -AllMatches "," | %{$_.toString()}
$temp = ($temp + $programs[[array]::indexof($programs,"and") + 1]).split(",") | Where-Object {$_}

$installedPrograms =  Get-Package -Provider Programs -IncludeWindowsInstaller
uninstall-package -name MobaXterm