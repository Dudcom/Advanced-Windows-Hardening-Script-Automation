echo off
setlocal enabledelayedexpansion
set /p pass="Enter the password you will use: "
cd %userprofile%\Desktop
"CyberPatriot README.lnk" && echo Opening readme...
mkdir ScriptOut
cd ScriptOut
notepad TRUEUSERS.txt
wmic useraccount get name | more +1 | sort | more +2 > MYUSERS.txt
set temp=N
for /F "tokens=1,* delims=]" %%s in ('find /n /v "" ^<TRUEUSERS.txt') do (
	if not "%%t" == "" (
		if "!temp!" == "N" (
			echo %%t>>MYADMINU.txt
		) else (
			echo %%t>>MYSTANDARDU.txt
		)
	) else (
		set temp=Y & echo !temp!
	)
)
sort TRUEUSERS.txt | more +1 > temp.txt
copy /y temp.txt TRUEUSERS.txt
del temp.txt
for /F "tokens=*" %%s in ('more MYUSERS.txt') do (>NUL findstr /c:%%s TRUEUSERS.txt && break || echo %%s>>REMOVEUSERS.txt) 2>nul
for /F "tokens=*" %%s in ('more TRUEUSERS.txt') do @net user "%%s" %pass%
for /F "tokens=*" %%s in ('more TRUEUSERS.txt') do @net user "%%s" /active:yes
for /F "tokens=*" %%s in ('more TRUEUSERS.txt') do @wmic useraccount where "Name='%%s'" set passwordchangeable=TRUE
for /F "tokens=*" %%s in ('more TRUEUSERS.txt') do @wmic useraccount where "Name='%%s'" set passwordexpires=TRUE
for /F "tokens=*" %%s in ('more TRUEUSERS.txt') do @wmic useraccount where "Name='%%s'" set passwordrequired=TRUE
for /F "tokens=*" %%s in ('more REMOVEUSERS.txt') do (set foobar=%%s & call :Trim removeme !foobar! & echo !removeme!>>REMOVEME.txt)
del REMOVEUSERS.txt
for /F "tokens=*" %%s in ('more REMOVEME.txt') do @net user "%%s" /active:no
net user Guest /active:no
net user Administrator /active:no
net user DefaultAccount /active:no
for /F "tokens=*" %%s in ('more MYSTANDARDU.txt') do (net localgroup Administrators | findstr /c:%%s && net localgroup Administrators "%%s" /del || break) 2>nul
for /F "tokens=*" %%s in ('more REMOVEME.txt') do (net localgroup Administrators | findstr /c:%%s && net localgroup Administrators "%%s" /del || break) 2>nul
for /F "tokens=*" %%s in ('more MYADMINU.txt') do (net localgroup Administrators | findstr /c:%%s && break || net localgroup Administrators "%%s" /add) 2>nul
start lusrmgr
start notepad TRUEUSERS.txt

:Trim
set Params=%*
for /f "tokens=1*" %%a in ("!Params!") do EndLocal & set %1=%%b
exit /b