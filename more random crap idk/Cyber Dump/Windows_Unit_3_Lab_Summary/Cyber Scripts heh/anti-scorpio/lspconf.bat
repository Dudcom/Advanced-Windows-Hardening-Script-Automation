@echo off
ECHO 1. Minimum conf
ECHO 2. Maximum conf

CHOICE /C 12 /M "Enter your choice:"

IF ERRORLEVEL 2 GOTO Maximum
IF ERRORLEVEL 1 GOTO Minimum

:Minimum
ECHO Minimum configuration selected
secedit /configure /db %userprofile%\Desktop\ScriptOut\Scripts\Minimum10.sdb
GOTO End

:Maximum
ECHO Maximum configuration selected
secedit /configure /db %userprofile%\Desktop\ScriptOut\Scripts\Maximum10.sdb
GOTO End

:End
ECHO Configuration has finished. Please double check URA and services.
pause