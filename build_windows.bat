:: Windows Installer MSI builder script
:: Copyright (C) 2003-2025 ITRS Group Ltd. All rights reserved

@echo off

where python >nul 2>nul
if ERRORLEVEL 1 (
    echo [ERROR] Unable to find 'python' executable in PATH && exit /B 1
)
python --version | findstr /E 3.9.[0-9][0-9] >nul
if ERRORLEVEL 1 (
    echo [ERROR] Python binary found is not a version of Python 3.9.x && exit /B 1
)
where wix >nul 2>nulc
if ERRORLEVEL 1 (
    echo [ERROR] Unable to find 'wix' executable in PATH && exit /B 1
)
where heat >nul 2>nulc
if ERRORLEVEL 1 (
    echo [ERROR] Unable to find 'heat' executable in PATH && exit /B 1
)
python -c "import cx_Freeze" >nul 2>nul
if ERRORLEVEL 1 (
    echo [ERROR] 'cx_Freeze' missing from python modules && exit /B 1
)

echo [BUILD] Checking Agent VERSION
if NOT EXIST VERSION (
    echo [BUILD] Creating new Agent VERSION file
    python build_version.py -w >nul
)
set /p VERSION=<VERSION
echo Version=%VERSION%

set AGENT_NAME=infrastructure-agent
set AGENT_MSI=%AGENT_NAME%-%VERSION%.msi
set AGENT_DIR=C:/Program\ Files/Infrastructure\ Agent
set DEFAULT_CONFIG=agent.default.yml
set DEFAULT_WINDOWS_PLUGIN_DIR=infrastructure-agent-windows-plugins
if NOT DEFINED WINDOWS_PLUGIN_DIR (
    call :setplugindir %DEFAULT_WINDOWS_PLUGIN_DIR%
)

set PLUGNPSHELL_DIR=plugnpshell

set SDIR=build\exe.win-amd64-3.9
set BUILD_EXE_DIR=%SDIR%\bin
set CFG_DIR=%SDIR%\cfg
set LICENSES_DIR=%SDIR%\licenses
set LOGS_DIR=%SDIR%\logs
set PLUGINS_DIR=%SDIR%\plugins
set VAR_DIR=%SDIR%\var
set WIX_GEN=plib

del %AGENT_MSI% 2>nul

echo [BUILD] Building Infrastructure Agent
python setup.py build --build-exe %BUILD_EXE_DIR% || echo [ERROR] Failed to build Python component of Agent && exit /B 1

echo [BUILD] Creating extra directories
mkdir %CFG_DIR%
mkdir %LICENSES_DIR%
mkdir %LOGS_DIR%
mkdir %VAR_DIR%
mkdir %PLUGINS_DIR%

echo [BUILD] Adding version file
copy VERSION %VAR_DIR%\version

echo [BUILD] Adding Licensing files
copy LICENSING.md %SDIR%\AGENT_LICENSE.md || echo [ERROR] Failed to copy Licensing file && exit /B 1
copy %WINDOWS_PLUGIN_DIR%\LICENSING.md %SDIR%\PLUGIN_LICENSES.md || echo [ERROR] Failed to copy Licensing file && exit /B 1
copy %WINDOWS_PLUGIN_DIR%\licenses\* %LICENSES_DIR% || echo [ERROR] Failed to copy License files && exit /B 1

echo [BUILD] Building default configuration YAML
python build_config.py --install-dir "%AGENT_DIR%" --plugin-config-dir "%WINDOWS_PLUGIN_DIR%\config" || echo [ERROR] Failed to build Agent configuration YAML && exit /B 1
move cfg\%DEFAULT_CONFIG% %CFG_DIR%\ || echo [ERROR] Failed to move Agent configuration YAML && exit /B 1

echo [BUILD] Building Windows plugins
pushd %WINDOWS_PLUGIN_DIR% || echo [ERROR] Missing '%WINDOWS_PLUGIN_DIR%' project && exit /B 1
call build_all.bat || echo [ERROR] Failed to compile Windows plugins && exit /B 1
popd
echo [SUCCESS] Windows plugin built!
copy %WINDOWS_PLUGIN_DIR%\out\* %PLUGINS_DIR% || echo [ERROR] Failed to copy built plugins && exit /B 1

echo [BUILD] Including PlugNPShell Powershell module
xcopy /e /f /h /i /s /y %PLUGNPSHELL_DIR%\PlugNpshell %PLUGINS_DIR%\lib\powershell\PlugNpshell || echo [ERROR] Failed to copy PlugNPShell module

if DEFINED BUILD_UUID_PATH (
    if EXIST "%BUILD_UUID_PATH%" (
        echo [BUILD] Including build UUID file
        copy %BUILD_UUID_PATH% %VAR_DIR%\
    )
)

echo [BUILD] Building MSI with WiX
:: 'Harvest' the built agent files with heat, creating %WIX_GEN%.wxs
heat dir %SDIR% ^
    -cg %WIX_GEN% ^
    -ke ^
    -out %WIX_GEN%.wxs ^
    -gg ^
    -sfrag ^
    -srd ^
    -sreg ^
    -dr INSTALLDIR ^
    -var var.SourceDir ^
    || echo [ERROR] WiX compilation failed in 'heat' && exit /B 1

:: Build the final MSI using harvested files and the WiX template
wix build -o %AGENT_MSI% ^
    -arch x64 ^
    -define AgentVersion=%VERSION% ^
    -define SourceDir=%SDIR% ^
    win_wix.wxs %WIX_GEN%.wxs ^
    || echo [ERROR] WiX compilation failed in 'wix' && exit /B 1

echo [BUILD] Complete!
call:cleanup
exit /B 0


:cleanup
echo [BUILD] Cleaning up intermediate objects
del win_wix.wixobj 2>nul
del %WIX_GEN%.wixobj 2>nul
del %WIX_GEN%.wxs 2>nul
del %AGENT_NAME%-%VERSION%.wixpdb 2>nul
del VERSION
exit /B 0

:setplugindir
set WINDOWS_PLUGIN_DIR=%1
