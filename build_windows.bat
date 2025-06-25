:: Windows Installer MSI builder script
:: Copyright (C) 2003-2025 ITRS Group Ltd. All rights reserved

@echo off

where python >nul 2>nul
if ERRORLEVEL 1 (
    echo [ERROR] Unable to find 'python' executable in PATH && exit /B 1
)
python --version | findstr /E 3.13.[0-9][0-9]* >nul
if ERRORLEVEL 1 (
    echo [ERROR] Python binary found is not a version of Python 3.13.x && exit /B 1
)
where wix >nul 2>nulc
if ERRORLEVEL 1 (
    echo [ERROR] Unable to find 'wix' executable in PATH && exit /B 1
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

for /f "tokens=1,2 delims=." %%a in ("%VERSION%") do set "MAJOR_MINOR_VERSION=%%a.%%b"

echo MajorMinorVersion=%MAJOR_MINOR_VERSION%

set AGENT_NAME=infrastructure-agent
set AGENT_MSI=%AGENT_NAME%-%VERSION%.msi
set AGENT_INSTALLER_BUNDLE=%AGENT_NAME%-installer-%VERSION%.exe
set AGENT_DIR=C:/Program\ Files/Infrastructure\ Agent
set DEFAULT_CONFIG=agent.default.yml
set DEFAULT_WINDOWS_PLUGIN_DIR=infrastructure-agent-windows-plugins
if NOT DEFINED WINDOWS_PLUGIN_DIR (
    call :setplugindir %DEFAULT_WINDOWS_PLUGIN_DIR%
)

set PLUGNPSHELL_DIR=plugnpshell

set SDIR=build\exe.win-amd64-3.13
set BUILD_EXE_DIR=%SDIR%\bin
set CFG_DIR=%SDIR%\cfg
set LICENSES_DIR=%SDIR%\licenses
set LOGS_DIR=%SDIR%\logs
set PLUGINS_DIR=%SDIR%\plugins
set VAR_DIR=%SDIR%\var

del %AGENT_MSI% 2>nul

echo [BUILD] Building Infrastructure Agent
python setup.py build_exe --build-exe %BUILD_EXE_DIR% || echo [ERROR] Failed to build Python component of Agent && exit /B 1

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
copy %WINDOWS_PLUGIN_DIR%\LICENSING.md %SDIR%\PLUGIN_LICENSES.md || echo [ERROR] Failed to copy plugin Licensing file && exit /B 1

echo [BUILD] Adding plugin Licensing files
copy %WINDOWS_PLUGIN_DIR%\licenses\* %LICENSES_DIR% || echo [ERROR] Failed to copy plugin License files && exit /B 1

echo [BUILD] Adding third-party Licensing files
copy LICENSE_MICROSOFT_VCPP %LICENSES_DIR% || echo [ERROR] Failed to copy LICENSE_MICROSOFT_VCPP && exit /B 1
copy LICENSE_WIX_THEME %LICENSES_DIR% || echo [ERROR] Failed to copy LICENSE_WIX_THEME && exit /B 1

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

echo [BUILD] Including Firewall Management script
copy managefirewall.bat %BUILD_EXE_DIR% || echo [ERROR] Failed to copy Firewall Management script && exit /B 1

if DEFINED BUILD_UUID_PATH (
    if EXIST "%BUILD_UUID_PATH%" (
        echo [BUILD] Including build UUID file
        copy %BUILD_UUID_PATH% %VAR_DIR%\
    )
)

echo [BUILD] Building MSI with WiX
:: Build the agent MSI using harvested files and the WiX template
wix build -o %AGENT_MSI% ^
    -arch x64 ^
    -define AgentVersion=%VERSION% ^
    -define SourceDir=%SDIR% ^
    win_wix_msi.wxs ^
    || echo [ERROR] WiX MSI compilation failed in 'wix' && exit /B 1

echo [BUILD] Building Installer bundle with WiX
:: Build the final installer bundle - this wraps the agent MSI up
:: with other EXEs/MSIs, if we need any as dependencies.
:: Bundled EXEs are referenced in the wxs file, and don't need to be copied in this file explicitly.
wix build -o %AGENT_INSTALLER_BUNDLE% ^
    -arch x64 ^
    -ext WixToolset.BootstrapperApplications.wixext ^
    -define AgentVersion=%VERSION% ^
    -define AgentMajorMinorVersion=%MAJOR_MINOR_VERSION% ^
    -define InfraAgentMSIFile=%AGENT_MSI% ^
     win_wix_bundle.wxs ^
    || echo [ERROR] WiX installer bundle compilation failed in 'wix' && exit /B 1

echo [BUILD] Complete!
call:cleanup
exit /B 0

:cleanup
echo [BUILD] Cleaning up intermediate objects
del win_wix_msi.wixobj 2>nul
del win_wix_bundle.wixobj 2>nul
del %AGENT_NAME%-%VERSION%.wixpdb 2>nul
del %AGENT_NAME%-installer-%VERSION%.wixpdb 2>nul
del VERSION
exit /B 0

:setplugindir
set WINDOWS_PLUGIN_DIR=%1
