:: Windows Agent firewall management script
:: Copyright (C) 2003-2026 ITRS Group Ltd. All rights reserved

@echo off
setlocal enabledelayedexpansion

:: Get location of infra agent bin dir
set AGENT_BIN_DIR=%~dp0

:: Default to no action
set SET_FIREWALL_RULE_PRIVATE=-1
set SET_FIREWALL_RULE_PUBLIC=-1
set SET_FIREWALL_RULE_DOMAIN=-1
set NETWORK_PROFILE=""
goto :main

:: Match arguments to infra agent installer
:showHelp
echo Manage Infrastructure Agent firewall rules.
echo:
echo By default, will add and remove firewall rules.
echo If actions on profiles are not specified, will leave rules as-is.
echo:
echo Alternate modes:
echo help - show this text
echo list - list current Infrastructure Agent firewall rules
echo:
echo To add or remove rules for each network profile:
echo - `SET_FIREWALL_RULE_PRIVATE=1` to add or `SET_FIREWALL_RULE_PRIVATE=0` to remove
echo - `SET_FIREWALL_RULE_DOMAIN=1` to add or `SET_FIREWALL_RULE_DOMAIN=0` to remove
echo - `SET_FIREWALL_RULE_PUBLIC=1` to add or `SET_FIREWALL_RULE_PUBLIC=0` to remove
goto :eof

:: List relevant firewall rules
:listFirewallRules
echo Current Infrastructure Agent firewall rules:
netsh advfirewall firewall show rule name="Infrastructure Agent"
goto :eof

:: Add firewall rule for network profile
:addFirewallRule
netsh advfirewall firewall show rule name="Infrastructure Agent" profile=!NETWORK_PROFILE! | find /i "No rules match" >nul
echo Adding Infrastructure Agent rule to !NETWORK_PROFILE! network profile...
if not errorlevel 1 (
    netsh advfirewall firewall add rule name="Infrastructure Agent" dir=in action=allow program="%AGENT_BIN_DIR%infra-agent.exe" enable=yes profile=!NETWORK_PROFILE! protocol=TCP"
) else (
    echo:
    echo Nothing to do
    echo:
)
goto :eof

:: Remove firewall rule for network profile
:removeFirewallRule
echo Removing Infrastructure Agent rule from !NETWORK_PROFILE! network profile...
netsh advfirewall firewall delete rule name="Infrastructure Agent" profile=!NETWORK_PROFILE!"
goto :eof

:main
:: no args provided
if "%~1" == "" (
    goto :showHelp
)

:: Parse args
set PREV_TOKEN=""
for %%A in (%*) do (

    if "%%A" == "help" (
        goto :showHelp
    ) else if "%%A" == "/help" (
        goto :showHelp
    ) else if "%%A" == "h" (
        goto :showHelp
    ) else if "%%A" == "/h" (
        goto :showHelp
    ) else if "%%A" == "list" (
        goto :listFirewallRules
    ) else if "%%A" == "/list" (
        goto :listFirewallRules
    )

    if "!PREV_TOKEN!" == "SET_FIREWALL_RULE_PRIVATE" (
        if "%%A" == "1" (
            set SET_FIREWALL_RULE_PRIVATE=1
        ) else if "%%A" == "0" (
            set SET_FIREWALL_RULE_PRIVATE=0
        )
    ) else if "!PREV_TOKEN!" == "SET_FIREWALL_RULE_DOMAIN" (
        if "%%A" == "1" (
            set SET_FIREWALL_RULE_DOMAIN=1
        ) else if "%%A" == "0" (
            set SET_FIREWALL_RULE_DOMAIN=0
        )
    ) else if "!PREV_TOKEN!" == "SET_FIREWALL_RULE_PUBLIC" (
        if "%%A" == "1" (
            set SET_FIREWALL_RULE_PUBLIC=1
        ) else if "%%A" == "0" (
            set SET_FIREWALL_RULE_PUBLIC=0
        )
    )
    set PREV_TOKEN=%%A
)

echo Managing Infrastructure Agent firewall rules:
echo:

set NETWORK_PROFILE=private
if "!SET_FIREWALL_RULE_PRIVATE!" == "1" (
    call :addFirewallRule
) else if "!SET_FIREWALL_RULE_PRIVATE!" == "0" (
    call :removeFirewallRule
)

set NETWORK_PROFILE=domain
if "!SET_FIREWALL_RULE_DOMAIN!" == "1" (
    call :addFirewallRule
) else if "!SET_FIREWALL_RULE_DOMAIN!" == "0" (
    call :removeFirewallRule
)

set NETWORK_PROFILE=public
if "!SET_FIREWALL_RULE_PUBLIC!" == "1" (
    call :addFirewallRule
) else if "!SET_FIREWALL_RULE_PUBLIC!" == "0" (
    call :removeFirewallRule
)

exit /B 0
