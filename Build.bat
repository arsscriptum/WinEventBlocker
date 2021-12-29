@echo off
setlocal EnableDelayedExpansion

:: ==============================================================================
:: 
::      Build.bat
::
::      Build different configuration of the app
::
:: ==============================================================================
::   arsccriptum - made in quebec 2020 <guillaumeplante.qc@gmail.com>
:: ==============================================================================

goto :init

:init
    set "__scripts_root=%AutomationScriptsRoot%"
    call :read_script_root development\build-automation  BuildAutomation
    set "__script_file=%~0"
    set "__target=%~1"
    set "__script_path=%~dp0"
    set "__makefile=%__scripts_root%\make\make.bat"
    set "__lib_date=%__scripts_root%\batlibs\date.bat"
    set "__lib_out=%__scripts_root%\batlibs\out.bat"
    ::*** This is the important line ***
    set "__build_cfg=%__script_path%buildcfg.ini"
    set "__build_cancelled=0"
    pushd %__script_path%
    goto :validate


:header
    echo. %__script_name% v%__script_version%
    echo.    This script is part of codecastor build wrappers.
    echo.
    goto :eof

:header_err
    echo.**************************************************
    echo.This script is part of codecastor build wrappers.
    echo.**************************************************
    echo.
    echo. YOU NEED TO HAVE THE BuildAutomation Scripts setup on you system...
    echo. https://github.com/codecastor/BuildAutomation
    goto :eof


:read_script_root
    set regpath=%OrganizationHKCU::=%
    for /f "tokens=2,*" %%A in ('REG.exe query %regpath%\%1 /v %2') do (
            set "__scripts_root=%%B"
        )
    goto :eof

:validate
    if not defined __scripts_root          call :header_err && call :error_missing_path __scripts_root & goto :eof
    if not exist %__makefile%  call :error_missing_script "%__makefile%" & goto :eof
    if not exist %__lib_date%  call :error_missing_script "%__lib_date%" & goto :eof
    if not exist %__lib_out%  call :error_missing_script "%__lib_out%" & goto :eof
    if not exist %__build_cfg%  call :error_missing_script "%__build_cfg%" & goto :eof

    goto :prebuild_header


:prebuild_header
    call %__lib_date% :getbuilddate
    call %__lib_out% :__out_d_red " ======================================================================="
    call %__lib_out% :__out_l_red " Compilation started for %cd%  %__target%"  
    call %__lib_out% :__out_d_red " ======================================================================="
    call :build
    goto :eof


:: ==============================================================================
::   call make
:: ==============================================================================
:call_make_build
    set config=%1
    set platform=%2
    call %__makefile% /v /i %__build_cfg% /t Build /c %config% /p %platform%
    goto :finished

:call_make_build_export
    set config=%1
    set platform=%2
    set export_path=%3
    call %__makefile% /v /i %__build_cfg% /t Build /c %config% /p %platform% /x %export_path%
    goto :finished

:: ==============================================================================
::   Build static
:: ==============================================================================
:build_debug
    call :call_make_build Debug x86
    goto :eof

:: ==============================================================================
::   Build x64
:: ==============================================================================
:build_x64
    call :call_make_build_export Release x64 "c:\Programs\SystemTools"
    goto :eof

:: ==============================================================================
::   clean all
:: ==============================================================================
:clean
    call %__makefile% /v /i %__build_cfg% /t Clean /c Debug /p x86
    call %__makefile% /v /i %__build_cfg% /t Clean /c Release /p x86
    call %__makefile% /v /i %__build_cfg% /t Clean /c Debug /p x64
    call %__makefile% /v /i %__build_cfg% /t Clean /c Release /p x64
    goto :eof


:: ==============================================================================
::   Build
:: ==============================================================================
:build
	if "%__target%" == "clean" (
		call :clean
		goto :finished
		)
    if "%__target%" == "rebuild" (
		call :clean
		)
    if "%__target%" == "debug" (
        call :build_debug
        goto :finished
        )
    ::call :build_x86
    call :build_x64
    goto :finished


:error_missing_path
    echo.
    echo   Error
    echo    Missing path: %~1
    echo.
    goto :eof



:error_missing_script
    echo.
    echo    Error
    echo    Missing bat script: %~1
    echo.
    goto :eof



:finished
    call %__lib_out% :__out_d_grn "Build complete"
