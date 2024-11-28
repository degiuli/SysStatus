@echo off
setlocal EnableDelayedExpansion

:: Initialize the Visual Studio build tools
call :SetupBuildTools

:: Setup the solution directory
set SolutionDir=%~dp0

call :Build

pause
exit /B 0


:: =============================================================================================
:: Builds everything
:: =============================================================================================
:Build

:: Use MSBuild to compile the solution
msbuild.exe "SysStatus.sln" /m /ds /t:Clean /p:Configuration="Release" /property:WarningLevel=4 /clp:"ShowCommandLine" /verbosity:diag /flp:LogFile=BuildReleaseClean.log
msbuild.exe "SysStatus.sln" /m /ds /t:Clean /p:Configuration="Debug" /property:WarningLevel=4 /clp:"ShowCommandLine" /verbosity:diag /flp:LogFile=BuildDebugClean.log
msbuild.exe "SysStatus.sln" /m /ds /t:Rebuild /p:Configuration="Release" /property:WarningLevel=4 /clp:"ShowCommandLine" /verbosity:diag /flp:LogFile=BuildReleaseDlv.log
msbuild.exe "SysStatus.sln" /m /ds /t:Rebuild /p:Configuration="Debug" /property:WarningLevel=4 /clp:"ShowCommandLine" /verbosity:diag /flp:LogFile=BuildDebugDlv.log

goto :EOF


:: =============================================================================================
:: Setup the correct build environment
:: =============================================================================================
:SetupBuildTools

:: Setup the correct Program Files folder path (32-bit vs 64-bit)
set ProgramFilesFolder=%ProgramFiles(x86)%
if "%ProgramFilesFolder%"=="" set ProgramFilesFolder=%ProgramFiles%

:: Check for VS 2019
if not exist "%VSDEVCMD_PATH%" (
	call :SetVsDevCmdPath "%ProgramFilesFolder%\Microsoft Visual Studio\2019"
)

:: Check for VS 2017
if not exist "%VSDEVCMD_PATH%" (
	call :SetVsDevCmdPath "%ProgramFilesFolder%\Microsoft Visual Studio\2017"
)

:: Check for VS 2015
if not exist "%VSDEVCMD_PATH%" (
	call :SetVsDevCmdPath "%ProgramFilesFolder%\Microsoft Visual Studio 14.0"
)

:: If the build tools were found, use them
if exist "%VSDEVCMD_PATH%" (
	call "%VSDEVCMD_PATH%"
	goto :EOF
)

echo No build tools found
goto :EOF


:: =============================================================================================
:: Find the VsDevCmd.bat file path in the specified folder
:: =============================================================================================
:SetVsDevCmdPath

:: If the folder does not exist, ignore it
if not exist %1 goto :EOF

:: Look for the VsDevCmd file in the provided folder
for /f "delims=" %%F in ('dir /b /s %1\VsDevCmd.bat 2^>nul') do set VSDEVCMD_PATH=%%F

goto :EOF