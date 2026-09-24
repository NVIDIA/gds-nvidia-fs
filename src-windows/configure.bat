@echo off
REM Windows configuration script for NVIDIA GDS driver
REM Copyright (c) 2021-2025, NVIDIA CORPORATION. All rights reserved.

echo Configuring NVIDIA GDS Windows Driver Build Environment...

REM Check for Windows Driver Kit (WDK)
if not exist "%WindowsSdkDir%" (
    echo ERROR: Windows SDK not found. Please install Windows Driver Kit.
    exit /b 1
)

REM Check for Visual Studio
if not defined VSINSTALLDIR (
    echo ERROR: Visual Studio not found. Please run from Developer Command Prompt.
    exit /b 1
)

REM Set build configuration
set BUILD_CONFIG=Release
set BUILD_PLATFORM=x64
set TARGET_OS=Win10

REM Check for NVIDIA GPU Driver SDK
if not exist "%NVIDIA_GPU_DRIVER_SDK%" (
    echo WARNING: NVIDIA GPU Driver SDK path not set. Some features may not compile.
    echo Please set NVIDIA_GPU_DRIVER_SDK environment variable.
)

REM Create build directories
if not exist "x64" mkdir x64
if not exist "x64\%BUILD_CONFIG%" mkdir "x64\%BUILD_CONFIG%"

REM Generate build configuration
echo Generating build configuration...
echo #ifndef BUILD_CONFIG_H > build-config.h
echo #define BUILD_CONFIG_H >> build-config.h
echo #define BUILD_CONFIGURATION "%BUILD_CONFIG%" >> build-config.h
echo #define BUILD_PLATFORM "%BUILD_PLATFORM%" >> build-config.h
echo #define TARGET_OS "%TARGET_OS%" >> build-config.h
echo #define BUILD_TIMESTAMP "%DATE% %TIME%" >> build-config.h
echo #endif >> build-config.h

REM Check dependencies
echo Checking dependencies...

REM Check for required headers
if not exist "%WindowsSdkDir%\Include\*\km\wdm.h" (
    echo ERROR: WDM headers not found. Please install Windows Driver Kit.
    exit /b 1
)

if not exist "%WindowsSdkDir%\Include\*\km\wdf.h" (
    echo ERROR: WDF headers not found. Please install Windows Driver Framework.
    exit /b 1
)

echo Configuration completed successfully.
echo.
echo To build the driver:
echo   msbuild nvidia-fs.sln /p:Configuration=%BUILD_CONFIG% /p:Platform=%BUILD_PLATFORM%
echo.
echo To install the driver:
echo   pnputil /add-driver nvidia-fs.inf
echo.