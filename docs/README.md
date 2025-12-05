# IICPC Anti-Cheat System (Track 3)

## Overview
This system is designed to detect various cheating methods in online programming contests. It runs on the candidate's Windows PC and monitors for:
1. **Virtual Machines (VMs)**  
   - Detects if the OS is running inside a VM (VirtualBox, VMware, QEMU, etc.).  
   - Detects if any virtual machines are running **on the host OS**, even when the anti-cheat program itself is executed on the host.
2.  **Remote Access Tools (RATs)**: Detects active remote desktop sessions and remote control software (TeamViewer, AnyDesk, etc.).
3.  **Screen Sharing & Recording**: Detects screen sharing applications (Discord, Zoom, OBS) and suspicious overlay windows.
4.  **Device & System Anomalies**: Detects multiple monitors, virtual display adapters, external/virtual webcams, and suspicious mouse behavior (botting).

## Architecture
The system is modular, enabling a plug and play design to add/remove modules and components. It consists of four specialized detection engines orchestrated by a main loop. It is designed for cross-platform compatibility (Windows and Linux).

**Source Code Location**:
-   `src/common/`: Platform-independent logic (`main.cpp`, `utils.cpp`).
-   `src/windows/`: Windows-specific detection implementations (`*_win.cpp`).
-   `src/linux/`: Linux-specific detection implementations (`*_linux.cpp`).
-   `include/`: Shared header files defining the detector interfaces.

## Platform Compatibility
This project is designed to be built and run on **Windows** and **Linux**.

*   **Build Environment**:
    *   **Windows**: Developed for **MinGW-w64** toolchain.
    *   **Linux**: Developed for **GCC** toolchain.
*   **Runtime Portability**:
    *   **Windows**: The compiled `bin/windows/main.exe` is a standalone static executable that can run on **any standard Windows PC** (Windows 7+) without needing MinGW installed.
    *   **Linux**: The compiled `bin/linux/main` binary can run on **any modern Linux distribution** (Ubuntu, Debian, etc.).

## Compilation
The system is built using simple `g++` commands. No complex build system (Make/CMake) is required.

### Prerequisites
-   **Windows**: MinGW-w64 (g++)
-   **Linux**: GCC (g++)

### Build Commands

#### Windows (MinGW-w64)
Run this command from the project root (`IICPC/`):
```cmd
mkdir bin\windows 2>NUL
g++ -o bin/windows/main.exe src/common/*.cpp src/windows/*.cpp -I include -lws2_32 -liphlpapi -lwtsapi32 -luser32 -lgdi32 -static
```

#### Linux (Ubuntu/Debian)
Run this command from the project root (`IICPC/`):
```bash
mkdir -p bin/linux
g++ -o bin/linux/main src/common/*.cpp src/linux/*.cpp -I include -pthread
```

The compiled binaries will be placed in `bin/windows/` or `bin/linux/` respectively.

## Usage
Run the generated executable as Administrator (Windows) or Root (Linux) for full functionality:

**Windows**:
```cmd
bin\windows\main.exe
```

**Linux**:
```bash
sudo ./bin/linux/main
```

The system will:
1.  Perform an initial **Passive Scan** for installed cheat software and VM artifacts (MAC Address).
2.  Enter an **Active Monitoring Loop**.
    -   **Interval**: 10s if passive threats found (High Risk), 25s otherwise (Low Risk).
3.  Report **ACTIVE THREATS (HARD CHECK)** and **ACTIVE THREATS (SOFT CHECK)**.

## Detection Logic
-   **Active Threat (Hard Check)**: Deterministic checks that confirm cheating (e.g., "TeamViewer.exe" running, CPUID Hypervisor bit set).
-   **Active Threat (Soft Check)**: Heuristic checks that indicate suspicious behavior (e.g., High mouse velocity, unknown overlay windows).
-   **Passive Threat**: Checks for installed but currently inactive cheat software (e.g., VirtualBox installed in `C:\Program Files`) or static indicators like MAC Address.

## Screenshots

1. Windows: System appears clean
   
   <img width="1832" height="910" alt="image" src="https://github.com/user-attachments/assets/cbcba5ef-e2d8-4432-8cee-3dd2dcd32743" />

2. Linux (Ubuntu): VM Detected! (multiple flags)

   <img width="1920" height="1014" alt="Screenshot from 2025-12-05 12-39-06" src="https://github.com/user-attachments/assets/7c32f075-1fdd-4ad9-9835-0897a058c22d" />

## Disclaimer
This tool is for educational and hackathon purposes. Some heuristic checks (like mouse velocity, and RDTSC timing) may require calibration for specific hardware.
