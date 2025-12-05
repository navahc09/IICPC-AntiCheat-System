# IICPC Anti-Cheat System Design Document

## 1. Introduction
This document outlines the design and architecture of the Anti-Cheat System developed for Track 3 of the IICPC internship assignment + hackathon. The system is a Windows-based C++ application designed to detect various forms of cheating in online programming contests, including Virtual Machines (VMs), Remote Access Tools (RATs), Screen Sharing, and Hardware Anomalies.

## 2. System Architecture
The system follows a modular architecture with a central orchestrator (`main.cpp`) and four specialized detection engines.

### 2.1 Modules & Checks

#### 1. VM Detection Engine (`vm_detect_mingw.cpp`)
*   **Passive Checks (Static Analysis)**:
    *   `checkCPUIDHypervisorBit()`: Checks CPUID leaf 1 ECX bit 31.
    *   `getHypervisorVendor()`: Checks CPUID leaf 0x40000000 for vendor string (e.g., "VMwareVMware").
    *   `checkCPUBrand()`: Checks for "QEMU", "Virtual", "Xeon" (often used in cloud VMs).
    *   `checkRDTSCTiming()`: Static analysis of RDTSC latency (VMs have higher latency/variance).
    *   `checkMacAddress()`: Checks OUI prefixes for VMware (00:05:69...), VirtualBox (08:00:27), etc.
    *   `checkVMwareBackdoor()`: Checks I/O port 0x5658 for VMware magic value.
    *   `checkLowSpecs()`: Checks for RAM < 2GB or CPU Cores < 2.
    *   `checkDiskSize()`: Checks for Disk < 60GB.
    *   `checkRegistryArtifacts()`: Scans for VBox/VMware registry keys.
    *   `checkDriverFiles()`: Scans for VBoxGuest.sys, vm3dmp.sys, etc.
    *   `checkInstalledSoftware()`: Scans Uninstall registry for "VMware Tools", "VirtualBox Guest Additions".
    *   `checkCommonPaths()`: Scans for "C:\Program Files\Oracle\VirtualBox Guest Additions", etc.
*   **Active Checks (Hard)**:
    *   `checkProcesses()`: Scans for running processes (vboxservice.exe, vmtoolsd.exe).

#### 2. Remote Access Detection Engine (`remote_detect.cpp`)
*   **Passive Checks**:
    *   `checkServiceState()`: Checks if services (TeamViewer, AnyDesk) are installed (even if stopped).
    *   `checkRegistryInstall()`: Checks Uninstall registry for RATs.
    *   `checkInstallPaths()`: Checks for installation directories of known RATs.
*   **Active Checks (Hard)**:
    *   `checkRDPSession()`: Checks `GetSystemMetrics(SM_REMOTESESSION)` and WTS APIs.
    *   `checkProcesses()`: Scans for running RAT processes (TeamViewer.exe, AnyDesk.exe).
    *   `checkServiceState()`: Checks for running RAT services.
*   **Active Checks (Soft)**:
    *   `checkPorts()`: Scans TCP table for known RAT ports (5938, 7070, etc.).
    *   `checkWindowTitles()`: Scans for visible windows with RAT titles.

#### 3. Screen Sharing Detection Engine (`screen_sharing_detect.cpp`)
*   **Active Checks (Hard)**:
    *   `checkProcesses()`: Scans for OBS, Discord, Zoom, Teams, Slack, etc.
    *   `checkWindows()`: Scans for specific window classes (e.g., "Qt5QWindowIcon" for OBS) and titles.
*   **Active Checks (Soft)**:
    *   `checkWindows()` (Heuristics): Scans for "Stop Sharing", "is sharing your screen" overlays.
    *   `checkWindows()` (Class Heuristics): Scans for "GDI+ Hook Window Class", "ScreenCapture".

#### 4. Device & Anomaly Detection Engine (`device_detect.cpp`)
*   **Active Checks (Hard)**:
    *   `checkMultiMonitor()`: Checks `SM_CMONITORS` > 1.
    *   `checkWebcams()`: Checks for known Virtual Camera drivers (OBS, ManyCam).
    *   `checkMouseAnomalies()`: Detects teleportation (> 50000 px/s).
*   **Active Checks (Soft)**:
    *   `checkVirtualMonitors()`: Checks for virtual display adapters (Spacedesk, IddCx, Citrix).
    *   `checkWebcams()`: Detects > 1 physical camera.
    *   `checkMouseAnomalies()`: Detects suspicious speed (> 20000 px/s).

### 2.2 Orchestrator (`main.cpp`)
The `main.cpp` file acts as the entry point. It:
1.  **Initializes** all detector classes.
2.  **Performs a Passive Scan**: Checks for installed (but inactive) cheat software and VM artifacts (MAC Address) at startup.
3.  **Enters Active Loop**:
    *   **Dynamic Interval**:
        *   **10 Seconds**: If passive threats were detected (High Risk Mode).
        *   **25 Seconds**: If system appears clean (Low Risk Mode).
    *   **Time Display**: Shows "Time Since Active" to indicate uptime.
    *   Calls active checks from all modules.
    *   Aggregates results into "Active Threats (Hard Check)" and "Active Threats (Soft Check)".
    *   Updates the console UI with current status.

## 3. Design Decisions

### 3.1 Single-Executable Deployment
*   **Decision**: The system is compiled into a single static executable (`main.exe`).
*   **Reason**: Simplifies deployment to candidate machines. No need to install dependencies or DLLs.
*   **Implementation**: Used `-static` flag with MinGW64 and included `.cpp` files directly (simulating a unity build) to avoid complex makefiles/project files for the end user.

### 3.2 Threat Classification Terminology
*   **Passive Threat**:
    *   **Definition**: Indicators that a cheat tool is *present* on the system but not necessarily *active* right now.
    *   **Examples**: "VirtualBox" installed in Program Files, MAC Address belonging to VMware (indicates VM environment), Registry keys for cheat tools.
    *   **Action**: Increases the monitoring frequency (Sleep interval drops to 10s).
*   **Active Threat (Hard Check)**:
    *   **Definition**: Deterministic, high-confidence indicators that cheating is occurring *right now*.
    *   **Examples**: "TeamViewer.exe" process running, RDP session active, CPUID Hypervisor bit set.
    *   **Action**: Immediate "CRITICAL" alert. In a real contest, this would trigger an auto-ban or flag.
*   **Active Threat (Soft Check)**:
    *   **Definition**: Heuristic or probabilistic indicators that suggest suspicious behavior but could be false positives. Represented by a confidence score internally.
    *   **Examples**: Mouse moving too fast (could be high DPI gamer mouse), unknown overlay window.
    *   **Action**: "WARNING" alert. Requires manual review.

### 3.3 MinGW64 Compatibility
*   **Decision**: Target MinGW64 compiler.
*   **Reason**: Requested by the user. Required careful selection of Windows APIs (e.g., using `_WIN32_WINNT` definitions) and avoiding MSVC-specific pragmas where possible.

### 3.4 User Privacy & Safety
*   **Decision**: The tool only *monitors* and *reports*. It does not automatically kill processes or delete files.
*   **Reason**: To prevent accidental system instability or data loss on candidate machines.

## 4. Flowchart
1.  **Start** -> **Initialize Detectors**
2.  **Passive Scan** (Registry/Files/MAC) -> Report Passive Threats
    *   If Threats Found -> Set Interval = 10s
    *   Else -> Set Interval = 25s
3.  **Loop Start** (Track Start Time)
4.  **Check VM** (CPUID, Drivers, Processes)
5.  **Check Remote** (RDP, Ports, Processes)
6.  **Check Screen** (Windows, Titles)
7.  **Check Device** (Monitors, Mouse, Webcams)
8.  **Aggregate Results**
    *   If Hard Check -> **ACTIVE THREAT (HARD)**
    *   If Soft Check -> **ACTIVE THREAT (SOFT)**
9.  **Display Status** (Time Since Active)
10. **Sleep** (Interval) -> **Go to Loop Start**

## 5. Future Improvements
*   **Server Reporting**: Send violation logs to a central contest server.
*   **Screenshotting**: Take periodic screenshots of the candidate's desktop.
*   **Kernel Driver**: Implement a kernel-mode driver for more robust anti-tamper protection (out of scope for this hackathon track).
