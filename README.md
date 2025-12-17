# NT230 - Malware Mechanism Analysis - Macro Stomping Project

## Overview
This project investigates the **VBA Macro Stomping** technique, a sophisticated method used by malware authors to evade detection. Macro Stomping involves modifying the compiled P-code of a VBA macro while leaving the source code intact (or replacing it with benign code). This discrepancy allows malicious code to execute in Office applications while security tools analyzing only the source code see nothing suspicious.

The project consists of two main components:
1.  **Macro Stomping Builder**: A Proof-of-Concept (PoC) tool to generate stomped documents.
2.  **Macro Stomping Detector**: A security tool designed to detect anomalies between VBA source code and P-code.

## Project Objectives
*   **Research**: Understand the internal structure of Microsoft Office documents (OLE Compound Files) and the execution mechanism of VBA macros (Source Code vs. P-code).
*   **Attack Simulation**: Develop a tool to perform Macro Stomping, creating documents that execute malicious behavior despite appearing harmless in the VBA Editor.
*   **Defense**: Build a detection utility that can identify stomped macros by comparing the compiled P-code against the visible source code.

## Results
*   Successfully demonstrated the Macro Stomping attack where the executed code differs from the displayed source code.
*   Developed a functional detector that scans directories, analyzes `.docm` files, and generates detailed reports on suspicious files with high accuracy.

## Technologies Used
*   **Programming Language**: Python 3.x
*   **Core Libraries**:
    *   `olefile`: For low-level OLE Compound File manipulation.
    *   `oletools`: For VBA macro analysis and extraction.
    *   `pcodedmp`: For VBA P-code disassembly.
    *   `colorama`: For cross-platform colored terminal output.
    *   `cryptography`: For AES-256-GCM encryption/decryption of payloads.
*   **Payload Generation & Execution**:
    *   **Sliver C2 Framework**: Used for generating advanced shellcode payloads.
    *   **C/C++ (Windows API)**: Custom loader implementation using `BCrypt` for decryption and memory injection techniques.

## Project Structure
```
nt230-marco-malware/
├── Macro_Stomping_Builder/      # Tool for creating stomped documents
│   ├── VBA_Stomper.py           # Main script for stomping
│   ├── Revershell_Payload/      # Payload generation and templates
│   └── VBA_Code/                # Source VBA 
├── Macro_Stomping_Detector/     # Tool for detecting stomped documents
│   ├── detector.py              # Main entry point
│   ├── modules/                 # Core analysis modules
│   │   ├── file_analyzer.py     # File I/O and extraction
│   │   ├── pattern_analyzer.py  # P-code vs Source comparison logic
│   │   ├── stomping_detector.py # Detection orchestration
│   │   └── report_generator.py  # Reporting engine
│   └── reports/                 # Output scan reports
├── requirements.txt             # Python dependencies
└── README.md                    # Project documentation
```

## References
*   [EvilClippy by outflanknl](https://github.com/outflanknl/EvilClippy)
*   [VBA Stomping - The Art of Deception](https://vbastomp.com/)
*   [PCodedmp](https://github.com/bontchev/pcodedmp)

## Authors
*   GROUP05:
-   Nguyễn Đức Khoa     - 23520748
-   Huỳnh Quốc Khánh    - 23520718
-   Đặng Thành Nhân     - 23521071
-   Vỗ Ngọc Hoàng Lâm   - 23520839
