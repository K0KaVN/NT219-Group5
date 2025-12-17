# Macro Stomping Builder

## Tool Features
The **Macro Stomping Builder** is a Python-based tool designed to demonstrate the VBA Stomping technique. It directly manipulates the OLE Compound File structure of Office documents to create a mismatch between the compiled P-code and the compressed source code.

*   **P-code Injection**: Retains the compiled P-code from a malicious macro.
*   **Source Code Replacement**: Overwrites the compressed source code with benign (fake) VBA code.
*   **OLE Stream Manipulation**: Uses `olefile` to modify the `VBA/Module1` stream directly within `vbaProject.bin`.
*   **Padding Handling**: Automatically calculates and applies compressed padding to ensure the modified stream matches the original size or structure requirements.

## Technologies Used
*   **Python**: The core programming language.
*   **olefile**: Used to parse, read, and write Microsoft OLE2 files (Structured Storage). This is the critical library that allows direct modification of the `VBA/Module1` stream to perform the stomping attack.
*   **struct**: Standard Python library used for packing and unpacking binary data (handling headers, endianness).
*   **cryptography**: Python library used for AES-256-GCM encryption of the shellcode payload.
*   **Sliver C2**: Command & Control framework used to generate the initial shellcode payload.
*   **Windows API (C/C++)**: Used in the loader to perform memory injection (`VirtualAlloc`, `CreateThread`) and decryption (`BCrypt`).

## Results
The tool generates a `vbaProject.bin` file that, when embedded into a Word document (`.docm`), exhibits the following behavior:
1.  **Execution**: When macros are enabled, the **malicious P-code** executes.
2.  **Inspection**: If a user or analyst opens the VBA Editor (IDE), they see the **benign source code**.
3.  **Evasion**: Static analysis tools that only check the source code will fail to detect the malicious payload.

## Workflow
1.  **Preparation**:
    *   Create a `malicious_vbaProject.bin` containing the actual payload (e.g., Reverse Shell).
    *   Create a `fakesource_vbaProject.bin` containing harmless code (e.g., a simple MsgBox or empty sub).
2.  **Extraction**: The tool reads the `VBA/Module1` stream from both files.
3.  **Stomping**:
    *   Identifies the offset where the Compressed Source Code begins.
    *   Combines the **P-code** from the malicious file with the **Source Code** from the fake file.
4.  **Finalization**:
    *   Calculates size differences.
    *   Adds necessary padding to maintain file integrity.
    *   Writes the new stream to `vbaProject.bin`.

## Usage

### Prerequisites
*   Python 3.x
*   `olefile` library

### Running the Tool
1.  Ensure you have `malicious_vbaProject.bin` and `fakesource_vbaProject.bin` in the same directory (or update the paths in the script).
2.  Run the script:
    ```bash
    python VBA_Stomper.py
    ```
3.  The output `vbaProject.bin` will be created. You can then replace this file inside a valid `.docm` archive (using a tool like 7-Zip or re-zipping the contents).
