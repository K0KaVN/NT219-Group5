# Macro Stomping Detector

## Tool Features
The **Macro Stomping Detector** is a specialized security tool designed to identify Office documents that have been tampered with using VBA Stomping techniques. It goes beyond simple signature matching by analyzing the behavioral and structural differences between the compiled code and the source code.

*   **Recursive Scanning**: Scans entire directories and subdirectories for `.docm` files.
*   **Dual Extraction**: Extracts both the compiled P-code (using `pcodedmp`) and the VBA source code (using `oletools`).
*   **Pattern Matching**: Compares identifiers, strings, and comments between P-code and Source code to calculate mismatch rates.
*   **Behavioral Analysis**: Detects high-risk API calls (e.g., `CreateObject`, `Shell`, `URLDownloadToFile`) hidden in P-code that are absent from the source.
*   **Confidence Scoring**: Assigns a suspicion score (0-100%) based on mismatch rates and risk indicators.
*   **Detailed Reporting**: Generates summary reports for all files and detailed forensic reports for suspicious findings.

## Technologies Used
*   **Python**: The core programming language.
*   **oletools (olevba)**: Used to detect macros and extract the compressed VBA source code from Office documents.
*   **pcodedmp**: A specialized tool used to disassemble the compiled P-code from the VBA streams, enabling the comparison against source code.
*   **colorama**: Provides colored terminal output for better user experience and visual distinction of alerts (Red for suspicious, Green for clean).
*   **argparse**: Handles command-line argument parsing for flexible tool usage.

## Results
The detector outputs:
*   **Console Output**: Real-time scanning progress and summary statistics (Clean, Suspicious, Errors).
*   **Summary Reports**: A text file listing all scanned files and their status.
*   **Suspicious Reports**: Individual reports for each detected file, detailing:
    *   Threat Level (High/Medium/Low)
    *   Confidence Score
    *   Specific mismatch statistics (Identifiers, Strings, Comments)
    *   Detected hidden API calls or suspicious patterns.

## Workflow
1.  **Input**: User provides a directory path containing `.docm` files.
2.  **Analysis Loop**:
    *   **Step 1**: Check for macros and extract VBA Source Code.
    *   **Step 2**: Extract P-code using the `pcodedmp` engine.
    *   **Step 3**: Clean and normalize both code sets (remove metadata, attributes).
    *   **Step 4**: Compare patterns (variables, function names, string literals).
    *   **Step 5**: Analyze for dangerous behaviors present in P-code but missing in Source.
3.  **Scoring**: Calculate a confidence score based on the divergence between P-code and Source.
4.  **Reporting**: Save results to the `reports/` directory.

## Usage

### Prerequisites
*   Python 3.x
*   Dependencies: `colorama`, `oletools`, `pcodedmp`

### Installation
```bash
pip install -r ../requirements.txt
```

### Running the Detector
**Basic Scan:**
Scan a specific directory for `.docm` files.
```bash
python detector.py -d "path/to/documents"
```

**Recursive Scan:**
Scan a directory and all its subfolders.
```bash
python detector.py -d "path/to/documents" -r
```

**Help:**
View all available options.
```bash
python detector.py -h
```
