# Network Scanner Tool

## Overview

This is a Python-based GUI network scanner tool built using Tkinter and Nmap. It allows users to scan IP ranges or domains for open ports and services using Nmap, display the results in a scrolled text box, and save the results to a PDF file. The tool includes features like toggling between light and dark themes, progress tracking during scans, and stopping scans on demand.

## Features

- **IP Range Scanning**: Scan specified IP ranges or domains for open ports and services using Nmap.
- **Port and Nmap Options**: Choose from popular port ranges, custom ports, or specify Nmap command options.
- **Progress Tracking**: Real-time progress tracking with a progress bar.
- **Result Management**: Display scan results in a text box, clear results, or save them to a PDF file.
- **Theme Toggle**: Switch between light and dark themes.
- **Multithreading**: Perform scans in a separate thread to keep the GUI responsive.

## Prerequisites

- **Python 3.x**
- **Nmap**: Installable via your package manager (e.g., `sudo apt install nmap` for Ubuntu).
- **fpdf**: Install via pip:
  ```bash
  pip install fpdf
  ```
- **Tkinter**: Pre-installed with Python, but make sure it's available on your system.

## How to Use

1. **Start the Application**: Run the script using Python:
   ```bash
   python network_scanner.py
   ```

2. **Enter IP Range/Domain**: Input the desired IP range or domain in the `IP Range or Domain` field.

3. **Select Ports**: Choose from popular port ranges in the dropdown or enter custom ports in the `Custom Ports` field.

4. **Specify Nmap Options**: Choose from pre-defined Nmap options in the dropdown, or manually enter your options in the `Nmap Options` field.

5. **Scan the Network**: Click the `Scan` button to start scanning. The results will be displayed in the text box, and the progress will be tracked using the progress bar.

6. **Save Results**: Click the `Save Results` button to save the scan results to a PDF file.

7. **Stop Scanning**: Click the `Stop Scan` button to terminate an ongoing scan.

8. **Clear Results**: Use the `Clear Results` button to clear the text box.

9. **Toggle Theme**: Click the `Toggle Theme` button to switch between light and dark modes.

## Files

- **network_scanner.py**: The main script containing the GUI and scanning logic.

## Notes

- The tool uses multithreading to ensure the GUI remains responsive during network scans.
- Nmap needs to be installed and accessible from your system's PATH.
- The tool offers example Nmap options for convenience but allows full customization through the options field.

## License

This project is licensed under the MIT License. Feel free to modify and distribute it as needed.

## Contact

For any questions or issues, please contact [Your Name] at [Your Email].