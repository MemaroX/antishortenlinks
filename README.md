# Anti-Shorten Links: URL Safety Checker

This Python script provides a robust way to check the safety of URLs, trace redirects, and leverage the VirusTotal API for malware and suspicious activity detection. It's designed to help users make informed decisions before visiting potentially harmful links.

## Features

- **VirusTotal Integration:** Utilizes the VirusTotal API to scan URLs for known threats and suspicious indicators.
- **Redirect Tracing:** Follows URL redirects and provides safety information for each intermediate URL in the chain.
- **Comprehensive Verdict:** Offers a final safety verdict for the ultimate destination URL.
- **User Confirmation:** Prompts the user for confirmation before opening the final URL in a web browser.
- **Secure API Key Handling:** Reads the VirusTotal API key from an environment variable, enhancing security.

## Requirements

- Python 3.x
- `requests` library
- `webbrowser` (standard Python library)
- A VirusTotal API key (obtainable for free for non-commercial use from the [VirusTotal website](https://www.virustotal.com/)).

## Setup and Usage

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/MemaroX/antishortenlinks.git
    cd antishortenlinks
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Set your VirusTotal API Key:**
    **IMPORTANT:** For security reasons, the API key is not hardcoded in the script. You must set it as an environment variable named `VIRUSTOTAL_API_KEY`.

    *   **On Windows (Command Prompt):**
        ```bash
        set VIRUSTOTAL_API_KEY=YOUR_API_KEY_HERE
        ```
    *   **On Windows (PowerShell):**
        ```powershell
        $env:VIRUSTOTAL_API_KEY="YOUR_API_KEY_HERE"
        ```
    *   **On Linux/macOS:**
        ```bash
        export VIRUSTOTAL_API_KEY=YOUR_API_KEY_HERE
        ```
    Replace `YOUR_API_KEY_HERE` with your actual VirusTotal API key.

4.  **Run the script:**
    ```bash
    python main.py
    ```

5.  **Enter the URL:**
    Follow the prompts to enter the URL you wish to check. The script will display safety information for each redirect and ask for confirmation before opening the final URL.

## Notes

- This script is provided for educational and informational purposes only. It should not be considered a definitive security solution.
- VirusTotal API detection capabilities may vary.
- Always exercise caution when visiting unfamiliar websites.

## Contributing

Contributions are welcome! Feel free to fork this repository, improve its functionality, or add new features.

## License

This project is licensed under the MIT License - see the `LICENSE` file for details.