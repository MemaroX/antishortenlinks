This repository contains a Python script that checks the safety of a URL and follows redirects, displaying safety information along the way.
Features:

Leverages VirusTotal API to check for malware and suspicious activity on the URL.
Traces redirects and displays the safety status of each intermediate URL.
Provides the user with a final safe/unsafe verdict for the ultimate destination.
Asks for user confirmation before opening the final URL.
Requirements:

Python 3
requests library
webbrowser library
VirusTotal API key (free for non-commercial use)
Usage:

Clone or download the repository.
Install the required libraries (if not already installed).
Replace APIKEY with your own VirusTotal API key.
Run the script: python main.py
Enter the URL you want to check.
Follow the prompts to see the safety information and decide whether to open the final URL.
Notes:

This script is provided for educational purposes only and should not be relied upon as a definitive source of URL safety.
VirusTotal API may have limitations in its detection capabilities.
Always exercise caution when visiting unfamiliar websites.
Contributing:

Feel free to fork this repository and contribute by improving the script's functionality or adding additional features.

Contact:

If you have any feedback or questions, please feel free to open an issue on this repository.

Additional Resources:

VirusTotal API documentation: https://developers.virustotal.com/reference
requests library documentation: https://docs.python-requests.org/en/latest/
webbrowser library documentation: https://docs.python.org/3/library/webbrowser.html
Written by *Fatma Kamel*
