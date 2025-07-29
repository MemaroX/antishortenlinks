#!/usr/bin/python
import requests
import time
import webbrowser

def is_safe(url):
    import os
    api_key = os.getenv('VIRUSTOTAL_API_KEY')
    if not api_key:
        print("Error: VirusTotal API key not found. Please set the VIRUSTOTAL_API_KEY environment variable.")
        return False
    url_id = requests.get('https://www.virustotal.com/vtapi/v2/url/report',
                          params={'apikey': api_key, 'resource':url})
    report = url_id.json()
    if 'positives' in report and report['positives'] > 0:
        return False
    else:
        return True

def print_redirects(url):
    final_url = url
    with requests.Session() as session:
        try:
            response = session.get(url, allow_redirects=False)
            print(response.url)
            print(f'Is URL safe? {is_safe(response.url)}')
            while 'location' in response.headers:
                time.sleep(5)  # Wait for 5 seconds
                url = response.headers['location']
                response = session.get(url, allow_redirects=False)
                print(response.url)
                print(f'Is URL safe? {is_safe(response.url)}')
                final_url = response.url
        except requests.exceptions.RequestException as e:
            print(f'An error occurred: {e}')
    return final_url  # Return the final URL

link = input('Enter the link you want: ')
result = print_redirects(link)  # Assign the final URL to 'result'
print('Do you want to go to the result immediately?')
answer = input('Yes or No?\n')
if answer == 'Y' or answer == 'Yes' or answer == 'yes' or answer == 'y':
    webbrowser.open(result)  # Open the final URL
    exit()
else:
    exit()
