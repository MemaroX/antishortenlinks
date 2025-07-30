#!/usr/bin/python
import requests
import time
import webbrowser
import customtkinter
import tkinter as tk
from tkinter import messagebox

def is_safe(url):
    import os
    api_key = os.getenv('VIRUSTOTAL_API_KEY')
    if not api_key:
        messagebox.showerror("Error", "VirusTotal API key not found. Please set the VIRUSTOTAL_API_KEY environment variable.")
        return False
    try:
        url_id = requests.get('https://www.virustotal.com/vtapi/v2/url/report',
                              params={'apikey': api_key, 'resource':url})
        report = url_id.json()
        if 'positives' in report and report['positives'] > 0:
            return False
        else:
            return True
    except requests.exceptions.RequestException as e:
        print(f"Network Error during URL safety check: {e}")
        import traceback
        traceback.print_exc()
        messagebox.showerror("Network Error", f"An error occurred while checking URL safety: {e}")
        return False

def print_redirects(url, output_text_widget):
    final_url = url
    output_text_widget.insert(tk.END, f"Checking: {url}\n")
    output_text_widget.see(tk.END)
    with requests.Session() as session:
        try:
            response = session.get(url, allow_redirects=False)
            output_text_widget.insert(tk.END, f"  -> {response.url}\n")
            output_text_widget.insert(tk.END, f"  Is URL safe? {is_safe(response.url)}\n")
            output_text_widget.see(tk.END)
            while 'location' in response.headers:
                time.sleep(1)  # Reduced sleep for GUI responsiveness
                url = response.headers['location']
                response = session.get(url, allow_redirects=False)
                output_text_widget.insert(tk.END, f"  -> {response.url}\n")
                output_text_widget.insert(tk.END, f"  Is URL safe? {is_safe(response.url)}\n")
                output_text_widget.see(tk.END)
                final_url = response.url
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Network Error", f"An error occurred during redirection check: {e}")
    return final_url

class App(customtkinter.CTk):
    def __init__(self):
        super().__init__()

        self.title("Anti-Shorten Links")
        self.geometry("700x500")

        # Configure grid layout
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=0)
        self.grid_rowconfigure(1, weight=1)
        self.grid_rowconfigure(2, weight=0)

        # Input Frame
        self.input_frame = customtkinter.CTkFrame(self)
        self.input_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        self.input_frame.grid_columnconfigure(0, weight=1)

        self.url_label = customtkinter.CTkLabel(self.input_frame, text="Enter URL:")
        self.url_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")

        self.url_entry = customtkinter.CTkEntry(self.input_frame, placeholder_text="http://shortened.url")
        self.url_entry.grid(row=1, column=0, padx=5, pady=5, sticky="ew")

        self.check_button = customtkinter.CTkButton(self.input_frame, text="Check URL", command=self.check_url)
        self.check_button.grid(row=2, column=0, padx=5, pady=5, sticky="ew")

        # Output Frame
        self.output_frame = customtkinter.CTkFrame(self)
        self.output_frame.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")
        self.output_frame.grid_columnconfigure(0, weight=1)
        self.output_frame.grid_rowconfigure(0, weight=1)

        self.output_text = customtkinter.CTkTextbox(self.output_frame, wrap="word")
        self.output_text.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")

        # Action Frame
        self.action_frame = customtkinter.CTkFrame(self)
        self.action_frame.grid(row=2, column=0, padx=10, pady=10, sticky="ew")
        self.action_frame.grid_columnconfigure(0, weight=1)

        self.open_button = customtkinter.CTkButton(self.action_frame, text="Open Final URL", command=self.open_final_url, state="disabled")
        self.open_button.grid(row=0, column=0, padx=5, pady=5, sticky="ew")

        self.final_url = None

    def check_url(self):
        url = self.url_entry.get()
        if not url:
            messagebox.showwarning("Input Error", "Please enter a URL.")
            return

        if not url.startswith("http://") and not url.startswith("https://"):
            url = "https://" + url

        self.output_text.delete("1.0", tk.END)  # Clear previous output
        self.open_button.configure(state="disabled")
        self.final_url = None

        self.final_url = print_redirects(url, self.output_text)
        if self.final_url:
            self.output_text.insert(tk.END, f"\nFinal URL: {self.final_url}\n")
            self.output_text.see(tk.END)
            self.open_button.configure(state="normal")

    def open_final_url(self):
        if self.final_url:
            webbrowser.open(self.final_url)
        else:
            messagebox.showwarning("No URL", "No final URL to open. Please check a URL first.")

if __name__ == "__main__":
    app = App()
    app.mainloop()