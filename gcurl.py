import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import subprocess
import json
import os
import re  # Added for regular expressions
from threading import Thread

class CurlGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Curl GUI Manager")
        self.root.geometry("1200x800")
        
        # Create main notebook for tabs
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self.request_tab = ttk.Frame(self.notebook)
        self.response_tab = ttk.Frame(self.notebook)
        self.headers_tab = ttk.Frame(self.notebook)
        self.auth_tab = ttk.Frame(self.notebook)
        self.advanced_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.request_tab, text="Request")
        self.notebook.add(self.response_tab, text="Response")
        self.notebook.add(self.headers_tab, text="Headers")
        self.notebook.add(self.auth_tab, text="Authentication")
        self.notebook.add(self.advanced_tab, text="Advanced Options")
        
        # Initialize all tabs
        self.initialize_request_tab()
        self.initialize_response_tab()
        self.initialize_headers_tab()
        self.initialize_auth_tab()
        self.initialize_advanced_tab()
        
        # Command history
        self.command_history = []
        self.history_index = -1
        
        # Status bar
        self.status_bar = tk.Label(root, text="Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Add command execution button at the bottom
        self.execute_frame = ttk.Frame(root)
        self.execute_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.curl_command_display = ttk.Entry(self.execute_frame, width=80)
        self.curl_command_display.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        self.execute_button = ttk.Button(self.execute_frame, text="Execute", command=self.execute_curl)
        self.execute_button.pack(side=tk.RIGHT)
        
        self.save_button = ttk.Button(self.execute_frame, text="Save Command", command=self.save_command)
        self.save_button.pack(side=tk.RIGHT, padx=5)
        
        self.load_button = ttk.Button(self.execute_frame, text="Load Command", command=self.load_command)
        self.load_button.pack(side=tk.RIGHT, padx=5)

    def initialize_request_tab(self):
        # URL and method section
        url_frame = ttk.LabelFrame(self.request_tab, text="URL and Method")
        url_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(url_frame, text="URL:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.url_entry = ttk.Entry(url_frame, width=80)
        self.url_entry.grid(row=0, column=1, sticky=tk.W+tk.E, padx=5, pady=5)
        
        ttk.Label(url_frame, text="Method:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.method_var = tk.StringVar(value="GET")
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
        self.method_combo = ttk.Combobox(url_frame, textvariable=self.method_var, values=methods)
        self.method_combo.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Request body section
        body_frame = ttk.LabelFrame(self.request_tab, text="Request Body")
        body_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.body_type_var = tk.StringVar(value="none")
        body_types = [("None", "none"), 
                     ("Raw", "raw"), 
                     ("Form Data", "form"), 
                     ("JSON", "json"),
                     ("File Upload", "file")]
        
        # Body type radio buttons
        body_type_frame = ttk.Frame(body_frame)
        body_type_frame.pack(fill=tk.X, padx=5, pady=5)
        
        for text, value in body_types:
            ttk.Radiobutton(body_type_frame, text=text, variable=self.body_type_var, 
                           value=value, command=self.update_body_frame).pack(side=tk.LEFT, padx=5)
        
        # Container for body content based on type
        self.body_content_frame = ttk.Frame(body_frame)
        self.body_content_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Initialize with empty content
        self.update_body_frame()
        
        # Options section
        options_frame = ttk.LabelFrame(self.request_tab, text="Request Options")
        options_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Follow redirects
        self.follow_redirects_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Follow Redirects", variable=self.follow_redirects_var).grid(
            row=0, column=0, sticky=tk.W, padx=5, pady=5)
        
        # Include response headers
        self.include_headers_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Include Response Headers", variable=self.include_headers_var).grid(
            row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Verbose output
        self.verbose_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Verbose Output", variable=self.verbose_var).grid(
            row=0, column=2, sticky=tk.W, padx=5, pady=5)
        
        # Timeout
        ttk.Label(options_frame, text="Timeout (sec):").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.timeout_var = tk.StringVar(value="30")
        ttk.Entry(options_frame, textvariable=self.timeout_var, width=10).grid(
            row=1, column=1, sticky=tk.W, padx=5, pady=5)

    def update_body_frame(self):
        # Clear current content
        for widget in self.body_content_frame.winfo_children():
            widget.destroy()
            
        body_type = self.body_type_var.get()
        
        if body_type == "none":
            # No body widgets needed
            pass
            
        elif body_type == "raw":
            self.body_text = scrolledtext.ScrolledText(self.body_content_frame, height=15)
            self.body_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            content_type_frame = ttk.Frame(self.body_content_frame)
            content_type_frame.pack(fill=tk.X, padx=5, pady=5)
            
            ttk.Label(content_type_frame, text="Content-Type:").pack(side=tk.LEFT, padx=5)
            self.content_type_var = tk.StringVar(value="text/plain")
            content_types = ["text/plain", "application/json", "application/xml", "text/html", "application/x-www-form-urlencoded"]
            self.content_type_combo = ttk.Combobox(content_type_frame, textvariable=self.content_type_var, values=content_types)
            self.content_type_combo.pack(side=tk.LEFT, padx=5)
            
        elif body_type == "form":
            # Form data with key-value pairs
            form_control_frame = ttk.Frame(self.body_content_frame)
            form_control_frame.pack(fill=tk.X, padx=5, pady=5)
            
            ttk.Button(form_control_frame, text="Add Field", command=self.add_form_field).pack(side=tk.LEFT, padx=5)
            
            # Container for form fields
            self.form_fields_frame = ttk.Frame(self.body_content_frame)
            self.form_fields_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            # Add initial field
            self.add_form_field()
            
        elif body_type == "json":
            self.json_text = scrolledtext.ScrolledText(self.body_content_frame, height=15)
            self.json_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            json_tools_frame = ttk.Frame(self.body_content_frame)
            json_tools_frame.pack(fill=tk.X, padx=5, pady=5)
            
            ttk.Button(json_tools_frame, text="Format JSON", command=self.format_json).pack(side=tk.LEFT, padx=5)
            ttk.Button(json_tools_frame, text="Validate JSON", command=self.validate_json).pack(side=tk.LEFT, padx=5)
            
        elif body_type == "file":
            file_frame = ttk.Frame(self.body_content_frame)
            file_frame.pack(fill=tk.X, padx=5, pady=10)
            
            ttk.Label(file_frame, text="File:").pack(side=tk.LEFT, padx=5)
            self.file_path_var = tk.StringVar()
            ttk.Entry(file_frame, textvariable=self.file_path_var, width=60).pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
            ttk.Button(file_frame, text="Browse...", command=self.browse_file).pack(side=tk.LEFT, padx=5)

    def add_form_field(self):
        row_frame = ttk.Frame(self.form_fields_frame)
        row_frame.pack(fill=tk.X, padx=5, pady=2)
        
        key_entry = ttk.Entry(row_frame, width=30)
        key_entry.pack(side=tk.LEFT, padx=5)
        
        value_entry = ttk.Entry(row_frame, width=50)
        value_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        ttk.Button(row_frame, text="Remove", 
                  command=lambda frame=row_frame: frame.destroy()).pack(side=tk.LEFT, padx=5)

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_path_var.set(file_path)

    def format_json(self):
        try:
            text = self.json_text.get("1.0", tk.END).strip()
            if not text:
                return
                
            parsed = json.loads(text)
            formatted = json.dumps(parsed, indent=2)
            
            self.json_text.delete("1.0", tk.END)
            self.json_text.insert("1.0", formatted)
            
        except json.JSONDecodeError as e:
            messagebox.showerror("JSON Error", f"Invalid JSON: {str(e)}")

    def validate_json(self):
        try:
            text = self.json_text.get("1.0", tk.END).strip()
            if not text:
                messagebox.showinfo("JSON Validation", "No JSON entered")
                return
                
            json.loads(text)
            messagebox.showinfo("JSON Validation", "Valid JSON format")
            
        except json.JSONDecodeError as e:
            messagebox.showerror("JSON Error", f"Invalid JSON: {str(e)}")

    def initialize_response_tab(self):
        # Response paned window - headers on top, body below
        response_paned = ttk.PanedWindow(self.response_tab, orient=tk.VERTICAL)
        response_paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Headers frame
        headers_frame = ttk.LabelFrame(response_paned, text="Response Headers")
        self.response_headers = scrolledtext.ScrolledText(headers_frame, height=6)
        self.response_headers.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        response_paned.add(headers_frame)
        
        # Body frame
        body_frame = ttk.LabelFrame(response_paned, text="Response Body")
        
        # Response format toolbar
        format_frame = ttk.Frame(body_frame)
        format_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.response_format_var = tk.StringVar(value="auto")
        formats = [("Auto", "auto"), ("Raw", "raw"), ("JSON", "json"), ("XML", "xml"), ("HTML", "html")]
        
        for text, value in formats:
            ttk.Radiobutton(format_frame, text=text, variable=self.response_format_var, 
                           value=value, command=self.update_response_format).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(format_frame, text="Pretty Print", command=self.pretty_print_response).pack(side=tk.LEFT, padx=15)
        ttk.Button(format_frame, text="Save Response", command=self.save_response).pack(side=tk.LEFT, padx=5)
        
        # Response body text
        self.response_body = scrolledtext.ScrolledText(body_frame, height=20)
        self.response_body.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Response metrics
        metrics_frame = ttk.Frame(body_frame)
        metrics_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(metrics_frame, text="Status:").pack(side=tk.LEFT, padx=5)
        self.status_var = tk.StringVar(value="")
        ttk.Label(metrics_frame, textvariable=self.status_var).pack(side=tk.LEFT, padx=5)
        
        ttk.Label(metrics_frame, text="Time:").pack(side=tk.LEFT, padx=15)
        self.time_var = tk.StringVar(value="")
        ttk.Label(metrics_frame, textvariable=self.time_var).pack(side=tk.LEFT, padx=5)
        
        ttk.Label(metrics_frame, text="Size:").pack(side=tk.LEFT, padx=15)
        self.size_var = tk.StringVar(value="")
        ttk.Label(metrics_frame, textvariable=self.size_var).pack(side=tk.LEFT, padx=5)
        
        response_paned.add(body_frame)

    def update_response_format(self):
        # This would process the current response data according to selected format
        pass

    def pretty_print_response(self):
        format_type = self.response_format_var.get()
        content = self.response_body.get("1.0", tk.END).strip()
        
        if not content:
            return
            
        try:
            if format_type == "json" or (format_type == "auto" and content.startswith("{")):
                # Format JSON
                parsed = json.loads(content)
                formatted = json.dumps(parsed, indent=2)
                self.response_body.delete("1.0", tk.END)
                self.response_body.insert("1.0", formatted)
                
            elif format_type == "xml" or (format_type == "auto" and content.startswith("<")):
                # We'd need an XML formatter here
                # For simplicity, just show a message
                messagebox.showinfo("XML Formatting", "XML formatting would be done here")
                
        except Exception as e:
            messagebox.showerror("Format Error", f"Error formatting content: {str(e)}")

    def save_response(self):
        content = self.response_body.get("1.0", tk.END)
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[
                ("Text files", "*.txt"),
                ("JSON files", "*.json"),
                ("XML files", "*.xml"),
                ("HTML files", "*.html"),
                ("All files", "*.*")
            ]
        )
        
        if file_path:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)
            messagebox.showinfo("Save Successful", f"Response saved to {file_path}")

    def initialize_headers_tab(self):
        # Header controls
        control_frame = ttk.Frame(self.headers_tab)
        control_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(control_frame, text="Add Header", command=self.add_header).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Add Common Headers", command=self.add_common_headers).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Clear All", command=self.clear_headers).pack(side=tk.LEFT, padx=5)
        
        # Headers container
        headers_container = ttk.Frame(self.headers_tab)
        headers_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.headers_canvas = tk.Canvas(headers_container)
        scrollbar = ttk.Scrollbar(headers_container, orient=tk.VERTICAL, command=self.headers_canvas.yview)
        self.headers_canvas.configure(yscrollcommand=scrollbar.set)
        
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.headers_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Frame for header fields
        self.headers_frame = ttk.Frame(self.headers_canvas)
        self.headers_canvas_frame = self.headers_canvas.create_window((0, 0), window=self.headers_frame, anchor=tk.NW)
        
        # Configure scroll region when size changes
        self.headers_frame.bind("<Configure>", self.on_headers_frame_configure)
        self.headers_canvas.bind("<Configure>", self.on_headers_canvas_configure)
        
        # Add some common headers for convenience
        common_headers_frame = ttk.LabelFrame(self.headers_tab, text="Common Headers")
        common_headers_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # User-Agent
        ua_frame = ttk.Frame(common_headers_frame)
        ua_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(ua_frame, text="User-Agent:").pack(side=tk.LEFT, padx=5)
        self.user_agent_var = tk.StringVar(value="curl/7.79.1")
        ttk.Entry(ua_frame, textvariable=self.user_agent_var, width=50).pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        # Accept
        accept_frame = ttk.Frame(common_headers_frame)
        accept_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(accept_frame, text="Accept:").pack(side=tk.LEFT, padx=5)
        self.accept_var = tk.StringVar(value="*/*")
        accept_values = ["*/*", "application/json", "application/xml", "text/html", "text/plain"]
        ttk.Combobox(accept_frame, textvariable=self.accept_var, values=accept_values, width=50).pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

    def add_header(self):
        row_frame = ttk.Frame(self.headers_frame)
        row_frame.pack(fill=tk.X, padx=5, pady=2)
        
        key_entry = ttk.Entry(row_frame, width=30)
        key_entry.pack(side=tk.LEFT, padx=5)
        
        value_entry = ttk.Entry(row_frame, width=50)
        value_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        ttk.Button(row_frame, text="Remove", 
                  command=lambda frame=row_frame: frame.destroy()).pack(side=tk.LEFT, padx=5)

    def add_common_headers(self):
        common_headers = [
            ("Accept", "*/*"),
            ("Accept-Language", "en-US,en;q=0.9"),
            ("Cache-Control", "no-cache"),
            ("Content-Type", "application/json"),
            ("User-Agent", "curl/7.79.1")
        ]
        
        for key, value in common_headers:
            row_frame = ttk.Frame(self.headers_frame)
            row_frame.pack(fill=tk.X, padx=5, pady=2)
            
            key_entry = ttk.Entry(row_frame, width=30)
            key_entry.insert(0, key)
            key_entry.pack(side=tk.LEFT, padx=5)
            
            value_entry = ttk.Entry(row_frame, width=50)
            value_entry.insert(0, value)
            value_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
            
            ttk.Button(row_frame, text="Remove", 
                      command=lambda frame=row_frame: frame.destroy()).pack(side=tk.LEFT, padx=5)

    def clear_headers(self):
        for widget in self.headers_frame.winfo_children():
            widget.destroy()

    def on_headers_frame_configure(self, event):
        self.headers_canvas.configure(scrollregion=self.headers_canvas.bbox("all"))

    def on_headers_canvas_configure(self, event):
        self.headers_canvas.itemconfig(self.headers_canvas_frame, width=event.width)

    def initialize_auth_tab(self):
        # Auth method selection
        auth_method_frame = ttk.LabelFrame(self.auth_tab, text="Authentication Method")
        auth_method_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.auth_method_var = tk.StringVar(value="none")
        auth_methods = [
            ("None", "none"),
            ("Basic Auth", "basic"),
            ("Bearer Token", "bearer"),
            ("API Key", "apikey"),
            ("OAuth 2.0", "oauth"),
            ("Digest Auth", "digest"),
            ("AWS Signature", "aws")
        ]
        
        for text, value in auth_methods:
            ttk.Radiobutton(auth_method_frame, text=text, variable=self.auth_method_var, 
                           value=value, command=self.update_auth_frame).pack(side=tk.LEFT, padx=10)
        
        # Container for auth settings
        self.auth_container = ttk.Frame(self.auth_tab)
        self.auth_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Initialize with default (none)
        self.update_auth_frame()

    def update_auth_frame(self):
        # Clear current auth settings
        for widget in self.auth_container.winfo_children():
            widget.destroy()
            
        auth_method = self.auth_method_var.get()
        
        if auth_method == "none":
            ttk.Label(self.auth_container, text="No authentication will be used").pack(padx=10, pady=20)
            
        elif auth_method == "basic":
            basic_frame = ttk.Frame(self.auth_container)
            basic_frame.pack(fill=tk.X, padx=10, pady=10)
            
            ttk.Label(basic_frame, text="Username:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
            self.basic_username = ttk.Entry(basic_frame, width=40)
            self.basic_username.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
            
            ttk.Label(basic_frame, text="Password:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
            self.basic_password = ttk.Entry(basic_frame, width=40, show="*")
            self.basic_password.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
            
        elif auth_method == "bearer":
            bearer_frame = ttk.Frame(self.auth_container)
            bearer_frame.pack(fill=tk.X, padx=10, pady=10)
            
            ttk.Label(bearer_frame, text="Token:").pack(side=tk.LEFT, padx=5)
            self.bearer_token = ttk.Entry(bearer_frame, width=60)
            self.bearer_token.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
            
        elif auth_method == "apikey":
            apikey_frame = ttk.Frame(self.auth_container)
            apikey_frame.pack(fill=tk.X, padx=10, pady=10)
            
            ttk.Label(apikey_frame, text="Key Name:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
            self.apikey_name = ttk.Entry(apikey_frame, width=30)
            self.apikey_name.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
            
            ttk.Label(apikey_frame, text="Key Value:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
            self.apikey_value = ttk.Entry(apikey_frame, width=50)
            self.apikey_value.grid(row=1, column=1, sticky=tk.W+tk.E, padx=5, pady=5)
            
            ttk.Label(apikey_frame, text="Add In:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
            self.apikey_in_var = tk.StringVar(value="header")
            apikey_in_frame = ttk.Frame(apikey_frame)
            apikey_in_frame.grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
            
            ttk.Radiobutton(apikey_in_frame, text="Header", variable=self.apikey_in_var, value="header").pack(side=tk.LEFT, padx=5)
            ttk.Radiobutton(apikey_in_frame, text="Query Parameter", variable=self.apikey_in_var, value="query").pack(side=tk.LEFT, padx=5)
            
        elif auth_method == "oauth":
            oauth_frame = ttk.LabelFrame(self.auth_container, text="OAuth 2.0")
            oauth_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            ttk.Label(oauth_frame, text="Token URL:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
            self.oauth_token_url = ttk.Entry(oauth_frame, width=60)
            self.oauth_token_url.grid(row=0, column=1, columnspan=2, sticky=tk.W+tk.E, padx=5, pady=5)
            
            ttk.Label(oauth_frame, text="Client ID:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
            self.oauth_client_id = ttk.Entry(oauth_frame, width=40)
            self.oauth_client_id.grid(row=1, column=1, sticky=tk.W+tk.E, padx=5, pady=5)
            
            ttk.Label(oauth_frame, text="Client Secret:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
            self.oauth_client_secret = ttk.Entry(oauth_frame, width=40, show="*")
            self.oauth_client_secret.grid(row=2, column=1, sticky=tk.W+tk.E, padx=5, pady=5)
            
            ttk.Label(oauth_frame, text="Scope:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
            self.oauth_scope = ttk.Entry(oauth_frame, width=60)
            self.oauth_scope.grid(row=3, column=1, columnspan=2, sticky=tk.W+tk.E, padx=5, pady=5)
            
            ttk.Button(oauth_frame, text="Request Token", command=self.request_oauth_token).grid(
                row=4, column=1, padx=5, pady=10)
            
        elif auth_method == "digest":
            digest_frame = ttk.Frame(self.auth_container)
            digest_frame.pack(fill=tk.X, padx=10, pady=10)
            
            ttk.Label(digest_frame, text="Username:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
            self.digest_username = ttk.Entry(digest_frame, width=40)
            self.digest_username.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
            
            ttk.Label(digest_frame, text="Password:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
            self.digest_password = ttk.Entry(digest_frame, width=40, show="*")
            self.digest_password.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
            
        elif auth_method == "aws":
            aws_frame = ttk.Frame(self.auth_container)
            aws_frame.pack(fill=tk.X, padx=10, pady=10)
            
            ttk.Label(aws_frame, text="Access Key:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
            self.aws_access_key = ttk.Entry(aws_frame, width=40)
            self.aws_access_key.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
            
            ttk.Label(aws_frame, text="Secret Key:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
            self.aws_secret_key = ttk.Entry(aws_frame, width=40, show="*")
            self.aws_secret_key.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
            
            ttk.Label(aws_frame, text="Region:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
            self.aws_region = ttk.Entry(aws_frame, width=20)
            self.aws_region.grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
            
            ttk.Label(aws_frame, text="Service:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
            self.aws_service = ttk.Entry(aws_frame, width=20)
            self.aws_service.grid(row=3, column=1, sticky=tk.W, padx=5, pady=5)

    def request_oauth_token(self):
        # Implement OAuth token request logic
        messagebox.showinfo("OAuth Token", "OAuth token request functionality would be implemented here")

    def initialize_advanced_tab(self):
        notebook = ttk.Notebook(self.advanced_tab)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # SSL/TLS options
        ssl_frame = ttk.Frame(notebook)
        notebook.add(ssl_frame, text="SSL/TLS")
        
        ssl_options_frame = ttk.LabelFrame(ssl_frame, text="SSL/TLS Options")
        ssl_options_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Verify SSL
        self.verify_ssl_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(ssl_options_frame, text="Verify SSL Certificate", variable=self.verify_ssl_var).grid(
            row=0, column=0, sticky=tk.W, padx=5, pady=5)
        
        # Client Certificate
        cert_frame = ttk.Frame(ssl_options_frame)
        cert_frame.grid(row=1, column=0, sticky=tk.W, padx=5, pady=5, columnspan=2)
        
        ttk.Label(cert_frame, text="Client Certificate:").pack(side=tk.LEFT, padx=5)
        self.client_cert_path = tk.StringVar()
        ttk.Entry(cert_frame, textvariable=self.client_cert_path, width=40).pack(side=tk.LEFT, padx=5)
        ttk.Button(cert_frame, text="Browse...", command=self.browse_cert).pack(side=tk.LEFT, padx=5)
        
        # Client Key
        key_frame = ttk.Frame(ssl_options_frame)
        key_frame.grid(row=2, column=0, sticky=tk.W, padx=5, pady=5, columnspan=2)
        
        ttk.Label(key_frame, text="Client Key:").pack(side=tk.LEFT, padx=5)
        self.client_key_path = tk.StringVar()
        ttk.Entry(key_frame, textvariable=self.client_key_path, width=40).pack(side=tk.LEFT, padx=5)
        ttk.Button(key_frame, text="Browse...", command=self.browse_key).pack(side=tk.LEFT, padx=5)
        
        # CA Certificate
        ca_frame = ttk.Frame(ssl_options_frame)
        ca_frame.grid(row=3, column=0, sticky=tk.W, padx=5, pady=5, columnspan=2)
        
        ttk.Label(ca_frame, text="CA Certificate:").pack(side=tk.LEFT, padx=5)
        self.ca_cert_path = tk.StringVar()
        ttk.Entry(ca_frame, textvariable=self.ca_cert_path, width=40).pack(side=tk.LEFT, padx=5)
        ttk.Button(ca_frame, text="Browse...", command=self.browse_ca).pack(side=tk.LEFT, padx=5)
        
        # SSL Protocols
        protocols_frame = ttk.LabelFrame(ssl_frame, text="SSL Protocols")
        protocols_frame.pack(fill=tk.X, padx=10, pady=10)
        
        protocols = ["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3", "SSLv3"]
        self.protocol_vars = {}
        
        for i, protocol in enumerate(protocols):
            var = tk.BooleanVar(value=protocol in ["TLSv1.2", "TLSv1.3"])
            self.protocol_vars[protocol] = var
            ttk.Checkbutton(protocols_frame, text=protocol, variable=var).grid(
                row=i//3, column=i%3, sticky=tk.W, padx=15, pady=5)
        
        # Proxy options
        proxy_frame = ttk.Frame(notebook)
        notebook.add(proxy_frame, text="Proxy")
        
        proxy_options = ttk.LabelFrame(proxy_frame, text="Proxy Settings")
        proxy_options.pack(fill=tk.X, padx=10, pady=10)
        
        # Use Proxy
        proxy_enable_frame = ttk.Frame(proxy_options)
        proxy_enable_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.use_proxy_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(proxy_enable_frame, text="Use Proxy", variable=self.use_proxy_var, 
                        command=self.toggle_proxy_options).pack(side=tk.LEFT, padx=5)
        
        # Proxy URL
        proxy_url_frame = ttk.Frame(proxy_options)
        proxy_url_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(proxy_url_frame, text="Proxy URL:").pack(side=tk.LEFT, padx=5)
        self.proxy_url = ttk.Entry(proxy_url_frame, width=60)
        self.proxy_url.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        # Proxy Authentication
        proxy_auth_frame = ttk.Frame(proxy_options)
        proxy_auth_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(proxy_auth_frame, text="Username:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.proxy_username = ttk.Entry(proxy_auth_frame, width=30)
        self.proxy_username.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(proxy_auth_frame, text="Password:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.proxy_password = ttk.Entry(proxy_auth_frame, width=30, show="*")
        self.proxy_password.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Disable proxy fields initially
        self.toggle_proxy_options()
        
        # Advanced options
        advanced_frame = ttk.Frame(notebook)
        notebook.add(advanced_frame, text="Advanced")
        
        # Connection options
        connection_frame = ttk.LabelFrame(advanced_frame, text="Connection Options")
        connection_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Connect timeout
        ttk.Label(connection_frame, text="Connect Timeout (sec):").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.connect_timeout = ttk.Entry(connection_frame, width=10)
        self.connect_timeout.insert(0, "30")
        self.connect_timeout.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Max redirects
        ttk.Label(connection_frame, text="Max Redirects:").grid(row=0, column=2, sticky=tk.W, padx=15, pady=5)
        self.max_redirects = ttk.Entry(connection_frame, width=10)
        self.max_redirects.insert(0, "5")
        self.max_redirects.grid(row=0, column=3, sticky=tk.W, padx=5, pady=5)
        
        # Retry options
        retry_frame = ttk.LabelFrame(advanced_frame, text="Retry Options")
        retry_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Retry count
        ttk.Label(retry_frame, text="Retry Count:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.retry_count = ttk.Entry(retry_frame, width=10)
        self.retry_count.insert(0, "0")
        self.retry_count.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Retry delay
        ttk.Label(retry_frame, text="Retry Delay (sec):").grid(row=0, column=2, sticky=tk.W, padx=15, pady=5)
        self.retry_delay = ttk.Entry(retry_frame, width=10)
        self.retry_delay.insert(0, "1")
        self.retry_delay.grid(row=0, column=3, sticky=tk.W, padx=5, pady=5)
        
        # Extra options
        extra_frame = ttk.LabelFrame(advanced_frame, text="Extra Options")
        extra_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(extra_frame, text="Additional curl Parameters:").pack(side=tk.LEFT, padx=5, pady=5)
        self.extra_params = ttk.Entry(extra_frame, width=60)
        self.extra_params.pack(side=tk.LEFT, padx=5, pady=5, fill=tk.X, expand=True)

    def toggle_proxy_options(self):
        state = "normal" if self.use_proxy_var.get() else "disabled"
        self.proxy_url.config(state=state)
        self.proxy_username.config(state=state)
        self.proxy_password.config(state=state)

    def browse_cert(self):
        file_path = filedialog.askopenfilename(filetypes=[("Certificate files", "*.crt *.pem *.cert"), ("All files", "*.*")])
        if file_path:
            self.client_cert_path.set(file_path)

    def browse_key(self):
        file_path = filedialog.askopenfilename(filetypes=[("Key files", "*.key *.pem"), ("All files", "*.*")])
        if file_path:
            self.client_key_path.set(file_path)

    def browse_ca(self):
        file_path = filedialog.askopenfilename(filetypes=[("Certificate files", "*.crt *.pem *.cert"), ("All files", "*.*")])
        if file_path:
            self.ca_cert_path.set(file_path)

    def build_curl_command(self):
        # Start with the base command
        command = ["curl"]
        
        # Add method
        method = self.method_var.get()
        if method != "GET":
            command.extend(["-X", method])
        
        # Add URL
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Error", "URL is required")
            return None
            
        # Add headers
        # Common headers
        if self.accept_var.get() and self.accept_var.get() != "*/*":
            command.extend(["-H", f"Accept: {self.accept_var.get()}"])
            
        if self.user_agent_var.get():
            command.extend(["-H", f"User-Agent: {self.user_agent_var.get()}"])
        
        # Custom headers
        for widget in self.headers_frame.winfo_children():
            if isinstance(widget, ttk.Frame):
                header_widgets = widget.winfo_children()
                if len(header_widgets) >= 2:  # Key and value entries
                    key = header_widgets[0].get().strip()
                    value = header_widgets[1].get().strip()
                    if key and value:
                        command.extend(["-H", f"{key}: {value}"])
        
        # Add request body
        body_type = self.body_type_var.get()
        
        if body_type == "raw":
            content = self.body_text.get("1.0", tk.END).strip()
            if content:
                command.extend(["-d", content])
                # Add content type if specified
                content_type = self.content_type_var.get()
                if content_type:
                    command.extend(["-H", f"Content-Type: {content_type}"])
                    
        elif body_type == "form":
            form_data = []
            for widget in self.form_fields_frame.winfo_children():
                if isinstance(widget, ttk.Frame):
                    form_widgets = widget.winfo_children()
                    if len(form_widgets) >= 2:  # Key and value entries
                        key = form_widgets[0].get().strip()
                        value = form_widgets[1].get().strip()
                        if key:
                            form_data.append(f"{key}={value}")
            
            if form_data:
                command.extend(["-d", "&".join(form_data)])
                command.extend(["-H", "Content-Type: application/x-www-form-urlencoded"])
                
        elif body_type == "json":
            json_content = self.json_text.get("1.0", tk.END).strip()
            if json_content:
                command.extend(["-d", json_content])
                command.extend(["-H", "Content-Type: application/json"])
                
        elif body_type == "file":
            file_path = self.file_path_var.get()
            if file_path:
                command.extend(["-d", f"@{file_path}"])
        
        # Add authentication
        auth_method = self.auth_method_var.get()
        
        if auth_method == "basic":
            username = self.basic_username.get()
            password = self.basic_password.get()
            if username:
                command.extend(["-u", f"{username}:{password}"])
                
        elif auth_method == "bearer":
            token = self.bearer_token.get()
            if token:
                command.extend(["-H", f"Authorization: Bearer {token}"])
                
        elif auth_method == "apikey":
            key_name = self.apikey_name.get()
            key_value = self.apikey_value.get()
            key_in = self.apikey_in_var.get()
            
            if key_name and key_value:
                if key_in == "header":
                    command.extend(["-H", f"{key_name}: {key_value}"])
                else:  # query parameter
                    # Append to URL
                    separator = "&" if "?" in url else "?"
                    url = f"{url}{separator}{key_name}={key_value}"
                    
        elif auth_method == "digest":
            username = self.digest_username.get()
            password = self.digest_password.get()
            if username:
                command.extend(["--digest", "-u", f"{username}:{password}"])
                
        elif auth_method == "aws":
            # AWS Signature would be complex to implement
            # For now, just add a placeholder
            if self.aws_access_key.get():
                command.append("--aws-sigv4")
        
        # Add SSL/TLS options
        if not self.verify_ssl_var.get():
            command.append("-k")
            
        if self.client_cert_path.get():
            command.extend(["--cert", self.client_cert_path.get()])
            
        if self.client_key_path.get():
            command.extend(["--key", self.client_key_path.get()])
            
        if self.ca_cert_path.get():
            command.extend(["--cacert", self.ca_cert_path.get()])
        
        # Add proxy options
        if self.use_proxy_var.get() and self.proxy_url.get():
            command.extend(["-x", self.proxy_url.get()])
            
            if self.proxy_username.get():
                command.extend(["-U", f"{self.proxy_username.get()}:{self.proxy_password.get()}"])
        
        # Add other options
        if self.follow_redirects_var.get():
            command.append("-L")
            
        if self.include_headers_var.get():
            command.append("-i")
            
        if self.verbose_var.get():
            command.append("-v")
            
        if self.timeout_var.get():
            command.extend(["-m", self.timeout_var.get()])
            
        if self.connect_timeout.get():
            command.extend(["--connect-timeout", self.connect_timeout.get()])
            
        if self.max_redirects.get():
            command.extend(["--max-redirs", self.max_redirects.get()])
            
        if self.retry_count.get() and int(self.retry_count.get()) > 0:
            command.extend(["--retry", self.retry_count.get()])
            
        if self.retry_delay.get() and int(self.retry_delay.get()) > 0:
            command.extend(["--retry-delay", self.retry_delay.get()])
        
        # Add extra parameters
        extra = self.extra_params.get().strip()
        if extra:
            command.extend(extra.split())
        
        # Add the URL at the end
        command.append(url)
        
        return command

    def execute_curl(self):
        command = self.build_curl_command()
        if not command:
            return
            
        # Display the command
        cmd_str = " ".join(command)
        self.curl_command_display.delete(0, tk.END)
        self.curl_command_display.insert(0, cmd_str)
        
        # Add to history
        self.command_history.append(cmd_str)
        
        # Update status
        self.status_bar.config(text="Executing...")
        
        # Clear response
        self.response_headers.delete("1.0", tk.END)
        self.response_body.delete("1.0", tk.END)
        
        # Execute in a separate thread to avoid freezing the UI
        thread = Thread(target=self.run_curl_command, args=(command,))
        thread.daemon = True
        thread.start()

    def run_curl_command(self, command):
        try:
            # Enable verbose output to get headers
            if "-v" not in command and "-i" not in command:
                command.append("-i")  # Include headers in output
                
            # Execute curl
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            # Get output
            stdout, stderr = process.communicate()
            
            # Process output
            self.process_curl_output(stdout, stderr, process.returncode)
            
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to execute curl: {str(e)}"))
            self.root.after(0, lambda: self.status_bar.config(text="Error: Failed to execute curl"))

    def process_curl_output(self, stdout, stderr, return_code):
        def update_ui():
            if return_code != 0:
                self.status_bar.config(text=f"Error: curl returned {return_code}")
                self.response_body.insert("1.0", f"Error executing curl command:\n\n{stderr}")
                return
                
            # Split headers and body if present
            if stdout.strip():
                # Try to split at the first empty line
                parts = stdout.split('\r\n\r\n', 1)
                if len(parts) == 1:
                    parts = stdout.split('\n\n', 1)
                
                if len(parts) > 1:
                    headers = parts[0]
                    body = parts[1]
                    
                    # Set headers
                    self.response_headers.insert("1.0", headers)
                    
                    # Extract status code
                    status_match = re.search(r'HTTP/\d\.\d\s+(\d+)', headers)
                    if status_match:
                        self.status_var.set(status_match.group(1))
                    
                    # Set body
                    self.response_body.insert("1.0", body)
                else:
                    # No clear separation, just put everything in the body
                    self.response_body.insert("1.0", stdout)
            
            # Update status bar
            self.status_bar.config(text="Request completed")
            
            # Update response size
            response_size = len(stdout.encode('utf-8'))
            if response_size < 1024:
                size_text = f"{response_size} B"
            elif response_size < 1024 * 1024:
                size_text = f"{response_size / 1024:.1f} KB"
            else:
                size_text = f"{response_size / (1024 * 1024):.1f} MB"
            
            self.size_var.set(size_text)
        
        # Schedule UI updates to run in the main thread
        self.root.after(0, update_ui)

    def save_command(self):
        command = self.curl_command_display.get()
        if not command:
            messagebox.showerror("Error", "No command to save")
            return
            
        file_path = filedialog.asksaveasfilename(
            defaultextension=".sh",
            filetypes=[("Shell scripts", "*.sh"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, "w") as f:
                    f.write("#!/bin/bash\n")
                    f.write(command)
                os.chmod(file_path, 0o755)  # Make executable
                messagebox.showinfo("Success", f"Command saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save command: {str(e)}")

    def load_command(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("Shell scripts", "*.sh"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, "r") as f:
                    content = f.read()
                    
                # Remove shebang if present
                if content.startswith("#!/"):
                    content = content.split("\n", 1)[1]
                    
                self.curl_command_display.delete(0, tk.END)
                self.curl_command_display.insert(0, content.strip())
                messagebox.showinfo("Success", "Command loaded successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load command: {str(e)}")

def main():
    root = tk.Tk()
    app = CurlGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
