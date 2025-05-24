import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
from ruamel.yaml import YAML
import yaml
import requests
import urllib3
import threading
import json
import uuid
from datetime import date

# Constants for UI configuration
FONT_TITLE = ("Arial", 16, "bold")
FONT_DEFAULT = ("Arial", 10)
PADX_DEFAULT = 5
PADY_DEFAULT = 8
BG_COLOR = "#f0f0f0"
ACCENT_COLOR = "#4a86e8"
TEXT_COLOR = "#333333"
BUTTON_BG = "#4a86e8"
BUTTON_FG = "black"
ENTRY_BG = "white"

class SigmaConverter:
    def __init__(self, root):
        self.root = root
        self.root.title("Enhanced Sigma Rule Converter")
        # Adjusted default window size to better fit content
        self.root.geometry("900x680")
        self.root.minsize(900, 780)

        # Configure styles
        self.style = ttk.Style()
        self._configure_styles()

        # Initialize variables
        self._init_variables()

        # Create main container
        self.main_container = ttk.Frame(root, padding="20 20 20 20", style="TFrame")
        self.main_container.pack(fill="both", expand=True)

        # Create notebook for tabbed interface
        self.notebook = ttk.Notebook(self.main_container)
        self.notebook.pack(fill="both", expand=True, pady=10)

        # Create tab frames (removed About tab)
        self.converter_frame = ttk.Frame(self.notebook, style="TFrame")
        self.upload_frame = ttk.Frame(self.notebook, style="TFrame")

        self.notebook.add(self.converter_frame, text="Converter")
        self.notebook.add(self.upload_frame, text="OpenSearch Upload")

        # Setup tabs
        self.setup_converter_tab()
        self.setup_upload_tab()

        # Disable certificate warnings
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _configure_styles(self):
        """Configure ttk styles for consistent UI appearance."""
        self.style.configure("TButton", font=FONT_DEFAULT, background=BUTTON_BG, foreground=BUTTON_FG)
        self.style.configure("TLabel", font=FONT_DEFAULT, background=BG_COLOR, foreground=TEXT_COLOR)
        self.style.configure("TRadiobutton", font=FONT_DEFAULT, background=BG_COLOR, foreground=TEXT_COLOR)
        self.style.configure("TCheckbutton", font=FONT_DEFAULT, background=BG_COLOR, foreground=TEXT_COLOR)
        self.style.configure("TFrame", background=BG_COLOR)

    def _init_variables(self):
        """Initialize all tkinter variables."""
        self.input_file_var = tk.StringVar()
        self.mapping_file_var = tk.StringVar()
        self.output_file_var = tk.StringVar()
        self.output_folder_var = tk.StringVar()
        self.file_name_var = tk.StringVar()
        self.multiple_files_var = tk.StringVar()
        self.mode_var = tk.StringVar(value="single")
        self.single_output_option = tk.StringVar(value="file")
        self.conversion_type_var = tk.StringVar(value="winlogbeat")
        self.username_var = tk.StringVar(value="admin")
        self.password_var = tk.StringVar(value="")
        self.show_password_var = tk.BooleanVar(value=False)
        self.node_ip_var = tk.StringVar(value="localhost")
        self.port_var = tk.StringVar(value="9200")
        self.category_var = tk.StringVar(value="windows")
        self.upload_mode_var = tk.StringVar(value="single")
        self.upload_input_file_var = tk.StringVar()
        self.upload_folder_var = tk.StringVar()
        self.upload_mapping_file_var = tk.StringVar()
        self.upload_status_var = tk.StringVar(value="Ready")

    def _create_label_entry_button(self, parent, label_text, variable, button_text, command, row, column, width=50, entry_options=None, include_checkbox=False):
        """Helper method to create a label-entry-button row, optionally with a checkbox."""
        if entry_options is None:
            entry_options = {}
        ttk.Label(parent, text=label_text, style="TLabel").grid(row=row, column=column, sticky="w", padx=PADX_DEFAULT, pady=PADY_DEFAULT)
        entry = ttk.Entry(parent, textvariable=variable, width=width, **entry_options)
        entry.grid(row=row, column=column+1, padx=PADX_DEFAULT, pady=PADY_DEFAULT, sticky="ew")
        if button_text and command:
            ttk.Button(parent, text=button_text, command=command).grid(row=row, column=column+2, padx=PADX_DEFAULT, pady=PADY_DEFAULT)
        if include_checkbox:
            ttk.Checkbutton(parent, text="Show Password", variable=self.show_password_var, command=self.toggle_password_visibility, style="TCheckbutton").grid(
                row=row+1, column=column+1, columnspan=2, sticky="w", padx=PADX_DEFAULT, pady=(0, PADY_DEFAULT))
        return entry

    def toggle_password_visibility(self):
        """Toggle the visibility of the password entry."""
        self.password_entry.config(show="" if self.show_password_var.get() else "•")

    def setup_upload_tab(self):
        """Setup the OpenSearch upload tab."""
        upload_container = ttk.Frame(self.upload_frame, style="TFrame")
        upload_container.pack(fill="both", expand=True, padx=10, pady=10)
    
        # Title
        ttk.Label(upload_container, text="OpenSearch Rule Upload", font=FONT_TITLE, style="TLabel").grid(
            row=0, column=0, columnspan=3, pady=(0, 20), sticky="w")
    
        # Connection settings
        conn_frame = ttk.LabelFrame(upload_container, text="Connection Settings", style="TFrame")
        conn_frame.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(0, 15), padx=5)
    
        # Connection fields
        self._create_label_entry_button(conn_frame, "Username:", self.username_var, None, None, 0, 0, width=20)
        self.password_entry = self._create_label_entry_button(conn_frame, "Password:", self.password_var, None, None, 0, 2, width=20,
                                                             entry_options={"show": "•"}, include_checkbox=True)
        self._create_label_entry_button(conn_frame, "Node IP:", self.node_ip_var, None, None, 2, 0, width=20)
        self._create_label_entry_button(conn_frame, "Port:", self.port_var, None, None, 2, 2, width=20)
    
        # Category
        ttk.Label(conn_frame, text="Category:", style="TLabel").grid(row=3, column=0, sticky="w", padx=PADX_DEFAULT, pady=PADY_DEFAULT)
        category_combobox = ttk.Combobox(conn_frame, textvariable=self.category_var,
                                        values=["windows", "linux", "apache_access"],
                                        state="readonly", width=17)
        category_combobox.grid(row=3, column=1, padx=PADX_DEFAULT, pady=PADY_DEFAULT, sticky="w")
        category_combobox.current(0)
    
        # File selection
        file_frame = ttk.LabelFrame(upload_container, text="File Selection", style="TFrame")
        file_frame.grid(row=2, column=0, columnspan=3, sticky="ew", pady=(0, 15), padx=5)
    
        # Upload mode
        ttk.Label(file_frame, text="Upload Mode:", style="TLabel").grid(row=0, column=0, sticky="w", padx=PADX_DEFAULT, pady=PADY_DEFAULT)
        mode_frame = ttk.Frame(file_frame, style="TFrame")
        mode_frame.grid(row=0, column=1, columnspan=2, sticky="w", padx=PADX_DEFAULT, pady=PADY_DEFAULT)
        ttk.Radiobutton(mode_frame, text="Single File", variable=self.upload_mode_var,
                        value="single", command=self.toggle_upload_mode, style="TRadiobutton").grid(row=0, column=0, padx=(0, 10), pady=0)
        ttk.Radiobutton(mode_frame, text="Folder", variable=self.upload_mode_var,
                        value="folder", command=self.toggle_upload_mode, style="TRadiobutton").grid(row=0, column=1, padx=0, pady=0)
    
        # Single file section
        self.upload_single_frame = ttk.Frame(file_frame, style="TFrame")
        self.upload_single_frame.grid(row=1, column=0, columnspan=3, sticky="ew", pady=5)
        self._create_label_entry_button(self.upload_single_frame, "Input Sigma Rule File:",
                                       self.upload_input_file_var, "Browse", self.select_upload_input_file, 0, 0)
    
        # Folder section
        self.upload_folder_frame = ttk.Frame(file_frame, style="TFrame")
        self.upload_folder_frame.grid(row=1, column=0, columnspan=3, sticky="ew", pady=5)
        self.upload_folder_frame.grid_remove()
        self._create_label_entry_button(self.upload_folder_frame, "Input Folder:",
                                       self.upload_folder_var, "Browse", self.select_upload_folder, 0, 0)
    
        # Field mapping file
        self._create_label_entry_button(file_frame, "Field Mapping File:",
                                       self.upload_mapping_file_var, "Browse", self.select_upload_mapping_file, 2, 0)
    
        # Upload button
        ttk.Button(upload_container, text="Upload to OpenSearch", command=self.start_upload_process).grid(
            row=3, column=0, columnspan=3, pady=20)
    
        # Progress and status
        self.upload_progress = ttk.Progressbar(upload_container, orient=tk.HORIZONTAL, length=100, mode='indeterminate')
        self.upload_progress.grid(row=4, column=0, columnspan=3, sticky="ew", pady=(0, 10))
        self.upload_progress.grid_remove()
    
        upload_status = ttk.Label(upload_container, textvariable=self.upload_status_var, relief=tk.SUNKEN, anchor=tk.W)
        upload_status.grid(row=5, column=0, columnspan=3, sticky="ew", pady=(0, 10))
    
        # Results text area
        results_frame = ttk.LabelFrame(upload_container, text="Upload Results", style="TFrame")
        results_frame.grid(row=6, column=0, columnspan=3, sticky="nsew", pady=(0, 10), padx=5)
    
        upload_container.columnconfigure(0, weight=1)
        upload_container.columnconfigure(1, weight=1)
        upload_container.columnconfigure(2, weight=1)
        upload_container.rowconfigure(6, weight=1)
    
        results_scrollbar = ttk.Scrollbar(results_frame)
        results_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.results_text = tk.Text(results_frame, height=10, width=80, wrap=tk.WORD,
                                    yscrollcommand=results_scrollbar.set)
        self.results_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        results_scrollbar.config(command=self.results_text.yview)

    def toggle_upload_mode(self):
        """Toggle between single file and folder upload modes."""
        if self.upload_mode_var.get() == "single":
            self.upload_folder_frame.grid_remove()
            self.upload_single_frame.grid()
        else:
            self.upload_single_frame.grid_remove()
            self.upload_folder_frame.grid()
        self.root.update_idletasks()

    def select_input_file(self):
        """Select a single Sigma rule file for conversion."""
        file_path = filedialog.askopenfilename(filetypes=[("YAML Files", "*.yml *.yaml")])
        if file_path:
            self.input_file_var.set(file_path)
            if self.single_output_option.get() == "folder" and not self.file_name_var.get():
                base_name = os.path.basename(file_path)
                name_without_ext = os.path.splitext(base_name)[0]
                self.file_name_var.set(name_without_ext)

    def select_mapping_file(self):
        """Select a field mapping file for conversion."""
        file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if file_path:
            self.mapping_file_var.set(file_path)

    def select_output_file(self):
        """Select an output file for conversion."""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".yml",
            filetypes=[("YAML Files", "*.yml *.yaml"), ("Text Files", "*.txt")]
        )
        if file_path:
            self.output_file_var.set(file_path)

    def select_output_folder(self):
        """Select an output folder for conversion."""
        folder_path = filedialog.askdirectory()
        if folder_path:
            self.output_folder_var.set(folder_path)

    def select_multiple_files(self):
        """Select multiple Sigma rule files for conversion."""
        file_paths = filedialog.askopenfilenames(filetypes=[("YAML Files", "*.yml *.yaml")])
        if file_paths:
            self.multiple_files_var.set(", ".join(file_paths))

    def select_upload_input_file(self):
        """Select a single Sigma rule file for upload."""
        file_path = filedialog.askopenfilename(filetypes=[("YAML Files", "*.yml *.yaml")])
        if file_path:
            self.upload_input_file_var.set(file_path)

    def select_upload_folder(self):
        """Select a folder containing Sigma rule files for upload."""
        folder_path = filedialog.askdirectory()
        if folder_path:
            self.upload_folder_var.set(folder_path)

    def select_upload_mapping_file(self):
        """Select a field mapping file for upload."""
        file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if file_path:
            self.upload_mapping_file_var.set(file_path)

    def toggle_output_options_single_file(self):
        """Toggle between file and folder output options for single file mode."""
        output_frame = self.output_file_label.master
        
        if self.single_output_option.get() == "file":
            self.output_file_label.grid(row=1, column=0, sticky="w", padx=PADX_DEFAULT, pady=PADY_DEFAULT)
            self.output_file_entry.grid(row=1, column=1, padx=PADX_DEFAULT, pady=PADY_DEFAULT, sticky="ew")
            self.output_file_button.grid(row=1, column=2, padx=PADX_DEFAULT, pady=PADY_DEFAULT)
    
            self.output_folder_label.grid_remove()
            self.output_folder_entry.grid_remove()
            self.output_folder_button.grid_remove()
            self.file_name_label.grid_remove()
            self.file_name_entry.grid_remove()
        elif self.single_output_option.get() == "folder":
            self.output_file_label.grid_remove()
            self.output_file_entry.grid_remove()
            self.output_file_button.grid_remove()
    
            self.output_folder_label.grid(row=1, column=0, sticky="w", padx=PADX_DEFAULT, pady=PADY_DEFAULT)
            self.output_folder_entry.grid(row=1, column=1, padx=PADX_DEFAULT, pady=PADY_DEFAULT, sticky="ew")
            self.output_folder_button.grid(row=1, column=2, padx=PADX_DEFAULT, pady=PADY_DEFAULT)
            self.output_folder_label.grid(row=1, column=0, sticky="w", padx=PADX_DEFAULT, pady=PADY_DEFAULT)
            self.output_folder_entry.grid(row=1, column=1, padx=PADX_DEFAULT, pady=PADY_DEFAULT, sticky="ew")
            self.output_folder_button.grid(row=1, column=2, padx=PADX_DEFAULT, pady=PADY_DEFAULT)
            self.file_name_label.grid(row=2, column=0, sticky="w", padx=PADX_DEFAULT, pady=PADY_DEFAULT)
            self.file_name_entry.grid(row=2, column=1, padx=PADX_DEFAULT, pady=PADY_DEFAULT, sticky="ew", columnspan=2)
    
        self.root.update_idletasks()

    def toggle_mode(self):
        """Toggle between single and multiple file modes."""
        if self.mode_var.get() == "single":
            self.multiple_file_frame.grid_remove()
            self.single_file_frame.grid()
            self.toggle_output_options_single_file()
        elif self.mode_var.get() == "multiple":
            self.single_file_frame.grid_remove()
            self.multiple_file_frame.grid()
        self.toggle_output_frame()
        self.root.update_idletasks()

    def start_upload_process(self):
        """Start the upload process in a separate thread."""
        if not all([self.username_var.get(), self.password_var.get(), self.node_ip_var.get(), self.port_var.get(),
                    self.upload_mapping_file_var.get()]):
            messagebox.showerror("Error", "Please fill in all connection settings and select a mapping file.")
            return

        if self.upload_mode_var.get() == "single" and not self.upload_input_file_var.get():
            messagebox.showerror("Error", "Please select an input file.")
            return
        if self.upload_mode_var.get() == "folder" and not self.upload_folder_var.get():
            messagebox.showerror("Error", "Please select an input folder.")
            return

        self.upload_status_var.set("Uploading...")
        self.upload_progress.grid()
        self.upload_progress.start()
        threading.Thread(target=self._upload_to_opensearch, daemon=True).start()

    def _upload_to_opensearch(self):
        """Handle the upload process to OpenSearch."""
        try:
            # Retrieve connection settings from GUI
            username = self.username_var.get()
            password = self.password_var.get()
            node_ip = self.node_ip_var.get()
            port = self.port_var.get()
            category = self.category_var.get()
            mapping_file = self.upload_mapping_file_var.get()

            # Validate inputs
            if not all([username, password, node_ip, port, mapping_file]):
                self.root.after(0, lambda: self.upload_status_var.set("Error: Missing connection settings or mapping file"))
                self.root.after(0, lambda: self.results_text.insert(tk.END, "Error: Please provide all connection settings and mapping file\n"))
                return

            # Construct URL
            url = f'https://{node_ip}:{port}/_plugins/_security_analytics/rules?category={category}'
            headers = {'Content-Type': 'application/json'}

            # Load field mappings
            field_mappings = self.load_field_mappings(mapping_file)

            # Initialize counters
            uploaded_count = 0
            failed_count = 0

            # Handle single file or folder upload
            if self.upload_mode_var.get() == "single":
                file_paths = [self.upload_input_file_var.get()]
            else:
                folder_path = self.upload_folder_var.get()
                file_paths = [
                    os.path.join(folder_path, f) for f in os.listdir(folder_path)
                    if f.endswith('.yaml') or f.endswith('.yml')
                ]

            if not file_paths or (self.upload_mode_var.get() == "single" and not file_paths[0]):
                self.root.after(0, lambda: self.upload_status_var.set("Error: No files selected"))
                self.root.after(0, lambda: self.results_text.insert(tk.END, "Error: Please select a file or folder\n"))
                return

            # Process each file
            for file_path in file_paths:
                try:
                    if not os.path.exists(file_path):
                        self.root.after(0, lambda: self.results_text.insert(tk.END, f"Error: File not found - {file_path}\n"))
                        failed_count += 1
                        continue

                    with open(file_path, 'r', encoding='utf-8') as yaml_file:
                        yaml_content = yaml.safe_load(yaml_file)

                    # Add UUID if not present
                    yaml_content['id'] = str(uuid.uuid4())

                    # Add date field if not present
                    yaml_content = self.add_date_field(yaml_content)

                    # Convert dates to ISO format
                    yaml_content = self.convert_dates(yaml_content)

                    # Map detection fields
                    if 'detection' in yaml_content:
                        yaml_content['detection'] = self.map_detection_fields(yaml_content['detection'], field_mappings)

                    # Convert rule field to JSON if it is a dictionary
                    if 'rule' in yaml_content and isinstance(yaml_content['rule'], dict):
                        yaml_content['rule'] = json.dumps(yaml_content['rule'])

                    # Convert to JSON payload
                    json_payload = json.dumps(yaml_content)

                    # Send request to OpenSearch
                    response = requests.post(
                        url,
                        headers=headers,
                        data=json_payload,
                        auth=(username, password),
                        verify=False
                    )

                    filename = os.path.basename(file_path)
                    if response.status_code in [200, 201]:
                        self.root.after(0, lambda: self.results_text.insert(tk.END, f"Uploaded successfully: {filename}\n"))
                        uploaded_count += 1
                    else:
                        error_msg = f"Upload failed: {filename} ➔ Error {response.status_code}: {response.text}\n"
                        self.root.after(0, lambda: self.results_text.insert(tk.END, error_msg))
                        failed_count += 1

                except Exception as e:
                    filename = os.path.basename(file_path)
                    error_msg = f"Upload failed: {filename} ➔ Exception: {str(e)}\n"
                    self.root.after(0, lambda: self.results_text.insert(tk.END, error_msg))
                    failed_count += 1

            # Update status
            status_msg = f"Upload completed: {uploaded_count} successful, {failed_count} failed"
            self.root.after(0, lambda: self.upload_status_var.set(status_msg))
            self.root.after(0, lambda: self.results_text.insert(tk.END, f"\nSummary: {status_msg}\n"))

        except Exception as e:
            self.root.after(0, lambda: self.upload_status_var.set(f"Upload failed: {str(e)}"))
            self.root.after(0, lambda: self.results_text.insert(tk.END, f"Error: {str(e)}\n"))
        finally:
            self.root.after(0, self.upload_progress.stop)
            self.root.after(0, self.upload_progress.grid_remove)
    
    def convert_dates(self, obj):
        """Recursively convert date objects to ISO format."""
        if isinstance(obj, dict):
            return {key: self.convert_dates(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [self.convert_dates(item) for item in obj]
        elif isinstance(obj, date):
            return obj.isoformat()
        else:
            return obj

    def add_date_field(self, yaml_content):
        """Add date field to YAML content if not present."""
        if 'date' not in yaml_content:
            yaml_content['date'] = date.today().isoformat()
        return yaml_content

    def load_field_mappings(self, file_path):
        """Load field mappings from a file."""
        field_mappings = {}
        with open(file_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and ":" in line:
                    key, value = line.split(":", 1)
                    field_mappings[key.strip()] = value.strip()
        return field_mappings

    def map_detection_fields(self, detection, field_mappings):
        """Map detection fields using the provided field mappings."""
        mapped_detection = {}
        for selection_name, selection_conditions in detection.items():
            if isinstance(selection_conditions, dict):
                mapped_conditions = {}
                for field_with_modifier, value in selection_conditions.items():
                    if "|" in field_with_modifier:
                        field_name, field_modifier = field_with_modifier.split("|", 1)
                    else:
                        field_name, field_modifier = field_with_modifier, ""
                    mapped_field_name = field_mappings.get(field_name, field_name)
                    mapped_field_with_modifier = f"{mapped_field_name}|{field_modifier}" if field_modifier else mapped_field_name
                    mapped_conditions[mapped_field_with_modifier] = value
                mapped_detection[selection_name] = mapped_conditions
            else:
                mapped_detection[selection_name] = selection_conditions
        return mapped_detection

    def update_sigma_rule(self, input_file, output_file, field_mapping_file):
        """Update Sigma rule for Winlogbeat format."""
        try:
            field_mappings = self.load_field_mappings(field_mapping_file)
            yaml_parser = YAML()
            yaml_parser.preserve_quotes = True
            yaml_parser.indent(mapping=4, sequence=4, offset=2)
            yaml_parser.block_seq_indent = 2

            with open(input_file, "r") as f:
                sigma_rule = yaml_parser.load(f)

            if "detection" in sigma_rule:
                sigma_rule["detection"] = self.map_detection_fields(sigma_rule["detection"], field_mappings)
            else:
                messagebox.showerror("Error", "No 'detection' section found in the Sigma rule.")
                return False

            with open(output_file, "w") as f:
                yaml_parser.dump(sigma_rule, f)

            return True
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")
            return False

    def generate_dql_query(self, sigma_rule, field_mappings):
        """Convert Sigma rule to OpenSearch DQL query."""
        try:
            if "detection" not in sigma_rule:
                raise ValueError("No 'detection' section found in the Sigma rule")

            if "selection" not in sigma_rule["detection"]:
                raise ValueError("No 'selection' section found in the detection part")

            selection = sigma_rule["detection"]["selection"]

            mapped_selection = {}
            for field, value in selection.items():
                if "|" in field:
                    field_name, modifier = field.split("|", 1)
                    mapped_field = field_mappings.get(field_name, field_name)
                    mapped_field_with_modifier = f"{mapped_field}|{modifier}"
                else:
                    mapped_field = field_mappings.get(field, field)
                    mapped_field_with_modifier = mapped_field

                mapped_selection[mapped_field_with_modifier] = value

            query_parts = []

            for field, value in mapped_selection.items():
                if "|" in field:
                    field_name, modifier = field.split("|", 1)

                    if modifier == "contains":
                        if isinstance(value, list):
                            conditions = [f"{field_name}:*{v}*" for v in value]
                            query_part = f"({' OR '.join(conditions)})"
                        else:
                            query_part = f"({field_name}:*{value}*)"
                    elif modifier == "endswith":
                        if isinstance(value, list):
                            conditions = [f"{field_name}:*{v}" for v in value]
                            query_part = f"({' OR '.join(conditions)})"
                        else:
                            query_part = f"({field_name}:*{value})"
                    elif modifier == "startswith":
                        if isinstance(value, list):
                            conditions = [f"{field_name}:{v}*" for v in value]
                            query_part = f"({' OR '.join(conditions)})"
                        else:
                            query_part = f"({field_name}:{value}*)"
                    else:
                        query_part = f"({field_name}:{value})"
                else:
                    if isinstance(value, list):
                        conditions = [f"{field}:{v}" for v in value]
                        query_part = f"({' OR '.join(conditions)})"
                    else:
                        query_part = f"({field}:{value})"

                query_parts.append(query_part)

            condition = sigma_rule["detection"].get("condition", "all of selection")

            if condition == "all of selection" or condition == "selection":
                final_query = " AND ".join(query_parts)
            elif condition == "any of selection":
                final_query = " OR ".join(query_parts)
            else:
                final_query = " AND ".join(query_parts)

            return final_query
        except Exception as e:
            raise ValueError(f"Error generating DQL query: {e}")

    def convert_sigma_to_dql(self, input_file, field_mapping_file):
        """Convert Sigma rule to OpenSearch DQL query and return the result."""
        try:
            field_mappings = self.load_field_mappings(field_mapping_file)

            with open(input_file, 'r') as f:
                sigma_rule = yaml.safe_load(f)

            rule_title = sigma_rule.get('title', 'Unnamed Rule')

            dql_query = self.generate_dql_query(sigma_rule, field_mappings)

            output_content = f"""# DQL Query for: {rule_title}
    # Original Sigma rule: {os.path.basename(input_file)}
    # Converted on: {self.root.tk.call('clock', 'format', 'clock seconds', '-format', '%Y-%m-%d %H:%M:%S')}

    {dql_query}
    """

            return output_content, True
        except Exception as e:
            return f"Error: {str(e)}", False

    def convert_single_file(self):
        """Handle single file conversion."""
        input_file = self.input_file_var.get()
        mapping_file = self.mapping_file_var.get()

        if not input_file or not mapping_file:
            messagebox.showerror("Error", "Please select input and mapping files.")
            return

        if self.conversion_type_var.get() == "winlogbeat":
            if self.single_output_option.get() == "file":
                output_file = self.output_file_var.get()
                if not output_file:
                    messagebox.showerror("Error", "Please select an output file.")
                    return
            else:
                output_folder = self.output_folder_var.get()
                file_name = self.file_name_var.get()
                if not output_folder or not file_name:
                    messagebox.showerror("Error", "Please select an output folder and enter a file name.")
                    return
                output_file = os.path.join(output_folder, f"{file_name}.yml")

        self.status_var.set("Converting...")
        self.dql_results_text.delete(1.0, tk.END)  # Clear previous results
        self.root.update_idletasks()

        success = False
        if self.conversion_type_var.get() == "winlogbeat":
            success = self.update_sigma_rule(input_file, output_file, mapping_file)
            if success:
                self.status_var.set("Conversion completed successfully.")
                messagebox.showinfo("Success", f"File has been converted and saved to:\n{output_file}")
            else:
                self.status_var.set("Conversion failed.")
        else:
            result, success = self.convert_sigma_to_dql(input_file, mapping_file)
            self.dql_results_text.insert(tk.END, result + "\n")
            if success:
                self.status_var.set("DQL query generated successfully.")
                messagebox.showinfo("Success", "DQL query has been generated and displayed below.")
            else:
                self.status_var.set("DQL conversion failed.")

    def convert_multiple_files(self):
        """Handle multiple file conversion."""
        mapping_file = self.mapping_file_var.get()
        output_folder = self.output_folder_var.get()
        multiple_files = self.multiple_files_var.get()

        if not mapping_file or (self.conversion_type_var.get() == "winlogbeat" and not output_folder) or not multiple_files:
            messagebox.showerror("Error", "Please select all required files.")
            return

        file_list = multiple_files.split(", ")
        converted_count = 0
        failed_count = 0

        self.status_var.set(f"Converting {len(file_list)} files...")
        self.dql_results_text.delete(1.0, tk.END)  # Clear previous results
        self.root.update_idletasks()

        for file_path in file_list:
            file_name = os.path.basename(file_path)
            name_without_ext = os.path.splitext(file_name)[0]

            success = False
            if self.conversion_type_var.get() == "winlogbeat":
                output_file = os.path.join(output_folder, f"{name_without_ext}.yml")
                success = self.update_sigma_rule(file_path, output_file, mapping_file)
            else:
                result, success = self.convert_sigma_to_dql(file_path, mapping_file)
                self.dql_results_text.insert(tk.END, result + "\n\n")

            if success:
                converted_count += 1
            else:
                failed_count += 1

        if failed_count == 0:
            self.status_var.set(f"All {converted_count} files converted successfully.")
            messagebox.showinfo("Success", f"All {converted_count} files have been converted.")
        else:
            self.status_var.set(f"Conversion completed: {converted_count} successful, {failed_count} failed.")
            messagebox.showwarning("Partial Success",
                                   f"{converted_count} files converted successfully.\n{failed_count} files failed.")

    def setup_converter_tab(self):
        """Setup the converter tab."""
        converter_container = ttk.Frame(self.converter_frame, style="TFrame")
        converter_container.pack(fill="both", expand=True, padx=10, pady=10)

        # Title
        ttk.Label(converter_container, text="Sigma Rule Converter", font=FONT_TITLE, style="TLabel").grid(
            row=0, column=0, columnspan=3, pady=(0, 20), sticky="w")

        # Mode selection frame
        mode_frame = ttk.LabelFrame(converter_container, text="Mode Selection", style="TFrame")
        mode_frame.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(0, 15), padx=5)

        ttk.Radiobutton(mode_frame, text="Single File", variable=self.mode_var,
                        value="single", command=self.toggle_mode, style="TRadiobutton").grid(row=0, column=0, padx=20, pady=10)
        ttk.Radiobutton(mode_frame, text="Multiple Files", variable=self.mode_var,
                        value="multiple", command=self.toggle_mode, style="TRadiobutton").grid(row=0, column=1, padx=20, pady=10)

        # Conversion type frame
        conversion_frame = ttk.LabelFrame(converter_container, text="Conversion Type", style="TFrame")
        conversion_frame.grid(row=2, column=0, columnspan=3, sticky="ew", pady=(0, 15), padx=5)

        ttk.Radiobutton(conversion_frame, text="Opensearch Rule", variable=self.conversion_type_var,
                        value="winlogbeat", command=self.toggle_output_frame, style="TRadiobutton").grid(row=0, column=0, padx=20, pady=10)
        ttk.Radiobutton(conversion_frame, text="OpenSearch DQL", variable=self.conversion_type_var,
                        value="dql", command=self.toggle_output_frame, style="TRadiobutton").grid(row=0, column=1, padx=20, pady=10)

        # Create frames for single and multiple file modes
        self.single_file_frame = ttk.Frame(converter_container, style="TFrame")
        self.single_file_frame.grid(row=3, column=0, columnspan=3, sticky="nsew", padx=5)

        self.multiple_file_frame = ttk.Frame(converter_container, style="TFrame")
        self.multiple_file_frame.grid(row=3, column=0, columnspan=3, sticky="nsew", padx=5)
        self.multiple_file_frame.grid_remove()

        # Setup frames
        self.setup_single_file_frame()
        self.setup_multiple_file_frame()

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(converter_container, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.grid(row=5, column=0, columnspan=3, sticky="ew", pady=(15, 0))

        # Results text area for DQL output
        results_frame = ttk.LabelFrame(converter_container, text="Conversion Results", style="TFrame")
        results_frame.grid(row=6, column=0, columnspan=3, sticky="nsew", pady=(10, 0), padx=5)

        converter_container.columnconfigure(0, weight=1)
        converter_container.columnconfigure(1, weight=1)
        converter_container.columnconfigure(2, weight=1)
        converter_container.rowconfigure(3, weight=1)
        converter_container.rowconfigure(6, weight=0)  # Reduced weight to prevent excessive expansion

        results_scrollbar = ttk.Scrollbar(results_frame)
        results_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.dql_results_text = tk.Text(results_frame, height=5, width=80, wrap=tk.WORD,
                                        yscrollcommand=results_scrollbar.set)  # Reduced height from 10 to 5
        self.dql_results_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        results_scrollbar.config(command=self.dql_results_text.yview)

    def setup_single_file_frame(self):
        """Setup the single file conversion frame."""
        # Create a LabelFrame for file selection
        file_frame = ttk.LabelFrame(self.single_file_frame, text="File Selection", style="TFrame")
        file_frame.grid(row=0, column=0, columnspan=3, sticky="ew", pady=(0, 15), padx=5)

        # Input file
        self._create_label_entry_button(file_frame, "Input Sigma Rule File:",
                                       self.input_file_var, "Browse", self.select_input_file, 0, 0)

        # Field mapping file
        self._create_label_entry_button(file_frame, "Field Mapping File:",
                                       self.mapping_file_var, "Browse", self.select_mapping_file, 1, 0)

        # Output option frame
        output_frame = ttk.LabelFrame(self.single_file_frame, text="Output Options", style="TFrame")
        output_frame.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(0, 15), padx=5)

        # Output mode radiobuttons
        ttk.Radiobutton(output_frame, text="Save to File", variable=self.single_output_option,
                        value="file", command=self.toggle_output_options_single_file,
                        style="TRadiobutton").grid(row=0, column=0, padx=20, pady=8)
        ttk.Radiobutton(output_frame, text="Save to Folder", variable=self.single_output_option,
                        value="folder", command=self.toggle_output_options_single_file,
                        style="TRadiobutton").grid(row=0, column=1, padx=20, pady=8)

        # Output file (initially visible)
        self.output_file_label = ttk.Label(output_frame, text="Output File:", style="TLabel")
        self.output_file_label.grid(row=1, column=0, sticky="w", padx=PADX_DEFAULT, pady=PADY_DEFAULT)
        self.output_file_entry = ttk.Entry(output_frame, textvariable=self.output_file_var, width=50)
        self.output_file_entry.grid(row=1, column=1, padx=PADX_DEFAULT, pady=PADY_DEFAULT, sticky="ew")
        self.output_file_button = ttk.Button(output_frame, text="Browse", command=self.select_output_file)
        self.output_file_button.grid(row=1, column=2, padx=PADX_DEFAULT, pady=PADY_DEFAULT)

        # Output folder (initially hidden)
        self.output_folder_label = ttk.Label(output_frame, text="Output Folder:", style="TLabel")
        self.output_folder_entry = ttk.Entry(output_frame, textvariable=self.output_folder_var, width=50)
        self.output_folder_button = ttk.Button(output_frame, text="Browse", command=self.select_output_folder)

        # File name (initially hidden)
        self.file_name_label = ttk.Label(output_frame, text="File Name (without extension):", style="TLabel")
        self.file_name_entry = ttk.Entry(output_frame, textvariable=self.file_name_var, width=50)

        # Convert button
        convert_button = ttk.Button(self.single_file_frame, text="Convert", command=self.convert_single_file)
        convert_button.grid(row=2, column=0, columnspan=3, pady=10)

        # Configure grid weights
        self.single_file_frame.columnconfigure(1, weight=1)
        output_frame.columnconfigure(1, weight=1)

    def setup_multiple_file_frame(self):
        """Setup the multiple file conversion frame."""
        # Create a LabelFrame for file selection
        file_frame = ttk.LabelFrame(self.multiple_file_frame, text="File Selection", style="TFrame")
        file_frame.grid(row=0, column=0, columnspan=3, sticky="ew", pady=(0, 15), padx=5)

        # Multiple input files
        self._create_label_entry_button(file_frame, "Input Sigma Rule Files:",
                                       self.multiple_files_var, "Browse", self.select_multiple_files, 0, 0)

        # Field mapping file
        self._create_label_entry_button(file_frame, "Field Mapping File:",
                                       self.mapping_file_var, "Browse", self.select_mapping_file, 1, 0)

        # Output option frame
        output_frame = ttk.LabelFrame(self.multiple_file_frame, text="Output Options", style="TFrame")
        output_frame.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(0, 15), padx=5)

        # Output folder
        self._create_label_entry_button(output_frame, "Output Folder:",
                                       self.output_folder_var, "Browse", self.select_output_folder, 0, 0)

        # Convert button
        convert_button_multi = ttk.Button(self.multiple_file_frame, text="Convert", command=self.convert_multiple_files)
        convert_button_multi.grid(row=2, column=0, columnspan=3, pady=10)

        # Configure grid weights
        self.multiple_file_frame.columnconfigure(1, weight=1)
        file_frame.columnconfigure(1, weight=1)
        output_frame.columnconfigure(1, weight=1)
    
    def toggle_output_frame(self):
        """Show or hide the Output Options frame based on conversion type."""
        if self.conversion_type_var.get() == "winlogbeat":
            # Show Output Options for Winlogbeat
            if self.mode_var.get() == "single":
                self.single_file_frame.children['!labelframe2'].grid(row=1, column=0, columnspan=3, sticky="ew", pady=(0, 15), padx=5)
                self.toggle_output_options_single_file()
            else:
                self.multiple_file_frame.children['!labelframe2'].grid(row=1, column=0, columnspan=3, sticky="ew", pady=(0, 15), padx=5)
        else:
            # Hide Output Options for OpenSearch DQL
            if self.mode_var.get() == "single":
                self.single_file_frame.children['!labelframe2'].grid_remove()
            else:
                self.multiple_file_frame.children['!labelframe2'].grid_remove()
        self.root.update_idletasks()

if __name__ == "__main__":
    root = tk.Tk()
    app = SigmaConverter(root)
    root.mainloop()