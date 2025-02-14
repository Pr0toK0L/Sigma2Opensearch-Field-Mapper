import tkinter as tk
from tkinter import filedialog, messagebox
import os
from ruamel.yaml import YAML
import json

# Tạo các hàm xử lý
def load_field_mappings(file_path: str) -> dict:
    with open(file_path, "r") as f:
        return json.load(f)

def map_detection_fields(detection: dict, field_mappings: dict) -> dict:
    mapped_detection = {}
    for selection_name, selection_conditions in detection.items():
        if isinstance(selection_conditions, dict):  # Nếu selection chứa các field
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

def update_sigma_rule(input_file: str, output_file: str, field_mapping_file: str):
    try:
        field_mappings = load_field_mappings(field_mapping_file)
        yaml = YAML()
        yaml.preserve_quotes = True
        yaml.indent(mapping=4, sequence=4, offset=2)
        yaml.block_seq_indent = 2
        with open(input_file, "r") as f:
            sigma_rule = yaml.load(f)
        if "detection" in sigma_rule:
            sigma_rule["detection"] = map_detection_fields(sigma_rule["detection"], field_mappings)
        else:
            messagebox.showerror("Error", "No 'detection' section found in the Sigma rule.")
            return
        with open(output_file, "w") as f:
            yaml.dump(sigma_rule, f)
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

def select_input_file():
    file_path = filedialog.askopenfilename(filetypes=[("YAML Files", "*.yml *.yaml")])
    if file_path:
        input_file_var.set(file_path)

def select_mapping_file():
    file_path = filedialog.askopenfilename(filetypes=[("JSON Files", "*.json")])
    if file_path:
        mapping_file_var.set(file_path)

def select_output_file():
    file_path = filedialog.asksaveasfilename(defaultextension=".yml", filetypes=[("YAML Files", "*.yml *.yaml")])
    if file_path:
        output_file_var.set(file_path)

def select_output_folder():
    folder_path = filedialog.askdirectory()
    if folder_path:
        output_folder_var.set(folder_path)

def select_multiple_files():
    file_paths = filedialog.askopenfilenames(filetypes=[("YAML Files", "*.yml *.yaml")])
    if file_paths:
        multiple_files_var.set(", ".join(file_paths))  # Hiển thị danh sách file đã chọn

def toggle_output_options_single_file():
    """Ẩn hoặc hiển thị các trường phù hợp với lựa chọn output trong chế độ Single File."""
    if single_file_output_option.get() == "file":
        # Hiển thị Output File
        output_file_label.grid(row=5, column=0, padx=10, pady=5, sticky="w")
        output_file_entry.grid(row=5, column=1, padx=10, pady=5)
        output_file_button.grid(row=5, column=2, padx=10, pady=5)

        # Ẩn Output Folder và File Name
        output_folder_label.grid_remove()
        output_folder_entry.grid_remove()
        output_folder_button.grid_remove()
        file_name_label.grid_remove()
        file_name_entry.grid_remove()
    elif single_file_output_option.get() == "folder":
        # Hiển thị Output Folder và File Name
        output_folder_label.grid(row=5, column=0, padx=10, pady=5, sticky="w")
        output_folder_entry.grid(row=5, column=1, padx=10, pady=5)
        output_folder_button.grid(row=5, column=2, padx=10, pady=5)
        file_name_label.grid(row=6, column=0, padx=10, pady=5, sticky="w")
        file_name_entry.grid(row=6, column=1, padx=10, pady=5)

        # Ẩn Output File
        output_file_label.grid_remove()
        output_file_entry.grid_remove()
        output_file_button.grid_remove()

def toggle_mode(mode):
    """Chuyển đổi giữa chế độ Single File và Multiple Files."""
    if mode == "single":
        multiple_file_frame.grid_remove()  # Ẩn khung chế độ Multiple Files
        single_file_frame.grid()  # Hiển thị khung chế độ Single File
        toggle_output_options_single_file()  # Đảm bảo hiển thị đúng tùy chọn output cho Single File
    elif mode == "multiple":
        single_file_frame.grid_remove()  # Ẩn khung chế độ Single File
        multiple_file_frame.grid()  # Hiển thị khung chế độ Multiple Files

def convert_single_file():
    input_file = input_file_var.get()
    mapping_file = mapping_file_var.get()
    output_file = output_file_var.get()
    output_folder = output_folder_var.get()
    file_name = file_name_var.get()

    if not input_file or not mapping_file:
        messagebox.showerror("Error", "Please select all required files.")
        return

    if single_file_output_option.get() == "file":
        if not output_file:
            messagebox.showerror("Error", "Please select an output file.")
            return
        update_sigma_rule(input_file, output_file, mapping_file)
    elif single_file_output_option.get() == "folder":
        if not output_folder or not file_name:
            messagebox.showerror("Error", "Please select an output folder and enter a file name.")
            return
        output_file = os.path.join(output_folder, f"{file_name}.yml")
        update_sigma_rule(input_file, output_file, mapping_file)

    messagebox.showinfo("Success", f"File has been converted.")

def convert_multiple_files():
    mapping_file = mapping_file_var.get()
    output_folder = output_folder_var.get()
    multiple_files = multiple_files_var.get()

    if not mapping_file or not output_folder or not multiple_files:
        messagebox.showerror("Error", "Please select all required files.")
        return

    file_list = multiple_files.split(", ")
    for file_path in file_list:
        file_name = os.path.basename(file_path)  # Giữ nguyên tên file
        output_file = os.path.join(output_folder, file_name)
        update_sigma_rule(file_path, output_file, mapping_file)

    messagebox.showinfo("Success", "All files have been converted.")

# Tạo cửa sổ chính
root = tk.Tk()
root.title("Sigma -> Opensearch Field Mapper")

# Cài đặt kích thước và không cho thay đổi
root.geometry("600x300")
root.resizable(False, False)

# Phông chữ và màu sắc
FONT = ("Arial", 10)
LABEL_COLOR = "#333333"
BUTTON_COLOR = "#4CAF50"
BUTTON_TEXT_COLOR = "white"
BACKGROUND_COLOR = "#F9F9F9"

# Đặt màu nền cho cửa sổ
root.configure(bg=BACKGROUND_COLOR)

# Khung chính
main_frame = tk.Frame(root, bg=BACKGROUND_COLOR, padx=20, pady=10)
main_frame.pack(expand=True, fill="both")

# Các biến lưu trạng thái
input_file_var = tk.StringVar()
output_file_var = tk.StringVar()
mapping_file_var = tk.StringVar()
multiple_files_var = tk.StringVar()
output_folder_var = tk.StringVar()
file_name_var = tk.StringVar()
single_file_output_option = tk.StringVar(value="file")

# Hàm thay đổi kích thước cửa sổ
def update_window_size():
    if mode == "single":
        if single_file_output_option.get() == "file":
            root.geometry("610x300")
        elif single_file_output_option.get() == "folder":
            root.geometry("610x330")
    elif mode == "multiple":
        root.geometry("610x230")

# Hàm chuyển đổi chế độ
def toggle_mode(new_mode):
    global mode
    mode = new_mode
    if mode == "single":
        multiple_file_frame.grid_remove()
        single_file_frame.grid()
        update_window_size()
    elif mode == "multiple":
        single_file_frame.grid_remove()
        multiple_file_frame.grid()
        update_window_size()

# Hàm thay đổi tùy chọn Output Option
def toggle_output_options_single_file():
    if single_file_output_option.get() == "file":
        output_file_label.grid(row=4, column=0, sticky="w", pady=5)
        output_file_entry.grid(row=4, column=1, padx=10, pady=5)
        output_file_button.grid(row=4, column=2, padx=10, pady=5)

        output_folder_label.grid_remove()
        output_folder_entry.grid_remove()
        output_folder_button.grid_remove()
        file_name_label.grid_remove()
        file_name_entry.grid_remove()
    elif single_file_output_option.get() == "folder":
        output_folder_label.grid(row=4, column=0, sticky="w", pady=5)
        output_folder_entry.grid(row=4, column=1, padx=10, pady=5)
        output_folder_button.grid(row=4, column=2, padx=10, pady=5)
        file_name_label.grid(row=5, column=0, sticky="w", pady=5)
        file_name_entry.grid(row=5, column=1, padx=10, pady=5)

        output_file_label.grid_remove()
        output_file_entry.grid_remove()
        output_file_button.grid_remove()

    update_window_size()

# Khung chính cho chế độ Single File
single_file_frame = tk.Frame(main_frame, bg=BACKGROUND_COLOR, padx=10, pady=10, relief="groove", bd=2)
tk.Label(single_file_frame, text="Input File (.yml):", font=FONT, bg=BACKGROUND_COLOR, fg=LABEL_COLOR).grid(row=0, column=0, sticky="w", pady=5)
tk.Entry(single_file_frame, textvariable=input_file_var, width=50).grid(row=0, column=1, padx=10, pady=5)
tk.Button(single_file_frame, text="Browse", command=select_input_file).grid(row=0, column=2, padx=10, pady=5)

tk.Label(single_file_frame, text="Field Mapping File (.json):", font=FONT, bg=BACKGROUND_COLOR, fg=LABEL_COLOR).grid(row=1, column=0, sticky="w", pady=5)
tk.Entry(single_file_frame, textvariable=mapping_file_var, width=50).grid(row=1, column=1, padx=10, pady=5)
tk.Button(single_file_frame, text="Browse", command=select_mapping_file).grid(row=1, column=2, padx=10, pady=5)

tk.Label(single_file_frame, text="Output Option:", font=FONT, bg=BACKGROUND_COLOR, fg=LABEL_COLOR).grid(row=2, column=0, sticky="w", pady=5)
tk.Radiobutton(single_file_frame, text="Select File", variable=single_file_output_option, value="file", command=toggle_output_options_single_file, bg=BACKGROUND_COLOR).grid(row=2, column=1, sticky="w", pady=5)
tk.Radiobutton(single_file_frame, text="Select Folder", variable=single_file_output_option, value="folder", command=toggle_output_options_single_file, bg=BACKGROUND_COLOR).grid(row=3, column=1, sticky="w", pady=5)

output_file_label = tk.Label(single_file_frame, text="Output File (.yml):", font=FONT, bg=BACKGROUND_COLOR, fg=LABEL_COLOR)
output_file_entry = tk.Entry(single_file_frame, textvariable=output_file_var, width=50)
output_file_button = tk.Button(single_file_frame, text="Browse", command=select_output_file)

output_folder_label = tk.Label(single_file_frame, text="Output Folder:", font=FONT, bg=BACKGROUND_COLOR, fg=LABEL_COLOR)
output_folder_entry = tk.Entry(single_file_frame, textvariable=output_folder_var, width=50)
output_folder_button = tk.Button(single_file_frame, text="Browse", command=select_output_folder)

file_name_label = tk.Label(single_file_frame, text="Output File (.yml):", font=FONT, bg=BACKGROUND_COLOR, fg=LABEL_COLOR)
file_name_entry = tk.Entry(single_file_frame, textvariable=file_name_var, width=50)

convert_button = tk.Button(
    single_file_frame, text="Convert", command=convert_single_file, 
    bg=BUTTON_COLOR, fg=BUTTON_TEXT_COLOR, font=("Arial", 11, "bold"), 
    width=15, cursor="hand2"  # Biểu tượng ngón trỏ
)
convert_button.grid(row=6, column=0, columnspan=3, pady=20)

# Khung chính cho chế độ Multiple Files
multiple_file_frame = tk.Frame(main_frame, bg=BACKGROUND_COLOR, padx=10, pady=10, relief="groove", bd=2)
tk.Label(multiple_file_frame, text="Input Files:", font=FONT, bg=BACKGROUND_COLOR, fg=LABEL_COLOR).grid(row=0, column=0, sticky="w", pady=5)
tk.Entry(multiple_file_frame, textvariable=multiple_files_var, width=50, state="readonly").grid(row=0, column=1, padx=10, pady=5)
tk.Button(multiple_file_frame, text="Browse", command=select_multiple_files).grid(row=0, column=2, padx=10, pady=5)

tk.Label(multiple_file_frame, text="Field Mapping File (.json):", font=FONT, bg=BACKGROUND_COLOR, fg=LABEL_COLOR).grid(row=1, column=0, sticky="w", pady=5)
tk.Entry(multiple_file_frame, textvariable=mapping_file_var, width=50).grid(row=1, column=1, padx=10, pady=5)
tk.Button(multiple_file_frame, text="Browse", command=select_mapping_file).grid(row=1, column=2, padx=10, pady=5)

tk.Label(multiple_file_frame, text="Output Folder:", font=FONT, bg=BACKGROUND_COLOR, fg=LABEL_COLOR).grid(row=2, column=0, sticky="w", pady=5)
tk.Entry(multiple_file_frame, textvariable=output_folder_var, width=50).grid(row=2, column=1, padx=10, pady=5)
tk.Button(multiple_file_frame, text="Browse", command=select_output_folder).grid(row=2, column=2, padx=10, pady=5)

convert_button = tk.Button(
    multiple_file_frame, text="Convert", command=convert_multiple_files, 
    bg=BUTTON_COLOR, fg=BUTTON_TEXT_COLOR, font=("Arial", 11, "bold"), 
    width=15, cursor="hand2"  # Biểu tượng ngón trỏ
)
convert_button.grid(row=3, column=0, columnspan=3, pady=20)

# Menu bar
menu_bar = tk.Menu(root)
file_menu = tk.Menu(menu_bar, tearoff=0)
file_menu.add_command(label="Single File Mode", command=lambda: toggle_mode("single"))
file_menu.add_command(label="Multiple Files Mode", command=lambda: toggle_mode("multiple"))
menu_bar.add_cascade(label="Mode", menu=file_menu)
root.config(menu=menu_bar)

# Đặt chế độ mặc định
mode = "single"
single_file_output_option.set("file")
single_file_frame.grid(row=0, column=0, sticky="nsew")
multiple_file_frame.grid(row=0, column=0, sticky="nsew")
toggle_mode("single")
toggle_output_options_single_file()

# Khởi chạy GUI
root.mainloop()