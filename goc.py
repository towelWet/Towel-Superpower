#!/usr/bin/env python3
import tkinter as tk
from tkinter import filedialog, messagebox
import pefile
import os

class GhidraOffsetCalculatorApp:
    def __init__(self, master):
        self.master = master
        master.title("Ghidra Offset Calculator")
        master.resizable(False, False)

        # Initialize variables
        self.pe = None
        self.sections = []

        # --- Title ---
        title_label = tk.Label(master, text="Ghidra Offset Calculator", font=("Helvetica", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=3, pady=10)

        # --- File Loading ---
        load_button = tk.Button(master, text="Load PE File", command=self.load_file)
        load_button.grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.file_label = tk.Label(master, text="No file loaded")
        self.file_label.grid(row=1, column=1, columnspan=2, padx=10, pady=5, sticky="w")

        # --- Image Base (editable now) ---
        tk.Label(master, text="Image Base:").grid(row=2, column=0, padx=10, pady=5, sticky="e")
        self.image_base_var = tk.StringVar()
        # Allow editing so that you can override the default if Ghidra rebases the module
        self.image_base_entry = tk.Entry(master, textvariable=self.image_base_var, width=20)
        self.image_base_entry.grid(row=2, column=1, padx=10, pady=5, sticky="w")

        # --- Section Selection ---
        tk.Label(master, text="Select Section:").grid(row=3, column=0, padx=10, pady=5, sticky="e")
        self.section_var = tk.StringVar()
        self.section_menu = tk.OptionMenu(master, self.section_var, "")
        self.section_menu.config(width=20)
        self.section_menu.grid(row=3, column=1, padx=10, pady=5, sticky="w")
        # When selection changes, update section info
        self.section_var.trace("w", self.update_section_info)

        tk.Label(master, text="Section Raw Offset:").grid(row=4, column=0, padx=10, pady=5, sticky="e")
        self.section_raw_var = tk.StringVar()
        self.section_raw_entry = tk.Entry(master, textvariable=self.section_raw_var, state="readonly", width=20)
        self.section_raw_entry.grid(row=4, column=1, padx=10, pady=5, sticky="w")

        tk.Label(master, text="Section RVA:").grid(row=5, column=0, padx=10, pady=5, sticky="e")
        self.section_rva_var = tk.StringVar()
        self.section_rva_entry = tk.Entry(master, textvariable=self.section_rva_var, state="readonly", width=20)
        self.section_rva_entry.grid(row=5, column=1, padx=10, pady=5, sticky="w")

        # --- Bad Boy Offset (File Offset) ---
        tk.Label(master, text="Bad Boy Offset (File Offset):").grid(row=6, column=0, padx=10, pady=5, sticky="e")
        self.badboy_offset_entry = tk.Entry(master, width=20)
        self.badboy_offset_entry.grid(row=6, column=1, padx=10, pady=5, sticky="w")
        # Default value (example)
        self.badboy_offset_entry.insert(0, "0x5538a0")

        # --- Calculate Button ---
        calc_button = tk.Button(master, text="Calculate Virtual Address", command=self.calculate_va)
        calc_button.grid(row=7, column=0, columnspan=2, pady=10)

        # --- Result Display ---
        tk.Label(master, text="Calculated Virtual Address:").grid(row=8, column=0, padx=10, pady=5, sticky="e")
        self.result_var = tk.StringVar()
        self.result_entry = tk.Entry(master, textvariable=self.result_var, state="readonly", width=20)
        self.result_entry.grid(row=8, column=1, padx=10, pady=5, sticky="w")

        # --- Clear and Quit Buttons ---
        clear_button = tk.Button(master, text="Clear", command=self.clear_all)
        clear_button.grid(row=9, column=0, padx=10, pady=10)
        quit_button = tk.Button(master, text="Quit", command=master.quit)
        quit_button.grid(row=9, column=1, padx=10, pady=10)

        # --- Note Section ---
        note = ("Note: If the calculated address doesn’t match what you see in Ghidra, "
                "verify that:\n"
                "  1. You’re using the correct section (check its raw offset and RVA).\n"
                "  2. The Image Base value matches the one in Ghidra’s Memory Map.\n"
                "     (Ghidra may rebase the module.)")
        note_label = tk.Label(master, text=note, justify="left", fg="gray", font=("Helvetica", 8))
        note_label.grid(row=10, column=0, columnspan=3, padx=10, pady=(5,10))

    def load_file(self):
        file_path = filedialog.askopenfilename(
            title="Select a PE file", 
            filetypes=[("Executable Files", "*.exe;*.dll"), ("All Files", "*.*")]
        )
        if not file_path:
            return

        try:
            self.pe = pefile.PE(file_path)
            self.file_label.config(text=os.path.basename(file_path))
            # Get the image base from the PE header
            image_base = self.pe.OPTIONAL_HEADER.ImageBase
            self.image_base_var.set(hex(image_base))
            # Read section info and store it
            self.sections = []
            for section in self.pe.sections:
                # Decode section name and remove null bytes
                name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                self.sections.append({
                    "name": name,
                    "PointerToRawData": section.PointerToRawData,
                    "VirtualAddress": section.VirtualAddress
                })
            # Update the section OptionMenu
            menu = self.section_menu["menu"]
            menu.delete(0, "end")
            for idx, sec in enumerate(self.sections):
                option_text = f"{idx}: {sec['name']}"
                menu.add_command(
                    label=option_text, 
                    command=lambda value=option_text: self.section_var.set(value)
                )
            if self.sections:
                # Set the default selection to the first section
                self.section_var.set(f"0: {self.sections[0]['name']}")
                self.update_section_info()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load file: {e}")

    def update_section_info(self, *args):
        value = self.section_var.get()
        if not value:
            return
        try:
            idx = int(value.split(":")[0])
            section = self.sections[idx]
            self.section_raw_var.set(hex(section["PointerToRawData"]))
            self.section_rva_var.set(hex(section["VirtualAddress"]))
        except Exception as e:
            messagebox.showerror("Error", f"Error updating section info: {e}")

    def calculate_va(self):
        if self.pe is None:
            messagebox.showerror("Error", "No PE file loaded.")
            return
        try:
            # Convert the fields from hex strings to integers.
            image_base = int(self.image_base_var.get(), 16)
            section_raw = int(self.section_raw_var.get(), 16)
            section_rva = int(self.section_rva_var.get(), 16)
            badboy_offset = int(self.badboy_offset_entry.get().strip(), 16)
            # Compute the offset within the section:
            # offset_in_section = (Bad Boy File Offset) - (Section PointerToRawData)
            offset_in_section = badboy_offset - section_raw
            # Virtual Address = ImageBase + Section RVA + offset_in_section
            virtual_address = image_base + section_rva + offset_in_section
            self.result_var.set(hex(virtual_address))
        except Exception as e:
            messagebox.showerror("Error", f"Calculation failed: {e}")

    def clear_all(self):
        self.pe = None
        self.sections = []
        self.file_label.config(text="No file loaded")
        self.image_base_var.set("")
        self.section_var.set("")
        self.section_raw_var.set("")
        self.section_rva_var.set("")
        self.badboy_offset_entry.delete(0, tk.END)
        self.badboy_offset_entry.insert(0, "0x5538a0")
        self.result_var.set("")

if __name__ == "__main__":
    root = tk.Tk()
    app = GhidraOffsetCalculatorApp(root)
    root.mainloop()
