import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import re
import os
import pefile  # For file-based base detection (PE files)

class AddressConverterGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Ghidra/IDA Pro Address Converter")
        self.root.geometry("650x400")
        
        main_frame = ttk.Frame(root, padding="10")
        main_frame.pack(expand=True, fill="both")
        
        # Conversion Format Dropdowns
        ttk.Label(main_frame, text="From Format:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.from_format = ttk.Combobox(main_frame, values=["Ghidra", "IDA Pro", "x64dbg"],
                                        state="readonly", width=15)
        self.from_format.grid(row=0, column=1, sticky="w", padx=5, pady=5)
        self.from_format.set("Ghidra")
        
        ttk.Label(main_frame, text="To Format:").grid(row=0, column=2, sticky="w", padx=5, pady=5)
        self.to_format = ttk.Combobox(main_frame, values=["Ghidra", "IDA Pro", "x64dbg"],
                                      state="readonly", width=15)
        self.to_format.grid(row=0, column=3, sticky="w", padx=5, pady=5)
        self.to_format.set("IDA Pro")
        
        # Input Address / Function Name Field
        ttk.Label(main_frame, text="Input Address/Function:").grid(row=1, column=0, columnspan=2, sticky="w", padx=5, pady=5)
        self.input_entry = ttk.Entry(main_frame, width=40)
        self.input_entry.grid(row=1, column=2, columnspan=2, sticky="w", padx=5, pady=5)
        ttk.Label(main_frame, text="(e.g. FUN_18023bb10, LAB_180363e70, or pure hex)").grid(row=2, column=0, columnspan=4, sticky="w", padx=5)
        
        # Base Addresses (only used for memory conversion)
        base_frame = ttk.LabelFrame(main_frame, text="Base Addresses (for memory conversion)", padding="5")
        base_frame.grid(row=3, column=0, columnspan=4, sticky="ew", padx=5, pady=5)
        ttk.Label(base_frame, text="Ghidra Image Base:").grid(row=0, column=0, padx=5, pady=2)
        self.ghidra_base_entry = ttk.Entry(base_frame, width=20)
        self.ghidra_base_entry.grid(row=0, column=1, padx=5, pady=2)
        # Default value; adjust as needed
        self.ghidra_base_entry.insert(0, "0x180360000")
        
        ttk.Label(base_frame, text="Actual Module Base:").grid(row=0, column=2, padx=5, pady=2)
        self.module_base_entry = ttk.Entry(base_frame, width=20)
        self.module_base_entry.grid(row=0, column=3, padx=5, pady=2)
        # Default value; adjust as needed
        self.module_base_entry.insert(0, "0x7FF8A9D60000")
        
        # Convert Button
        convert_btn = ttk.Button(main_frame, text="Convert", command=self.convert)
        convert_btn.grid(row=4, column=0, columnspan=4, pady=10)
        
        # Output Field
        ttk.Label(main_frame, text="Output:").grid(row=5, column=0, sticky="nw", padx=5, pady=5)
        self.output_text = tk.Text(main_frame, height=4, width=60)
        self.output_text.grid(row=5, column=1, columnspan=3, sticky="w", padx=5, pady=5)
    
    def parse_input(self, input_str: str, from_fmt: str):
        """
        Returns a tuple (mode, addr) where mode is one of:
         - "fun" for function names (Ghidra: FUN_, IDA: sub_)
         - "lab" for labels (Ghidra: LAB_, IDA: loc_)
         - "memory" for pure addresses.
        """
        s = input_str.strip()
        # For Ghidra input, check for function/label prefixes (case-insensitive)
        if from_fmt.lower() == "ghidra":
            if s.upper().startswith("FUN_"):
                try:
                    addr = int(s[4:], 16)
                    return ("fun", addr)
                except:
                    raise ValueError("Invalid Ghidra function name format.")
            elif s.upper().startswith("LAB_"):
                try:
                    addr = int(s[4:], 16)
                    return ("lab", addr)
                except:
                    raise ValueError("Invalid Ghidra label format.")
        # For IDA Pro input, check for function/label prefixes
        if from_fmt.lower() == "ida pro":
            if s.lower().startswith("sub_"):
                try:
                    addr = int(s[4:], 16)
                    return ("fun", addr)
                except:
                    raise ValueError("Invalid IDA Pro function name format.")
            elif s.lower().startswith("loc_"):
                try:
                    addr = int(s[4:], 16)
                    return ("lab", addr)
                except:
                    raise ValueError("Invalid IDA Pro label format.")
        # Otherwise, assume pure memory address.
        try:
            # Remove "0x" prefix if present.
            s_clean = s.lower().replace("0x", "")
            addr = int(s_clean, 16)
            return ("memory", addr)
        except:
            raise ValueError("Invalid memory address format.")
    
    def convert(self):
        try:
            input_str = self.input_entry.get()
            from_fmt = self.from_format.get()
            to_fmt = self.to_format.get()
            mode, addr = self.parse_input(input_str, from_fmt)
            
            # Function/Label conversion (no arithmetic conversion)
            if mode in ["fun", "lab"]:
                # Conversion rules:
                # - For Ghidra to IDA Pro or x64dbg:
                #    * "fun" → "sub_" + uppercase hex
                #    * "lab" → "loc_" + uppercase hex (or lowercase if preferred)
                # - For IDA Pro to Ghidra:
                #    * "fun" → "FUN_" + lowercase hex
                #    * "lab" → "LAB_" + lowercase hex
                if from_fmt.lower() == "ghidra" and to_fmt.lower() in ["ida pro", "x64dbg"]:
                    if mode == "fun":
                        s = format(addr, "X")
                        if s[0] in "ABCDEF":
                            s = "0" + s
                        result = "sub_" + s
                    else:  # mode == "lab"
                        # For labels, we output "loc_" followed by the address in lowercase
                        s = format(addr, "x")
                        result = "loc_" + s
                elif from_fmt.lower() == "ida pro" and to_fmt.lower() == "ghidra":
                    if mode == "fun":
                        result = "FUN_" + format(addr, "x")
                    else:  # mode == "lab"
                        result = "LAB_" + format(addr, "x")
                else:
                    # If no conversion is specified (e.g. same format) output unchanged.
                    result = input_str
            else:
                # Memory address conversion.
                # If converting from Ghidra, perform arithmetic conversion:
                # True Address = Actual Module Base + (Input Address - Ghidra Image Base)
                if from_fmt.lower() == "ghidra":
                    ghidra_base = int(self.ghidra_base_entry.get().strip(), 16)
                    module_base = int(self.module_base_entry.get().strip(), 16)
                    mem_addr = module_base + (addr - ghidra_base)
                else:
                    mem_addr = addr  # For IDA Pro or x64dbg input, assume address is already absolute.
                if to_fmt.lower() == "x64dbg":
                    result = f"{mem_addr:016X}"
                elif to_fmt.lower() == "ida pro":
                    s = format(mem_addr, "X")
                    if s[0] in "ABCDEF":
                        s = "0" + s
                    result = s + "h"
                elif to_fmt.lower() == "ghidra":
                    result = "0x" + format(mem_addr, "x")
                else:
                    result = hex(mem_addr)
            
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, result)
        except Exception as e:
            messagebox.showerror("Conversion Error", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = AddressConverterGUI(root)
    root.mainloop()
