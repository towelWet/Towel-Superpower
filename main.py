import tkinter as tk
from tkinter import messagebox
import importlib

# Function to dynamically load and launch applications
def launch_app(module_name, class_name):
    try:
        module = importlib.import_module(module_name)
        importlib.reload(module)
        app_class = getattr(module, class_name)
        root = tk.Toplevel()
        app = app_class(root)
        root.mainloop()
    except ImportError:
        messagebox.showerror("Import Error", f"{module_name} module not found.")
    except AttributeError:
        messagebox.showerror("Error", f"Failed to find {class_name} in {module_name}.")
    except Exception as e:
        messagebox.showerror("Error", f"An unexpected error occurred: {str(e)}")

def main():
    root = tk.Tk()
    root.title("Towel Superpower Toolkit")
    root.geometry("400x300")

    tk.Button(root, text="Launch Ghidra Offset Calculator", command=lambda: launch_app('goc', 'GhidraOffsetCalculatorApp')).pack(pady=10)
    # GTX Converter button removed
    tk.Button(root, text="Launch Address Converter", command=lambda: launch_app('rc', 'AddressConverterGUI')).pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    main()
