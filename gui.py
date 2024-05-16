import tkinter as tk
from tkinter import filedialog, messagebox
from core_scan import scan_file, scan_directory, load_cache, save_cache

def scan():
    cache = load_cache()
    path = filedialog.askopenfilename() if scan_type.get() == 'file' else filedialog.askdirectory()
    if path:
        if scan_type.get() == 'file':
            result = scan_file(path, cache)
            if result:
                messagebox.showwarning("Threat Detected", f"Threat detected: {result}")
            else:
                messagebox.showinfo("No Threats", "No threats detected.")
        else:
            results = scan_directory(path, cache)
            if results:
                result_str = "\n".join([f"{file}: {virus}" for file, virus in results.items()])
                messagebox.showwarning("Threats Detected", f"Threats detected:\n{result_str}")
            else:
                messagebox.showinfo("No Threats", "No threats detected.")
        save_cache(cache)

app = tk.Tk()
app.title("ClawAV")

scan_type = tk.StringVar(value='file')
tk.Radiobutton(app, text="Scan File", variable=scan_type, value='file').pack(anchor='w')
tk.Radiobutton(app, text="Scan Directory", variable=scan_type, value='directory').pack(anchor='w')
tk.Button(app, text="Start Scan", command=scan).pack()

app.mainloop()
