# CTK_random_password_generator.py
# Make sure 'tobproject.ico' (and optionally 'tobproject.png') are in the same folder.

import os
import secrets
import string
import webbrowser
import threading
from datetime import datetime
import customtkinter as ctk
from tkinter import messagebox, filedialog, PhotoImage, Tk

ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

# ---------- Utilities ----------
def generate_password(length=12, use_upper=True, use_lower=True, use_digits=True, use_special=True):
    pool = ""
    if use_upper: pool += string.ascii_uppercase
    if use_lower: pool += string.ascii_lowercase
    if use_digits: pool += string.digits
    if use_special: pool += string.punctuation
    if not pool:
        raise ValueError("Select at least one character type.")
    return ''.join(secrets.choice(pool) for _ in range(length))

# ---------- App ----------
class PasswordGeneratorCTK(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Secure Password Generator (CTK)")
        self.geometry("750x750")
        self.resizable(False, False)

        # Icon (tobproject.ico)
        ico_path = os.path.join(os.path.dirname(__file__), "tobproject.ico")
        if os.path.exists(ico_path):
            try:
                self.wm_iconbitmap(ico_path)
            except Exception:
                png_path = os.path.join(os.path.dirname(__file__), "tobproject.png")
                if os.path.exists(png_path):
                    img = PhotoImage(file=png_path)
                    self.iconphoto(False, img)
        else:
            print("Warning: 'tobproject.ico' not found — continuing without custom icon.")

        # Header
        header = ctk.CTkLabel(self, text="Secure Password Generator", fg_color="#FFE490",
                              text_color="black", anchor="center", height=50,
                              font=("Helvetica", 16, "bold"))
        header.pack(fill="x", pady=(0,6))

        # Tabs
        self.tabs = ctk.CTkTabview(self, width=720, height=500)
        self.tabs.pack(padx=8, pady=8, expand=True, fill="both")
        self.tabs.add("Generator")
        self.tabs.add("Status")
        self.tabs.add("About Developer")

        self._build_generator_tab()
        self._build_status_tab()
        self._build_about_tab()

        # Storage
        self.last_results = []  # list of generated passwords
        self.status_log = []

    # ---------- UI builders ----------
    def _build_generator_tab(self):
        tab = self.tabs.tab("Generator")

        # Length + number to generate
        ctk.CTkLabel(tab, text="Password length:").grid(row=0, column=0, padx=6, pady=6, sticky="w")
        self.length_entry = ctk.CTkEntry(tab, width=120)
        self.length_entry.insert(0, "12")
        self.length_entry.grid(row=0, column=1, padx=6, pady=6, sticky="w")

        ctk.CTkLabel(tab, text="Quantity:").grid(row=0, column=2, padx=6, pady=6, sticky="w")
        self.qty_entry = ctk.CTkEntry(tab, width=80)
        self.qty_entry.insert(0, "1")
        self.qty_entry.grid(row=0, column=3, padx=6, pady=6, sticky="w")

        # Options checkboxes
        self.upper_var = ctk.BooleanVar(value=True)
        self.lower_var = ctk.BooleanVar(value=True)
        self.digits_var = ctk.BooleanVar(value=True)
        self.special_var = ctk.BooleanVar(value=True)

        ctk.CTkCheckBox(tab, text="Uppercase", variable=self.upper_var).grid(row=1, column=0, padx=6, pady=4, sticky="w")
        ctk.CTkCheckBox(tab, text="Lowercase", variable=self.lower_var).grid(row=1, column=1, padx=6, pady=4, sticky="w")
        ctk.CTkCheckBox(tab, text="Digits", variable=self.digits_var).grid(row=1, column=2, padx=6, pady=4, sticky="w")
        ctk.CTkCheckBox(tab, text="Special characters", variable=self.special_var).grid(row=1, column=3, padx=6, pady=4, sticky="w")

        # Results area
        self.results_box = ctk.CTkTextbox(tab, width=690, height=360)
        self.results_box.grid(row=2, column=0, columnspan=4, padx=6, pady=6)
        self.results_box.configure(state="disabled")

        # Buttons
        btn_frame = ctk.CTkFrame(tab)
        btn_frame.grid(row=3, column=0, columnspan=4, pady=(6,10))
        ctk.CTkButton(btn_frame, text="Generate", width=120, command=self.on_generate).pack(side="left", padx=6)
        ctk.CTkButton(btn_frame, text="Generate & Save (CSV)", width=160, command=self.on_generate_save).pack(side="left", padx=6)
        ctk.CTkButton(btn_frame, text="Copy", width=120, command=self.copy_latest).pack(side="left", padx=6)
        ctk.CTkButton(btn_frame, text="Copy All", width=120, command=self.copy_all).pack(side="left", padx=6)
        ctk.CTkButton(btn_frame, text="Clear", width=120, command=self.clear_results).pack(side="left", padx=6)

    def _build_status_tab(self):
        tab = self.tabs.tab("Status")
        self.status_box = ctk.CTkTextbox(tab, width=690, height=520)
        self.status_box.pack(padx=6, pady=6, fill="both", expand=True)
        self.status_box.configure(state="disabled")

    def _build_about_tab(self):
        tab = self.tabs.tab("About Developer")
        about_box = ctk.CTkTextbox(tab, width=690, height=520)
        about_box.pack(padx=6, pady=6, fill="both", expand=True)
        about_md = (
            "# Secure Password Generator\n"
            "**Author:** Andrés P. (tobproject)\n"
            "**Version:** v0.1 (Beta)\n"
            "**Purpose:** Educational and demonstrative use only.\n\n"
            "---\n\n"
            "## Contact\n"
            "LinkedIn: https://www.linkedin.com/in/andrespds/\n"
            "GitHub: https://github.com/tobproject\n"
            "Instagram: https://www.instagram.com/tob_project/\n"
        )
        about_box.insert("0.0", about_md)
        about_box.configure(state="disabled")

        # link buttons
        link_frame = ctk.CTkFrame(tab); link_frame.pack(padx=6, pady=(0,6), fill="x")
        ctk.CTkButton(link_frame, text="LinkedIn", command=lambda: webbrowser.open_new_tab("https://www.linkedin.com/in/andrespds/")).pack(side="left", padx=6)
        ctk.CTkButton(link_frame, text="GitHub", command=lambda: webbrowser.open_new_tab("https://github.com/tobproject")).pack(side="left", padx=6)
        ctk.CTkButton(link_frame, text="Instagram", command=lambda: webbrowser.open_new_tab("https://www.instagram.com/tob_project/")).pack(side="left", padx=6)

    # ---------- Actions ----------
    def on_generate(self):
        try:
            length = int(self.length_entry.get())
            qty = int(self.qty_entry.get())
            if length < 8:
                messagebox.showwarning("Invalid length", "Minimum length is 8 characters.")
                return
            if qty < 1:
                messagebox.showwarning("Invalid quantity", "Quantity must be >= 1.")
                return
        except ValueError:
            messagebox.showerror("Input error", "Please enter valid numbers for length and quantity.")
            return

        # run generation in a thread to keep UI responsive for large qty
        threading.Thread(target=self._generate_thread, args=(length, qty), daemon=True).start()

    def _generate_thread(self, length, qty):
        generated = []
        for _ in range(qty):
            pw = generate_password(length, self.upper_var.get(), self.lower_var.get(), self.digits_var.get(), self.special_var.get())
            generated.append(pw)
        ts = datetime.utcnow().isoformat()
        # update UI on main thread
        self.after(0, lambda: self._display_generated(generated))
        # update status log
        opts = f"U:{self.upper_var.get()} L:{self.lower_var.get()} D:{self.digits_var.get()} S:{self.special_var.get()}"
        log_line = f"{ts} | length={length} qty={qty} | options={opts}\n"
        self.status_log.append(log_line)
        self.after(0, lambda: self._append_status(log_line))

    def _display_generated(self, generated_list):
        self.last_results = generated_list
        self.results_box.configure(state="normal")
        self.results_box.delete("0.0", "end")
        for i, pw in enumerate(generated_list, start=1):
            self.results_box.insert("end", f"{i}: {pw}\n")
        self.results_box.see("end")
        self.results_box.configure(state="disabled")

    def _append_status(self, text):
        self.status_box.configure(state="normal")
        self.status_box.insert("end", text)
        self.status_box.see("end")
        self.status_box.configure(state="disabled")

    def on_generate_save(self):
        # generate first
        self.on_generate()
        # small delay to allow thread to produce results (for large qty better UX would wait)
        self.after(200, self._save_if_results)

    def _save_if_results(self):
        if not self.last_results:
            messagebox.showwarning("No results", "No passwords generated to save yet.")
            return
        # ask file and save simple CSV
        root = Tk(); root.withdraw()
        path = filedialog.asksaveasfilename(initialdir=os.path.expanduser("~/Desktop"), defaultextension=".csv", filetypes=[("CSV files","*.csv")])
        root.destroy()
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            for pw in self.last_results:
                f.write(pw + "\n")
        messagebox.showinfo("Saved", f"Passwords saved to {path}")

    def copy_latest(self):
        if not self.last_results:
            messagebox.showwarning("No results", "No password to copy.")
            return
        latest = self.last_results[-1]
        self.clipboard_clear()
        self.clipboard_append(latest)
        messagebox.showinfo("Copied", "Latest password copied to clipboard.")

    def copy_all(self):
        if not self.last_results:
            messagebox.showwarning("No results", "No passwords to copy.")
            return
        txt = "\n".join(self.last_results)
        self.clipboard_clear()
        self.clipboard_append(txt)
        messagebox.showinfo("Copied", "All passwords copied to clipboard.")

    def clear_results(self):
        self.last_results = []
        self.results_box.configure(state="normal")
        self.results_box.delete("0.0", "end")
        self.results_box.configure(state="disabled")

# ---------- Run ----------
if __name__ == "__main__":
    app = PasswordGeneratorCTK()
    app.mainloop()
