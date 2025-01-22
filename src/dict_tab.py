import ttkbootstrap as ttk
import tkinter as tk
from tkinter import messagebox
import subprocess
import os
from widget_registry import widget_registry
from log_utils import log_message
from ssh_utils import move_file
from config import config
from network_utils import get_local_path

local_path = get_local_path()
local_dict_path = os.path.join(local_path, config.get("dict_folder"))


def init(notebook):
    tab = ttk.Frame(notebook, padding=20)

    fields = [
        ("Ім'я", "name"),
        ("Прізвище", "surname"),
        ("Псевдонім", "nick"),
        ("Дата народження (DDMMYYYY)", "birthdate"),
        ("Ім'я дружини/чоловіка", "wife"),
        ("Псевдонім дружини/чоловіка", "wifen"),
        ("Дата народження дружини/чоловіка", "wifeb"),
        ("Ім'я дитини", "kid"),
        ("Псевдонім дитини", "kidn"),
        ("Дата народження дитини", "kidb"),
        ("Кличка домашнього улюбленця", "pet"),
        ("Назва компанії", "company"),
        ("Ключові слова", "words"),
    ]
    entries = {}

    form_frame = ttk.Frame(tab)
    form_frame.pack(fill=tk.BOTH, expand=True, pady=10)

    next_row_index = 0
    for i, (label, field) in enumerate(fields):
        ttk.Label(form_frame, text=label, anchor="e").grid(row=i, column=0, padx=5, pady=5, sticky="e")
        entry = ttk.Entry(form_frame, width=40)
        entry.grid(row=i, column=1, padx=5, pady=2)
        entries[field] = entry
        widget_registry.register_widget("dict_" + field, entry)
        next_row_index = i + 1

    # Checkbox для спеціальних символів
    special_symbols_var = tk.BooleanVar(value=True)
    special_symbols_checkbox = ttk.Checkbutton(form_frame, text="Спец. символи (!, @, #, ...)",
                                               variable=special_symbols_var)
    special_symbols_checkbox.grid(row=next_row_index, column=1, padx=5, pady=2, sticky="w")

    # Генерація
    scan_button = ttk.Button(
        tab,
        text="Генерувати словник",
        command=lambda: on_generate_dictionary(),
        bootstyle=ttk.SUCCESS
    )
    scan_button.pack()
    widget_registry.register_widget("dict_generate_button", scan_button)

    return tab


def on_generate_dictionary():
    fields = {
        "name": widget_registry.get_widget("dict_name").get().strip(),
        "surname": widget_registry.get_widget("dict_surname").get().strip(),
        "nick": widget_registry.get_widget("dict_nick").get().strip(),
        "birthdate": widget_registry.get_widget("dict_birthdate").get().strip(),
        "wife": widget_registry.get_widget("dict_wife").get().strip(),
        "wifen": widget_registry.get_widget("dict_wifen").get().strip(),
        "wifeb": widget_registry.get_widget("dict_wifeb").get().strip(),
        "kid": widget_registry.get_widget("dict_kid").get().strip(),
        "kidn": widget_registry.get_widget("dict_kidn").get().strip(),
        "kidb": widget_registry.get_widget("dict_kidb").get().strip(),
        "pet": widget_registry.get_widget("dict_pet").get().strip(),
        "company": widget_registry.get_widget("dict_company").get().strip(),
        "words": widget_registry.get_widget("dict_words").get().strip(),
    }

    if not fields["name"] or not fields["surname"]:
        messagebox.showerror("Помилка", "Ім'я та прізвище обов'язкові поля.")
        return

    # Інтерактивний ввід для Cupp
    interactive_input = (
        f"{fields['name']}\n{fields['surname']}\n{fields['nick']}\n{fields['birthdate']}\n"
        f"{fields['wife']}\n{fields['wifen']}\n{fields['wifeb']}\n"
        f"{fields['kid']}\n{fields['kidn']}\n{fields['kidb']}\n"
        f"{fields['pet']}\n{fields['company']}\n"
        f"{'y'}\n{fields['words']}\n{'y'}\n{'n'}\n{'n'}\n{'n'}\n"
    )

    try:
        process = subprocess.run(
            ["python", os.path.join(local_path, "cupp.py"), "-i"],
            input=interactive_input,
            text=True,
            capture_output=True,
            check=True,
        )

        log_message("[Dict] Словник успішно згенеровано!")
        messagebox.showinfo("Успіх", "Словник успішно згенеровано!")

        move_file(f"{fields['name'].lower()}.txt", local_dict_path, f"{fields['name'].lower()}_{fields['surname'].lower()}")
    except subprocess.CalledProcessError as e:
        print(e.stderr)
        log_message(f"[Dict] {e.stderr}")
        messagebox.showerror("Помилка", "Не вдалось згенерувати словник.")
    except FileNotFoundError:
        messagebox.showerror("Помилка", "cupp.py не знайдено")