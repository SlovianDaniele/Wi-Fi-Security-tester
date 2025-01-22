import ttkbootstrap as ttk
import tkinter as tk
from tkinter.scrolledtext import ScrolledText
from widget_registry import widget_registry
import wps_tab, handshake_tab, dict_tab
from vm_utils import init_vm, shutdown_vm

root = ttk.Window(
    title="Тестування вразливостей Wi-Fi",
    themename="minty",
    size=(900, 800),
    resizable=(True, True)
)

# Налаштування стилю ttk з TkFixedFont
style = ttk.Style()
fixed_font = ttk.font.nametofont("TkFixedFont")
fixed_font.configure(size=16)
style.configure("TLabel", font=fixed_font)
style.configure("TButton", font=fixed_font)
style.configure("TNotebook.Tab", font=fixed_font)
style.configure("TLabelFrame", font=fixed_font)
style.configure("TEntry", font=fixed_font)
style.configure("TCheckbutton", font=fixed_font)
style.configure("TCombobox", font=fixed_font)

# Створення основного контейнера з відступами
main_container = ttk.Frame(root, padding=20)
main_container.pack(fill="both", expand=True)

# Створення та стилізація вкладок
tabs = ttk.Notebook(main_container)
tabs.pack(fill="both", expand=True)

# Створення та додавання вкладок
wps_tab = wps_tab.init(tabs, root)
handshake_tab = handshake_tab.init(tabs, root)
dict_tab = dict_tab.init(tabs)

tabs.add(wps_tab, text='WPS')
tabs.add(handshake_tab, text="Handshake")
tabs.add(dict_tab, text="Словники")

# Текстовий віджет з прокруткою
console = ScrolledText(root, wrap=tk.WORD, height=6, width=50)
console.pack(padx=0, pady=0, fill=tk.BOTH, expand=False)
widget_registry.register_widget("console", console)

# Віджет для відображення статусу віртуальної машини
vm_status_label = ttk.Label(root, text=f"Статус віртуальної машини:", anchor="w")
vm_status_label.pack(padx=20, pady=10, expand=False, side="left")
widget_registry.register_widget("vm_status_label", vm_status_label)
vm_status = ttk.Label(root, text="", anchor="w")
vm_status.pack(padx=0, pady=10, expand=False, side="left")
widget_registry.register_widget("vm_status", vm_status)


def on_close():
    if tk.messagebox.askokcancel("Quit", "Ви дійсно хочете закрити застосунок?"):
        shutdown_vm(root)   # Вимкнення віртуальної машини
        root.destroy()  # Закриває додаток
    else:
        # Нічого не робити, якщо користувач скасовує
        pass


# Запитувати користувача, чи він дійсно хоче закрити вікно?
root.protocol("WM_DELETE_WINDOW", on_close)

# Запуск віртуальної машини після завантаження головного вікна
root.after(1000, lambda: init_vm(root))

# Запуск головного циклу
root.mainloop()