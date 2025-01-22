import tkinter as tk
from widget_registry import widget_registry


# Функція для запису повідомлень у консоль
def log_message(message):
    widget_registry.get_widget("console").insert(tk.END, message + "\n")  # Додає повідомлення
    widget_registry.get_widget("console").see(tk.END)  # Прокручує до останнього рядка