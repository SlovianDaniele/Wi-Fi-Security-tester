import re
import sys
import os

# Функція повертає вибрану мережу з listbox
def get_selected_network(listbox_widget):
    selected_network = None
    selected_index = listbox_widget.curselection()
    if selected_index:
        selected_network = listbox_widget.get(selected_index)
    return selected_network


# Функція повертає знайдену кількість мереж у відповідному форматі
def get_networks_correct_form(count):
    if 11 <= count % 100 <= 14:
        return f"Знайдено {count} мереж"
    elif count % 10 == 1:
        return f"Знайдено {count} мережу"
    elif 2 <= count % 10 <= 4:
        return f"Знайдено {count} мережі"
    else:
        return f"Знайдено {count} мереж"


# Функція маскує значення, залишаючи видимими перші та останні 2 символи
def mask_value(value: str) -> str:
    if len(value) <= 4:
        return value
    return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"


def extract_and_mask_dynamic(data: str) -> dict:
    """
    Витягти WPS PIN і WPA PSK з наданого тексту та замаскувати їх значення

    :param data: Текстовий вивід, що містить WPS PIN і WPA PSK.
    :return: Словник із замаскованими WPS PIN і WPA PSK.
    """
    def mask_value(value: str) -> str:
        """
        Замаскувати середню частину значення, залишаючи видимими перші та останні 2 символи.

        :param value: Значення для маскування.
        :return: Замасковане значення.
        """
        if len(value) <= 4:
            return value  # Немає маскування для дуже коротких значень
        return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"

    # Витягти WPS PIN за допомогою регулярного виразу
    pin_match = re.search(r"WPS PIN: '([^']+)'", data)
    wps_pin = pin_match.group(1) if pin_match else None

    # Витягти WPA PSK за допомогою регулярного виразу
    psk_match = re.search(r"WPA PSK: '([^']+)'", data)
    wpa_psk = psk_match.group(1) if psk_match else None

    # Замаскувати значення
    masked_pin = mask_value(wps_pin) if wps_pin else None
    masked_psk = mask_value(wpa_psk) if wpa_psk else None

    return {"masked_wps_pin": masked_pin, "masked_wpa_psk": masked_psk}


# Функція повертає шлях до папки, де знаходиться виконуваний файл
def get_local_path():
    if getattr(sys, "frozen", False):
        # Виконується в скомпільованому файлі
        return os.path.dirname(sys.executable)
    else:
        # Виконується в скрипті
        return os.path.dirname(os.path.abspath(__file__))