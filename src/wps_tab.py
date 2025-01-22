import ttkbootstrap as ttk
import tkinter as tk
import paramiko
import time
import os
import re
from widget_registry import widget_registry
from network_utils import get_networks_correct_form, get_selected_network, mask_value
from log_utils import log_message
from config import config

username = config.get("username")
password = config.get("password")


def init(notebook, root):
    tab = ttk.Frame(notebook, padding=20)

    fixed_font = tk.font.nametofont("TkFixedFont")

    # Кнопка для сканування доступних Wi-Fi мереж
    scan_button = ttk.Button(
        tab,
        text="Сканувати доступні Wi-Fi мережі",
        command=lambda: on_wifi_scan(root),
        bootstyle=ttk.SUCCESS
    )
    scan_button.pack(pady=10)
    widget_registry.register_widget("wps_scan_button", scan_button)

    # Мітка для статусу сканування
    scan_status_label = ttk.Label(tab, text="")
    scan_status_label.pack(pady=10)
    widget_registry.register_widget("wps_scan_status_label", scan_status_label)

    ttk.Frame(tab).pack(pady=10)

    # Мітка для списку мереж
    networks_label = ttk.Label(tab, anchor="w", text=f"BSSID               Ch  dBm  WPS  Lck  Vendor    ESSID")
    networks_label.pack(pady=0, anchor="w", fill="x")
    widget_registry.register_widget("wps_networks_label", networks_label)

    # Список для відображення знайдених Wi-Fi мереж
    networks_listbox = tk.Listbox(tab, height=8, font=fixed_font)
    networks_listbox.pack(fill="x", pady=10)
    networks_listbox.bind("<<ListboxSelect>>", on_network_select)
    widget_registry.register_widget("wps_networks_listbox", networks_listbox)

    # Кнопка для перевірки вразливості WPS
    check_button = ttk.Button(
        tab,
        text="Перевірити вразливість WPS",
        command=lambda: on_wps_check(root),
        bootstyle=ttk.SUCCESS,
        state=ttk.DISABLED
    )
    check_button.pack(pady=10)
    widget_registry.register_widget("wps_check_button", check_button)

    # Мітка для статусу перевірки
    check_status_label = ttk.Label(tab, text="")
    check_status_label.pack(pady=10)
    widget_registry.register_widget("wps_check_status_label", check_status_label)

    return tab


def on_network_select(event):
    selected_network = get_selected_network(widget_registry.get_widget("wps_networks_listbox"))
    if selected_network:
        check_status_label_text = "Обрано мережу: " + selected_network.split()[0]
        widget_registry.get_widget("wps_check_status_label").config(text=check_status_label_text)
        widget_registry.get_widget("wps_check_button").config(state=ttk.NORMAL)


def on_wifi_scan(root):
    host = config.get("host")

    widget_registry.get_widget("wps_scan_button").config(state=ttk.DISABLED)
    widget_registry.get_widget("wps_scan_status_label").config(text="Починаємо роботу...")
    log_message("[WPS]: Починаємо роботу...")

    widget_registry.get_widget("wps_check_button").config(state=ttk.DISABLED)
    widget_registry.get_widget("wps_check_status_label").config(text="")

    networks = []
    widget_registry.get_widget("wps_networks_listbox").delete(0, 'end')

    root.update()

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(host, username=username, password=password)

        widget_registry.get_widget("wps_scan_status_label").config(text="Переводимо wlan0 в режим моніторингу...")
        log_message("[WPS]: Переводимо wlan0 в режим моніторингу...")
        root.update()

        print("Переводимо wlan0 в режим моніторингу...")

        stdin, stdout, stderr = ssh.exec_command(f'echo {password} | sudo -S airmon-ng start wlan0', get_pty=True)
        time.sleep(5)

        output_wlan0 = stdout.read().decode()
        errors_wlan0 = stderr.read().decode()
        print(f"Результат виконання команди 'sudo airmon-ng start wlan0':\n{output_wlan0}")
        if errors_wlan0:
            print(f"Помилка: {errors_wlan0}")

        widget_registry.get_widget("wps_scan_status_label").config(text="Запускаємо wash для пошуку WPS точок...")
        log_message("[WPS]: Запускаємо wash для пошуку WPS точок...")
        root.update()

        print("Запускаємо wash для пошуку WPS точок...")
        stdin, stdout, stderr = ssh.exec_command(f'echo {password} | sudo -S wash -i wlan0mon', get_pty=True)
        stdout.channel.settimeout(10)

        start_time = time.time()
        max_duration = 60

        while True:
            try:
                output = stdout.readline()
                if output == '' and stdout.channel.exit_status_ready():
                    break
                if output:
                    print(output.strip())
                    network = output.strip()
                    if network and not network.startswith("BSSID") and not network.startswith("--------------------------------------------------------------------------------"):
                        networks.append(network)
                        widget_registry.get_widget("wps_networks_listbox").insert(tk.END, f"{network}")
                        widget_registry.get_widget("wps_scan_status_label").config(text=f"{get_networks_correct_form(len(networks))}")
                        root.update()
                if time.time() - start_time > max_duration:
                    print("\nМаксимальний час сканування завершився.")
                    log_message("[WPS]: Максимальний час сканування завершився.")
                    break
            except Exception as e:
                print(f"Помилка при читанні: {e}")
                break

        print(networks)
        filtered_networks = [network for network in networks if network and not network.startswith("BSSID") and not network.startswith("--------------------------------------------------------------------------------")]

        if filtered_networks:
            widget_registry.get_widget("wps_scan_status_label").config(text=f"{get_networks_correct_form(len(networks))}")
            root.update()

            print("\nДоступні мережі:")
            for i, network in enumerate(filtered_networks, 1):
                print(f"{i}. {network}")

        # Попередньо вибрати перший елемент
        widget_registry.get_widget("wps_networks_listbox").select_set(0)
        widget_registry.get_widget("wps_networks_listbox").activate(0)
        on_network_select(None)

        widget_registry.get_widget("wps_scan_button").config(state=ttk.NORMAL)

    except Exception as e:
        print(f"Виникла помилка: {e}")
        log_message(f"[WPS]: Виникла помилка: {e}")

    finally:
        print("\nЗупинка моніторингового режиму...")
        stdin, stdout, stderr = ssh.exec_command(f'echo {password} | sudo -S airmon-ng stop wlan0mon', get_pty=True)
        stdout.channel.recv_exit_status()  # Очікування завершення команди
        output_stop = stdout.read().decode()
        errors_stop = stderr.read().decode()
        print(f"Результат зупинки моніторингового режиму:\n{output_stop}")
        if errors_stop:
            print(f"Помилка: {errors_stop}")

        ssh.close()
        print("Підключення до SSH закрито.")

        widget_registry.get_widget("wps_check_button").config(state=ttk.NORMAL)
        root.update()


def on_wps_check(root):
    host = config.get("host")

    widget_registry.get_widget("wps_check_button").config(state=ttk.DISABLED)
    root.update()

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(host, username=username, password=password)

        print("Переводимо wlan0 в режим моніторингу...")
        widget_registry.get_widget("wps_check_status_label").config(text="Переводимо wlan0 в режим моніторингу...")
        log_message("[WPS]: Переводимо wlan0 в режим моніторингу...")
        root.update()

        stdin, stdout, stderr = ssh.exec_command(f'echo {password} | sudo -S airmon-ng start wlan0', get_pty=True)
        time.sleep(5)

        selected_network = get_selected_network(widget_registry.get_widget("wps_networks_listbox"))
        bssid = selected_network.split()[0]

        print(f"Запускаємо reaver для мережі з BSSID: {bssid}")
        widget_registry.get_widget("wps_check_status_label").config(text=f"Запускаємо reaver для мережі з BSSID: {bssid}")
        log_message(f"[WPS]: Запускаємо reaver для мережі з BSSID: {bssid}")
        root.update()

        stdin, stdout, stderr = ssh.exec_command(f'echo {password} | sudo -S reaver -i wlan0mon -b {bssid} -K -N',
                                                 get_pty=True)

        attack_successful = False
        no_vulnerabilities = False
        extracted_data = "\n"

        try:
            while True:
                output = stdout.readline()
                if output == '':
                    break
                print(output.strip())

                if "Pixiewps: success" in output or ("WPS PIN" in output and "WPA PSK" in output):
                    attack_successful = True
                if "WPS pin not found!" in output:
                    no_vulnerabilities = True

                # Витягти WPS PIN
                pin_match = re.search(r"WPS PIN: '([^']+)'", output)
                wps_pin = pin_match.group(1) if pin_match else None
                if wps_pin:
                    extracted_data += f"\nWPS PIN: {mask_value(wps_pin)}"
                # Витягти WPA
                psk_match = re.search(r"WPA PSK: '([^']+)'", output)
                wpa_psk = psk_match.group(1) if psk_match else None
                if wpa_psk:
                    extracted_data += f"\nWPA PSK: {mask_value(wpa_psk)}"
        except KeyboardInterrupt:
            print("\nСкасування атаки користувачем...")
            widget_registry.get_widget("wps_check_status_label").config(text="Скасування атаки користувачем...")
            log_message("[WPS]: Скасування атаки користувачем...")
            root.update()
            ssh.exec_command(f'echo {password} | sudo -S killall reaver', get_pty=True)

        if attack_successful:
            attack_successful_text = "Ваша мережа вразлива до WPS Pixie Dust атаки.\nРадимо вам вимкнути WPS, щоб покращити свій захист."
            attack_successful_text += extracted_data
            print(f"\n{attack_successful_text}")
            widget_registry.get_widget("wps_check_status_label").config(text=attack_successful_text)
            root.update()
        elif no_vulnerabilities:
            no_vulnerabilities_text = "Чудово! Ваша мережа не має вразливостей для WPS Pixie Dust атаки."
            print(f"\n{no_vulnerabilities_text}")
            widget_registry.get_widget("wps_check_status_label").config(text=no_vulnerabilities_text)
            root.update()

    except Exception as e:
        print(f"Виникла помилка: {e}")
        log_message(f"[WPS]: Виникла помилка: {e}")

    finally:
        print("\nЗупинка моніторингового режиму...")
        stdin, stdout, stderr = ssh.exec_command(f'echo {password} | sudo -S airmon-ng stop wlan0mon', get_pty=True)
        stdout.channel.recv_exit_status()  # Очікування завершення команди
        output_stop = stdout.read().decode()
        errors_stop = stderr.read().decode()
        print(f"Результат зупинки моніторингового режиму:\n{output_stop}")
        if errors_stop:
            print(f"Помилка: {errors_stop}")

        ssh.close()
        print("Підключення до SSH закрито.")

        widget_registry.get_widget("wps_check_button").config(state=ttk.NORMAL)
        root.update()