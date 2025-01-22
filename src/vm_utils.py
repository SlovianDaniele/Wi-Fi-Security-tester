import subprocess
import time
from config import config
from widget_registry import widget_registry

# Параметри підключення SSH
username = config.get("username")
password = config.get("password")
vm_name = config.get("vm_name")


# Запуск віртуальної машини
def start_vm(root):
    try:
        subprocess.run(["C:/Program Files/Oracle/VirtualBox/VBoxManage", "startvm", vm_name, "--type", "headless"])
        print(f"VM '{vm_name}' started.")
    except subprocess.CalledProcessError:
        print(f"Не вдалося запустити VM '{vm_name}'.")
        widget_registry.get_widget("vm_status").config(text=f"● ВИМКНЕНА, не вдалось запустити", foreground="red")
        root.update()


# Отримання IP через guestproperty
def get_ip_from_guestproperty(root):
    try:
        output = subprocess.check_output(
            ["C:/Program Files/Oracle/VirtualBox/VBoxManage", "guestproperty", "get", vm_name,
             "/VirtualBox/GuestInfo/Net/0/V4/IP"],
            universal_newlines=True
        )
        if "Value" in output:
            ip = output.split()[-1]
            if ip != "null":
                return ip
        else:
            return None
    except subprocess.CalledProcessError:
        print("Не вдалося отримати IP через guestproperty.")
    return None


# Вимкнення віртуальної машини
def shutdown_vm(root):
    try:
        subprocess.run(["C:/Program Files/Oracle/VirtualBox/VBoxManage", "controlvm", vm_name, "poweroff"])
        print(f"VM '{vm_name}' is powered off.")
    except Exception:
        print(f"Не вдалося вимкнути VM '{vm_name}'.")


# Перевірка статусу віртуальної машини
def is_vm_running(root):
    try:
        output = subprocess.check_output(
            ["C:/Program Files/Oracle/VirtualBox/VBoxManage", "showvminfo", vm_name],
            universal_newlines=True
        )
        return "running" in output
    except Exception:
        print(f"Не вдалося перевірити статус VM '{vm_name}'.")
        widget_registry.get_widget("vm_status").config(text=f"● Не вдалося перевірити статус", foreground="red")
        root.update()


# Ініціалізація віртуальної машини
def init_vm(root):
    try:
        if not is_vm_running(root):
            start_vm(root)
            widget_registry.get_widget("vm_status").config(text=f"● ЗАВАНТАЖЕННЯ...", foreground="orange")
            root.update()
            time.sleep(30)  # Чекаємо 30 секунд на завантаження

        # Спробуємо знайти IP
        ip = get_ip_from_guestproperty(root)
        if ip:
            print(f"Знайдено IP: {ip}")
            config.update("host", ip)
            widget_registry.get_widget("vm_status").config(text=f"● ПРАЦЮЄ, IP: {ip}", foreground="green")
        else:
            widget_registry.get_widget("vm_status").config(text=f"● ПРАЦЮЄ, IP не знайдено", foreground="red")
    except Exception as e:
        print(e)
