import paramiko
import os
import errno


def remove_and_create_wifi2(ssh, password):
    """Видаляє папку wifi2 та створює нову папку wifi2."""
    try:
        # Видаляємо папку wifi2, якщо вона існує
        print("Видаляємо папку wifi2...")
        execute_command_with_sudo(ssh, "sudo rm -r /home/kali/wifi2", password)

        # Створюємо нову папку wifi2
        print("Створюємо папку wifi2...")
        execute_command_with_sudo(ssh, "sudo mkdir /home/kali/wifi2", password)
        print("Папка wifi2 успішно створена.")
    except Exception as e:
        print(f"Помилка під час видалення та створення папки wifi2: {e}")


def remove_and_create_handshake(ssh, password):
    """Видаляє папку handshake та створює нову папку handshake."""
    try:
        # Видаляємо папку handshake та convert, якщо вона існує
        print("Видаляємо папку handshake та convert...")
        execute_command_with_sudo(ssh, "sudo rm -r /home/kali/handshake", password)
        execute_command_with_sudo(ssh, "sudo rm -r /home/kali/convert", password)

        # Створюємо нову папку handshake
        print("Створюємо папку handshake та convert...")
        execute_command_with_sudo(ssh, "sudo mkdir /home/kali/handshake", password)
        execute_command_with_sudo(ssh, "sudo mkdir /home/kali/convert", password)
        print("Папка handshake та convert успішно створена.")
    except Exception as e:
        print(f"Помилка під час видалення та створення папки handshake та convert: {e}")


def execute_command_with_sudo(ssh, command, password):
    """Виконує команду з використанням sudo і передає пароль через stdin."""
    stdin, stdout, stderr = ssh.exec_command(f"sudo -S {command}")
    stdin.write(f"{password}\n")
    stdin.flush()
    return stdout.read().decode(), stderr.read().decode()


def is_process_running(ssh, process_name):
    """Перевіряє, чи працює процес."""
    _, stdout, _ = ssh.exec_command(f"pgrep -f {process_name}")
    return bool(stdout.read().strip())


def copy_file_via_sftp(remote_path, local_dir, host, username, password):
    """Копіює файл з Kali на Windows через SFTP."""
    try:
        os.makedirs(local_dir, exist_ok=True)
        local_file_path = os.path.join(local_dir, os.path.basename(remote_path))

        print(f"Починаємо копіювання файлу через SFTP: {remote_path} -> {local_file_path}")

        transport = paramiko.Transport((host, 22))
        transport.connect(username=username, password=password)
        sftp = paramiko.SFTPClient.from_transport(transport)

        sftp.get(remote_path, local_file_path)
        print(f"Файл успішно скопійовано в {local_file_path}.")

        sftp.close()
        transport.close()
    except Exception as e:
        print(f"Помилка під час копіювання файлу через SFTP: {e}")


def move_file(src_path, dest_dir, new_name):
    try:
        # Переконуємось, що цільова директорія існує
        os.makedirs(dest_dir, exist_ok=True)

        # Витягуємо розширення файлу та створюємо новий шлях призначення
        _, ext = os.path.splitext(src_path)
        dest_path = os.path.join(dest_dir, new_name + ext)

        # Копіюємо файл
        with open(src_path, 'rb') as src_file:
            with open(dest_path, 'wb') as dest_file:
                dest_file.write(src_file.read())

        # Видаляємо оригінальний файл
        os.remove(src_path)

        print(f"Файл переміщено та перейменовано на: {dest_path}")
        return dest_path
    except OSError as e:
        if e.errno == errno.ENOENT:
            print("Вихідний файл не існує")
        else:
            print(f"Помилка: {e}")
