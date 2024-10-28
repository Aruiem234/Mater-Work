import asyncio
import logging
import time
import os
import re
import subprocess
from datetime import datetime
import paramiko
from scp import SCPClient
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    CallbackQueryHandler,
    ContextTypes,
    ConversationHandler,
    MessageHandler,
    filters,
)
from telegram.helpers import escape
import base64
from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform
from lxml import etree

# Logging settings
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)

# States for ConversationHandler
(
    ADDING_CLIENT,
    REMOVING_CLIENT,
    EXECUTING_COMMAND,
    DOWNLOADING_FILE,
    STARTING_OPENVAS_SCAN,
    CHOOSING_SCAN_TYPE,
    CHOOSING_NMAP_SCAN_TYPE,
    STARTING_NMAP_SCAN,
) = range(8)

# Telegram Token and ID of the authorized user
TOKEN = "TOKEN"
AUTHORIZED_USER_ID = ID

# Paths and settings
RASPBERRY_PI_VPN_IP = "IP"
SSH_USERNAME = "user"
SSH_PASSWORD = "pass"
GMP_HOST = RASPBERRY_PI_VPN_IP
GMP_PORT = 9390
GMP_USERNAME = 'admin'
GMP_PASSWORD = 'pass'
ADD_USER_SCRIPT = "/root/vpn_bot/add_user.sh"
OVPN_OUTPUT_DIR = "/root"
EASYRSA_PATH = "/etc/openvpn/easy-rsa"

# Directories for scan results on the server
SCAN_RESULTS_DIR = "/home/kali/scan_results/"
OPENVAS_RESULTS_DIR = "/home/kali/scan_results/openvas/"
NMAP_RESULTS_DIR = os.path.join(SCAN_RESULTS_DIR, "nmap/")
# Local path for temporary storage of results
LOCAL_RESULTS_DIR = "/tmp/openvas_results/"

# Function to display the main menu
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logging.info("start command called")
    if update.effective_user.id != AUTHORIZED_USER_ID:
        await update.effective_message.reply_text("❌ У вас немає доступу.")
        return ConversationHandler.END

    keyboard = [
        [InlineKeyboardButton("➕ Додати клієнта", callback_data="add_client")],
        [InlineKeyboardButton("➖ Видалити клієнта", callback_data="remove_client")],
        [InlineKeyboardButton("👥 Активні клієнти", callback_data="list_clients")],
        [InlineKeyboardButton("📄 Переглянути файли сканування", callback_data="list_scans")],
        [InlineKeyboardButton("🖥 Виконати команду", callback_data="execute_command")],
        [InlineKeyboardButton("🗂 Завантажити файл за шляхом", callback_data="download_by_path")],
        [InlineKeyboardButton("🔍 Запустити OpenVAS сканування", callback_data="start_openvas_scan")],
        [InlineKeyboardButton("🌐 Запустити Nmap сканування", callback_data="start_nmap_scan")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    await update.effective_message.reply_text(
        "👋 Вітаю! Виберіть дію з меню нижче:", reply_markup=reply_markup
    )
    return ConversationHandler.END

# Download file by path
async def download_by_path_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    file_path = update.message.text.strip()
    if file_path.lower() == "назад":
        return await go_back(update, context)

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(RASPBERRY_PI_VPN_IP, username=SSH_USERNAME, password=SSH_PASSWORD)

        with SCPClient(ssh.get_transport()) as scp:
            local_file = os.path.basename(file_path)
            scp.get(file_path, local_file)

        with open(local_file, "rb") as f:
            await update.message.reply_document(f, filename=local_file)
        os.remove(local_file)
        ssh.close()

        await update.message.reply_text(f"✅ Файл {escape(file_path)} успішно завантажений.", parse_mode="HTML")
    except Exception as e:
        logging.error(f"Error downloading file: {e}")
        await update.message.reply_text(f"❌ Помилка при завантаженні файлу:\n{e}")

    await start(update, context)
    return ConversationHandler.END

# Function to go back to the main menu
async def go_back(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logging.info("go_back called")
    query = update.callback_query
    if query:
        await query.answer()
        await start(update, context)
    else:
        await start(update, context)
    return ConversationHandler.END

# Function to display the "Back" button
def back_button():
    keyboard = [[InlineKeyboardButton("🔙 Назад", callback_data="go_back")]]
    return InlineKeyboardMarkup(keyboard)

# Handle commands from the menu
async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    if update.effective_user.id != AUTHORIZED_USER_ID:
        await query.message.reply_text("❌ У вас немає доступу.")
        return

    data = query.data
    logging.info(f"Button pressed: {data}")

    if data == "add_client":
        await query.message.reply_text(
            "✏ Введіть ім'я нового клієнта або натисніть 'Назад', щоб повернутися:",
            reply_markup=back_button(),
        )
        return ADDING_CLIENT
    elif data == "remove_client":
        await query.message.reply_text(
            "✏ Введіть ім'я клієнта для видалення або натисніть 'Назад', щоб повернутися:",
            reply_markup=back_button(),
        )
        return REMOVING_CLIENT
    elif data == "list_clients":
        await list_clients_command(update, context)
    elif data == "list_scans":
        await list_scans(update, context)
    elif data == "download_by_path":
        await query.message.reply_text(
            "✏ Введіть шлях до файлу для завантаження або натисніть 'Назад', щоб повернутися:",
            reply_markup=back_button(),
        )
        return DOWNLOADING_FILE
    elif data == "execute_command":
        await query.message.reply_text(
            "✏ Введіть команду для виконання на сервері або натисніть 'Назад', щоб повернутися:",
            reply_markup=back_button(),
        )
        return EXECUTING_COMMAND
    elif data == "start_openvas_scan":
        await choose_scan_type(update, context)
        return CHOOSING_SCAN_TYPE
    elif data == "start_nmap_scan":
        await choose_nmap_scan_type(update, context)
        return CHOOSING_NMAP_SCAN_TYPE
    elif data == "quick_scan":
        context.user_data["scan_type"] = "quick_scan"
        await query.message.reply_text(
            "✏ Введіть ціль для OpenVAS сканування (IP або діапазон) або натисніть 'Назад', щоб повернутися:",
            reply_markup=back_button(),
        )
        return STARTING_OPENVAS_SCAN
    elif data == "full_scan":
        context.user_data["scan_type"] = "full_scan"
        await query.message.reply_text(
            "✏ Введіть ціль для OpenVAS сканування (IP або діапазон) або натисніть 'Назад', щоб повернутися:",
            reply_markup=back_button(),
        )
        return STARTING_OPENVAS_SCAN
    elif data == "nmap_quick_scan":
        context.user_data["nmap_scan_type"] = "quick"
        await query.message.reply_text(
            "✏ Введіть ціль для Nmap сканування (IP або діапазон) або натисніть 'Назад', щоб повернутися:",
            reply_markup=back_button(),
        )
        return STARTING_NMAP_SCAN
    elif data == "nmap_full_scan":
        context.user_data["nmap_scan_type"] = "full"
        await query.message.reply_text(
            "✏ Введіть ціль для Nmap сканування (IP або діапазон) або натисніть 'Назад', щоб повернутися:",
            reply_markup=back_button(),
        )
        return STARTING_NMAP_SCAN
    elif data == "go_back":
        await go_back(update, context)
    elif data in context.user_data.get('file_mappings', {}):
        await download_scan(update, context, data)
    else:
        await query.message.reply_text("❌ Невідома команда.")
    return ConversationHandler.END

# Function to choose OpenVAS scan type
async def choose_scan_type(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = [
        [InlineKeyboardButton("Швидке сканування", callback_data="quick_scan")],
        [InlineKeyboardButton("Повне сканування", callback_data="full_scan")],
        [InlineKeyboardButton("🔙 Назад", callback_data="go_back")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.callback_query.message.reply_text("Виберіть тип сканування OpenVAS:", reply_markup=reply_markup)

# Function to choose Nmap scan type
async def choose_nmap_scan_type(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = [
        [InlineKeyboardButton("Швидке сканування", callback_data="nmap_quick_scan")],
        [InlineKeyboardButton("Повне сканування", callback_data="nmap_full_scan")],
        [InlineKeyboardButton("🔙 Назад", callback_data="go_back")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.callback_query.message.reply_text("Виберіть тип сканування Nmap:", reply_markup=reply_markup)

# Add client
async def add_client_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    client_name = update.message.text
    ovpn_file = f"{OVPN_OUTPUT_DIR}/{client_name}.ovpn"

    try:
        cmd_create = f"sudo bash {ADD_USER_SCRIPT} {client_name}"
        subprocess.run(cmd_create, shell=True, check=True)

        if os.path.exists(ovpn_file):
            with open(ovpn_file, "rb") as f:
                await update.message.reply_document(f, filename=f"{client_name}.ovpn")
            os.remove(ovpn_file)

            await update.message.reply_text(
                f"✅ Клієнт <b>{escape(client_name)}</b> успішно доданий, файл .ovpn надісланий.",
                parse_mode="HTML",
            )
        else:
            await update.message.reply_text(f"⚠ Файл {client_name}.ovpn не знайдений.")

        # Cleanup revoked certificates
        cleanup_revoked_certs()

    except subprocess.CalledProcessError as e:
        logging.error(f"Error adding client: {e}")
        await update.message.reply_text(f"❌ Помилка при додаванні клієнта:\n{e}")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        await update.message.reply_text(f"❌ Непередбачена помилка:\n{e}")

    await start(update, context)
    return ConversationHandler.END

# Remove client
async def remove_client_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    client_name = update.message.text

    try:
        cmd_revoke = f"cd {EASYRSA_PATH} && ./easyrsa --batch revoke {client_name} && ./easyrsa gen-crl"
        subprocess.run(cmd_revoke, shell=True, check=True)

        cmd_copy_crl = f"cp {EASYRSA_PATH}/pki/crl.pem /etc/openvpn/crl.pem"
        subprocess.run(cmd_copy_crl, shell=True, check=True)

        client_config = f"/etc/openvpn/client-configs/files/{client_name}.ovpn"
        if os.path.exists(client_config):
            os.remove(client_config)

        await update.message.reply_text(
            f"✅ Клієнт <b>{escape(client_name)}</b> успішно видалений.",
            parse_mode="HTML",
        )

        # Cleanup revoked certificates
        cleanup_revoked_certs()

    except subprocess.CalledProcessError as e:
        logging.error(f"Error removing client: {e}")
        await update.message.reply_text(f"❌ Помилка при видаленні клієнта:\n{e}")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        await update.message.reply_text(f"❌ Непередбачена помилка:\n{e}")

    await start(update, context)
    return ConversationHandler.END

# Function to clean up revoked certificates
def cleanup_revoked_certs():
    index_file = f"{EASYRSA_PATH}/pki/index.txt"
    with open(index_file, 'r') as f:
        lines = f.readlines()

    active_lines = []
    for line in lines:
        if line.startswith('V'):
            active_lines.append(line)
        else:
            # Remove revoked certificate files
            parts = line.strip().split('\t')
            if len(parts) >= 6:
                dn = parts[5]
                cn = dn.split('CN=')[-1]
                cert_file = f"{EASYRSA_PATH}/pki/issued/{cn}.crt"
                key_file = f"{EASYRSA_PATH}/pki/private/{cn}.key"
                req_file = f"{EASYRSA_PATH}/pki/reqs/{cn}.req"
                # Remove files if they exist
                for file_path in [cert_file, key_file, req_file]:
                    if os.path.exists(file_path):
                        os.remove(file_path)

    # Rewrite index.txt with active certificates
    with open(index_file, 'w') as f:
        f.writelines(active_lines)

    # Update CRL
    subprocess.run(f"cd {EASYRSA_PATH} && ./easyrsa gen-crl", shell=True, check=True)
    subprocess.run(f"cp {EASYRSA_PATH}/pki/crl.pem /etc/openvpn/crl.pem", shell=True, check=True)

# Execute commands on the server
async def execute_command_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    command = update.message.text

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(RASPBERRY_PI_VPN_IP, username=SSH_USERNAME, password=SSH_PASSWORD)

        stdin, stdout, stderr = ssh.exec_command(command)
        result = stdout.read().decode()
        error = stderr.read().decode()
        ssh.close()

        if result:
            await update.message.reply_text(f"✅ <b>Результат виконання:</b>\n{escape(result)}", parse_mode="HTML")
        if error:
            await update.message.reply_text(f"❌ <b>Помилка:</b>\n{escape(error)}", parse_mode="HTML")
    except Exception as e:
        logging.error(f"Error executing command: {e}")
        await update.message.reply_text(f"❌ Помилка при виконанні команди:\n{e}")

    await start(update, context)
    return ConversationHandler.END

# Function to extract and decode Base64 content
def extract_and_decode_base64(file_path, output_path):
    """Extracts and decodes Base64-encoded data from an XML report."""
    import re
    import base64

    # Read XML as text
    with open(file_path, 'r', encoding='utf-8') as file:
        xml_content = file.read()

    # Search for Base64 data between </report_format> and </report>
    base64_pattern = re.search(r'</report_format>([\s\S]*?)</report>', xml_content)

    if base64_pattern:
        base64_data = base64_pattern.group(1).strip()

        try:
            # Decode Base64
            decoded_text = base64.b64decode(base64_data).decode('utf-8')

            # Write decoded text to output file
            with open(output_path, 'w', encoding='utf-8') as output_file:
                output_file.write(decoded_text)

            print("Дані успішно декодовані та записані у файл.")
            return True  # Successfully decoded and written
        except (base64.binascii.Error, UnicodeDecodeError) as e:
            print(f"Помилка декодування Base64: {e}. Перевірте формат даних.")
            return False
    else:
        print("Поле з Base64 не знайдено між </report_format> і </report>.")
        return False

# Function to start OpenVAS scan and send the report
# Function to start OpenVAS scan and send the report
async def start_openvas_scan(update: Update, context: ContextTypes.DEFAULT_TYPE, target: str):
    scan_type = context.user_data.get("scan_type", "full_scan")
    config_name = "Full and fast" if scan_type == "full_scan" else "Host Discovery"

    # Create unique filenames based on time and target
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    safe_target = re.sub(r'[^\w\-_. ]', '_', target)
    base_filename = f"openvas_scan_{safe_target}_{timestamp}"
    xml_filename = f"{base_filename}.xml"
    txt_filename = f"{base_filename}.txt"
    
    # Full paths to files in local directory
    xml_file_path = os.path.join(LOCAL_RESULTS_DIR, xml_filename)
    txt_file_path = os.path.join(LOCAL_RESULTS_DIR, txt_filename)
    
    # Create local directory for results
    os.makedirs(LOCAL_RESULTS_DIR, exist_ok=True)

    try:
        # Connect to OpenVAS
        connection = TLSConnection(hostname=GMP_HOST, port=GMP_PORT)
        transform = EtreeTransform()
        with Gmp(connection, transform=transform) as gmp:
            gmp.authenticate(GMP_USERNAME, GMP_PASSWORD)

            # Get scan configuration
            configs = gmp.get_scan_configs()
            config_id = None
            for config in configs.xpath('.//config'):
                if config.find('name').text == config_name:
                    config_id = config.get('id')
                    break
            if not config_id:
                await update.message.reply_text(f"❌ Не вдалося знайти конфігурацію '{config_name}'.")
                return

            # Get scanner ID for OpenVAS
            scanners = gmp.get_scanners()
            scanner_id = None
            for scanner in scanners.xpath('.//scanner'):
                if "OpenVAS" in scanner.find('name').text:
                    scanner_id = scanner.get('id')
                    break
            if not scanner_id:
                await update.message.reply_text("❌ Не вдалося знайти сканер OpenVAS.")
                return

            # Get port list ID
            port_lists = gmp.get_port_lists()
            port_list_name = 'All TCP and Nmap top 100 UDP'  # Adjust this name as needed
            port_list_id = None
            for port_list in port_lists.xpath('.//port_list'):
                if port_list.find('name').text == port_list_name:
                    port_list_id = port_list.get('id')
                    break
            if not port_list_id:
                await update.message.reply_text(f"❌ Не вдалося знайти порт-лист '{port_list_name}'.")
                return

            # Check if target already exists
            existing_target_id = None
            targets = gmp.get_targets()
            for t in targets.xpath('.//target'):
                if target in t.find('hosts').text:
                    existing_target_id = t.get('id')
                    break

            # Use existing target or create a new one
            if existing_target_id:
                target_id = existing_target_id
                await update.message.reply_text(f"✅ Використовуємо наявну ціль з ID {target_id} для {target}.")
            else:
                target_resp = gmp.create_target(
                    name=f'Target {target}',
                    hosts=[target],
                    port_list_id=port_list_id
                )
                target_id = target_resp.get('id')
                if not target_id:
                    status_text = target_resp.xpath('//@status_text')[0]
                    await update.message.reply_text(f"❌ Не вдалося створити ціль для {target}. Статус: {status_text}")
                    return

            # Create and start the task
            task_resp = gmp.create_task(
                name=f'Task {target}',
                config_id=config_id,
                target_id=target_id,
                scanner_id=scanner_id
            )
            task_id = task_resp.get('id')
            if not task_id:
                await update.message.reply_text(f"❌ Не вдалося створити задачу для цілі {target}.")
                return

            gmp.start_task(task_id)
            await update.message.reply_text(f"✅ Сканування цілі {target} запущено ({config_name}).")

            # Monitor scan progress
            status = ''
            previous_progress = -1
            while status != 'Done':
                await asyncio.sleep(30)
                task = gmp.get_task(task_id=task_id)
                status = task.find('.//status').text
                progress_element = task.find('.//progress')
                if progress_element is not None:
                    progress = int(progress_element.text)
                else:
                    progress = None

                if progress != previous_progress and progress is not None:
                    await update.message.reply_text(f"⏳ Прогрес сканування: {progress}%")
                    previous_progress = progress

            await update.message.reply_text("✅ Сканування завершено. Формуємо звіт...")

            # Get the report in XML format
            report_id = task.find('.//last_report/report').get('id')
            txt_format_id = 'a3810a62-1f62-11e1-9219-406186ea4fc5'  # ID for TXT format
            xml_format_id = 'a994b278-1f62-11e1-96ac-406186ea4fc5'  # ID for XML format

            # Save the report to a local XML file
            report_resp_xml = gmp.get_report(report_id=report_id, report_format_id=xml_format_id)
            with open(xml_file_path, 'wb') as f:
                f.write(etree.tostring(report_resp_xml, pretty_print=True, encoding='utf-8', xml_declaration=True))

            # Get and decode the report in TXT format
            report_resp_txt = gmp.get_report(report_id=report_id, report_format_id=txt_format_id)
            temp_xml_file = f"/tmp/{base_filename}_temp.xml"
            with open(temp_xml_file, 'wb') as f:
                f.write(etree.tostring(report_resp_txt, pretty_print=True, encoding='utf-8', xml_declaration=True))

            # Decode Base64 content and save as a text file
            success = extract_and_decode_base64(temp_xml_file, txt_file_path)
            os.remove(temp_xml_file)  # Remove the temporary file

            if success:
                # Send files to the user
                with open(txt_file_path, 'rb') as f:
                    await update.message.reply_document(f, filename=os.path.basename(txt_file_path))
                with open(xml_file_path, 'rb') as f:
                    await update.message.reply_document(f, filename=os.path.basename(xml_file_path))
            else:
                await update.message.reply_text("❌ Не вдалося витягти та декодувати Base64-контент із XML-звіту.")

            # Upload files to Raspberry Pi
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(RASPBERRY_PI_VPN_IP, username=SSH_USERNAME, password=SSH_PASSWORD)
            ssh.exec_command(f"mkdir -p {OPENVAS_RESULTS_DIR}")  # Ensure directory exists
            with SCPClient(ssh.get_transport()) as scp:
                scp.put(txt_file_path, os.path.join(OPENVAS_RESULTS_DIR, os.path.basename(txt_file_path)))
                scp.put(xml_file_path, os.path.join(OPENVAS_RESULTS_DIR, os.path.basename(xml_file_path)))
            ssh.close()

            # Clean up local files after transfer
            os.remove(txt_file_path)
            os.remove(xml_file_path)

            await update.message.reply_text("✅ Звіти успішно збережені на Raspberry Pi.")

            # Optionally delete the task
            gmp.delete_task(task_id)

    except Exception as e:
        logging.error(f"Error starting OpenVAS scan: {e}")
        await update.message.reply_text(f"❌ Помилка при запуску OpenVAS сканування:\n{e}")

# Handle input for starting OpenVAS scan
async def start_openvas_scan_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    target = update.message.text.strip()
    if target.lower() == "назад":
        return await go_back(update, context)

    logging.info(f"Starting OpenVAS scan on target: {target}")
    await update.message.reply_text(f"⏳ Починаємо OpenVAS сканування цілі: {target}")

    await start_openvas_scan(update, context, target)

    await start(update, context)
    return ConversationHandler.END

# List active clients
async def list_clients_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        index_file = f"{EASYRSA_PATH}/pki/index.txt"
        with open(index_file, 'r') as f:
            lines = f.readlines()

        active_clients = []
        for line in lines:
            if line.startswith('V'):
                parts = line.strip().split('\t')
                if len(parts) >= 6:
                    dn = parts[5]
                    cn = dn.split('CN=')[-1]
                    active_clients.append(cn)

        if active_clients:
            clients_list = '\n'.join(active_clients)
            await update.callback_query.message.reply_text(
                f"👥 <b>Список активних клієнтів:</b>\n{escape(clients_list)}", parse_mode="HTML"
            )
        else:
            await update.callback_query.message.reply_text("⚠ Немає активних клієнтів.")
    except Exception as e:
        logging.error(f"Error listing clients: {e}")
        await update.callback_query.message.reply_text(f"❌ Помилка при отриманні списку клієнтів:\n{e}")

# List scan files on Raspberry Pi
async def list_scans(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        # Initialize file mappings
        context.user_data['file_mappings'] = {}
        file_index = 0

        # Set up SSH connection to Raspberry Pi
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(RASPBERRY_PI_VPN_IP, username=SSH_USERNAME, password=SSH_PASSWORD)

        # Specify paths for OpenVAS and Nmap on Raspberry Pi
        scan_dirs = {"OpenVAS": OPENVAS_RESULTS_DIR, "Nmap": NMAP_RESULTS_DIR}
        files = []

        # Get the list of files for each scan type
        for scan_type, dir_path in scan_dirs.items():
            stdin, stdout, stderr = ssh.exec_command(f"ls {dir_path}")
            dir_files = stdout.read().decode().splitlines()

            # Add files to the list if they exist
            for f in dir_files:
                file_id = str(file_index)
                files.append((file_id, scan_type, f))
                context.user_data['file_mappings'][file_id] = (scan_type, f)
                file_index += 1

        ssh.close()

        # Create keyboard with the files found
        if files:
            keyboard = []
            for file_id, scan_type, file_name in sorted(files):
                display_name = f"{scan_type}: {file_name}"
                keyboard.append([InlineKeyboardButton(display_name, callback_data=file_id)])
            keyboard.append([InlineKeyboardButton("🔙 Назад", callback_data="go_back")])
            reply_markup = InlineKeyboardMarkup(keyboard)
            await update.callback_query.message.reply_text("📄 Виберіть файл для завантаження:", reply_markup=reply_markup)
        else:
            await update.callback_query.message.reply_text("⚠ Немає доступних файлів сканування.")
    except Exception as e:
        logging.error(f"Error listing scans: {e}")
        await update.callback_query.message.reply_text(f"❌ Помилка при отриманні списку сканів:\n{e}")

# Download scan file from Raspberry Pi
async def download_scan(update: Update, context: ContextTypes.DEFAULT_TYPE, file_id: str):
    try:
        if file_id not in context.user_data.get('file_mappings', {}):
            await update.callback_query.message.reply_text("❌ Невідомий файл.")
            return

        scan_type, file_name = context.user_data['file_mappings'][file_id]
        dir_path = OPENVAS_RESULTS_DIR if scan_type == "OpenVAS" else NMAP_RESULTS_DIR
        remote_file_path = os.path.join(dir_path, file_name)

        # Connect to Raspberry Pi via SSH
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(RASPBERRY_PI_VPN_IP, username=SSH_USERNAME, password=SSH_PASSWORD)

        # Download the file from Raspberry Pi
        with SCPClient(ssh.get_transport()) as scp:
            local_file = os.path.basename(remote_file_path)
            scp.get(remote_file_path, local_file)

        # Send the file to the user
        with open(local_file, "rb") as f:
            await update.callback_query.message.reply_document(f, filename=file_name)

        # Close SSH connection and remove local file
        ssh.close()
        os.remove(local_file)

    except Exception as e:
        logging.error(f"Error downloading scan: {e}")
        await update.callback_query.message.reply_text(f"❌ Помилка при завантаженні файлу:\n{e}")

    await start(update, context)

# Function to start Nmap scan via SSH on Raspberry Pi
async def start_nmap_scan(update: Update, context: ContextTypes.DEFAULT_TYPE, target: str):
    nmap_scan_type = context.user_data.get("nmap_scan_type", "full")
    safe_target = re.sub(r'[^\w\-_. ]', '_', target)

    # Create unique filename based on time and target
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    base_filename = f"nmap_scan_{safe_target}_{timestamp}.txt"
    remote_file_path = os.path.join(NMAP_RESULTS_DIR, base_filename)

    # Select scan options
    if nmap_scan_type == "quick":
        scan_options = "-T4 -F"
    else:  # full scan
        scan_options = "-A -T4"

    try:

        # Connect to Raspberry Pi via SSH
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(RASPBERRY_PI_VPN_IP, username=SSH_USERNAME, password=SSH_PASSWORD)

        # Ensure the results directory exists
        stdin, stdout, stderr = ssh.exec_command(f"mkdir -p {NMAP_RESULTS_DIR}")
        stderr_output = stderr.read().decode()
        if stderr_output:
            logging.error(f"Error creating directory on Raspberry Pi: {stderr_output}")

        # Execute Nmap command on Raspberry Pi
        command = f"nmap {scan_options} {target} -oN {remote_file_path}"
        stdin, stdout, stderr = ssh.exec_command(command)

        # Wait for the scan to complete
        exit_status = stdout.channel.recv_exit_status()
        if exit_status != 0:
            error_output = stderr.read().decode()
            await update.message.reply_text(f"❌ Помилка при виконанні Nmap сканування:\n{error_output}")
            ssh.close()
            return

        # Download the scan result
        sftp = ssh.open_sftp()
        local_file = os.path.basename(remote_file_path)
        sftp.get(remote_file_path, local_file)
        sftp.close()
        ssh.close()

        # Send the scan result to the user
        with open(local_file, 'rb') as f:
            await update.message.reply_document(f, filename=local_file)

        # Remove the local file
        os.remove(local_file)

        await update.message.reply_text(f"✅ Nmap сканування цілі {target} завершено.")

    except Exception as e:
        logging.error(f"Error starting Nmap scan: {e}")
        await update.message.reply_text(f"❌ Помилка при запуску Nmap сканування:\n{e}")

# Handle input for starting Nmap scan
async def start_nmap_scan_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    target = update.message.text.strip()
    if target.lower() == "назад":
        return await go_back(update, context)

    logging.info(f"Starting Nmap scan on target: {target}")
    await update.message.reply_text(f"⏳ Починаємо Nmap сканування цілі: {target}")

    await start_nmap_scan(update, context, target)

    await start(update, context)
    return ConversationHandler.END

# Main function to run the bot
def main():
    application = ApplicationBuilder().token(TOKEN).build()

    conv_handler = ConversationHandler(
        entry_points=[
            CommandHandler("start", start),
            CallbackQueryHandler(button_handler),
        ],
        states={
            ADDING_CLIENT: [MessageHandler(filters.TEXT & ~filters.COMMAND, add_client_input)],
            REMOVING_CLIENT: [MessageHandler(filters.TEXT & ~filters.COMMAND, remove_client_input)],
            EXECUTING_COMMAND: [MessageHandler(filters.TEXT & ~filters.COMMAND, execute_command_input)],
            DOWNLOADING_FILE: [MessageHandler(filters.TEXT & ~filters.COMMAND, download_by_path_input)],
            STARTING_OPENVAS_SCAN: [MessageHandler(filters.TEXT & ~filters.COMMAND, start_openvas_scan_input)],
            CHOOSING_SCAN_TYPE: [CallbackQueryHandler(button_handler)],
            CHOOSING_NMAP_SCAN_TYPE: [CallbackQueryHandler(button_handler)],
            STARTING_NMAP_SCAN: [MessageHandler(filters.TEXT & ~filters.COMMAND, start_nmap_scan_input)],
        },
        fallbacks=[CallbackQueryHandler(go_back)],
    )

    application.add_handler(conv_handler)
    application.run_polling()

if __name__ == "__main__":
    main()
