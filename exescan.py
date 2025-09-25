import os 
import hashlib
import shutil
import time
import sys
import zipfile
import rarfile
import py7zr
import tarfile
import lzma  # Needed to catch LZMAError
from tabulate import tabulate
from colorama import Fore, Style, init

# Function to create ANSI color codes
def color_text(text, color_name):
    color_map = {
        "red": "\033[91m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "cyan": "\033[96m",
        "green": "\033[92m",
        "magenta": "\033[95m",
        "reset": "\033[0m"
    }
    return f"{color_map.get(color_name, '')}{text}{color_map['reset']}"

# ASCII Banner with Colors
BANNER = f"""{Fore.RED}
___________               _________                      
\\_   _____/__  ___ ____  /   _____/ ____ _____    ____   
 |    __)_\\  \\/  // __ \\ \\_____  \\_/ ___\\\\__  \\  /    \\  
 |        \\>    <\\  ___/ /        \\  \\___ / __ \\|   |  \\ 
/_______  /__/\\_ \\\\___  >_______  /\\___  >____  /___|  / 
        \\/      \\/    \\/        \\/     \\/     \\/     \\/  
{Fore.YELLOW}---------------------------------------------------------
        {Fore.BLUE}EXESCAN - Advanced File Scanner
{Fore.YELLOW}---------------------------------------------------------
"""

def typewriter_effect(text, delay=0.02, fast=False):
    """Displays text with a typewriter effect. Faster for banners."""
    speed = 0.01 if fast else delay
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(speed)
    print()

#########################
# For files on disk:
#########################

def calculate_hash(file_path, algo):
    """Calculate MD5, SHA1, or SHA256 hash of a given file on disk."""
    if algo == 'md5':
        hash_func = hashlib.md5()
    elif algo == 'sha1':
        hash_func = hashlib.sha1()
    elif algo == 'sha256':
        hash_func = hashlib.sha256()
    else:
        raise ValueError("Unsupported algorithm")
    
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            hash_func.update(chunk)
    
    return hash_func.hexdigest()

def process_file(file_path, virus_folder, results, serial_no):
    """Process a file on disk: compute hashes, check databases, and log results."""
    file_name = os.path.basename(file_path)
    file_ext = os.path.splitext(file_name)[1].lower()
    exec_exts = {'.exe', '.apk', '.bat', '.com', '.cmd', '.bin', '.cpl'}

    if file_ext not in exec_exts:
        typewriter_effect(color_text(f"\n Warning: Skipping non-executable file: {file_name}", "red"))
        return

    typewriter_effect(color_text(f"\n[Processing] {file_name}", "cyan"))
    start_time = time.time()

    md5_hash = calculate_hash(file_path, 'md5')
    time.sleep(1)
    typewriter_effect(color_text(f"MD5   : {md5_hash}", "magenta"))

    sha1_hash = calculate_hash(file_path, 'sha1')
    time.sleep(1)
    typewriter_effect(color_text(f"SHA1  : {sha1_hash}", "blue"))

    sha256_hash = calculate_hash(file_path, 'sha256')
    time.sleep(1)
    typewriter_effect(color_text(f"SHA256: {sha256_hash}", "green"))

    # Define hash database file paths using absolute paths
    md5_paths = [f"\\database\\md5\\md5_hashes_{i}.txt" for i in range(1, 13)]
    sha1_paths = [f"\\database\\sha1\\sha1_hashes_{i}.txt" for i in range(1, 8)]
    sha256_paths = [f"\\database\\sha256\\sha256_hashes_{i}.txt" for i in range(1, 8)]
    idx_path = "\\database\\idx_hash.txt"

    # Added comparison log messages
    typewriter_effect(color_text("Comparing file MD5 hash with our database MD5 hashes...", "cyan"))
    typewriter_effect(color_text("Comparing file SHA1 hash with our database SHA1 hashes...", "cyan"))
    typewriter_effect(color_text("Comparing file SHA256 hash with our database SHA256 hashes...", "cyan"))

    md5_match = check_against_database(md5_hash, md5_paths + [idx_path])
    sha1_match = check_against_database(sha1_hash, sha1_paths + [idx_path])
    sha256_match = check_against_database(sha256_hash, sha256_paths + [idx_path])

    match_count = sum([md5_match, sha1_match, sha256_match])
    match_percentage = (match_count / 3) * 100
    time_taken = time.time() - start_time

    if match_count > 0:
        status = color_text("MALWARE", "red")
        os.makedirs(virus_folder, exist_ok=True)
        shutil.move(file_path, os.path.join(virus_folder, file_name))
        typewriter_effect(color_text(f"[ALERT] Malware Detected: {file_name} -> Moved to {virus_folder}", "red"))
    else:
        status = color_text("SAFE", "green")
        typewriter_effect(color_text(f"[SAFE] {file_name} is clean.", "green"))

    typewriter_effect(color_text(f"[MATCH PERCENTAGE]: {match_percentage:.2f}%", "blue"))
    typewriter_effect(color_text(f"[TIME TAKEN]: {time_taken:.4f} seconds", "yellow"))
    results.append([serial_no, file_name, file_ext, status, f"{match_percentage:.2f}%", f"{time_taken:.4f} sec"])

#############################
# For files from archives:
#############################

def calculate_hash_from_bytes(file_bytes, algo):
    """Calculate MD5, SHA1, or SHA256 hash from in-memory file data (bytes)."""
    # If file_bytes is not a bytes object, try reading its contents.
    if not isinstance(file_bytes, bytes):
        try:
            file_bytes = file_bytes.read()
        except Exception as e:
            raise TypeError("object supporting the buffer API required") from e

    if algo == 'md5':
        hash_func = hashlib.md5()
    elif algo == 'sha1':
        hash_func = hashlib.sha1()
    elif algo == 'sha256':
        hash_func = hashlib.sha256()
    else:
        raise ValueError("Unsupported algorithm")
    
    hash_func.update(file_bytes)
    return hash_func.hexdigest()

def process_archive_file(file_name, file_data, virus_folder, results, serial_no):
    """Process a file from an archive using its name and bytes data."""
    # If file_data is not a bytes object, convert it to bytes.
    if not isinstance(file_data, bytes):
        file_data = file_data.read()

    file_ext = os.path.splitext(file_name)[1].lower()
    exec_exts = {'.exe', '.apk', '.bat', '.com', '.cmd', '.bin', '.cpl'}

    if file_ext not in exec_exts:
        typewriter_effect(color_text(f"\n Warning: Skipping non-executable file: {file_name}", "yellow"))
        return

    typewriter_effect(color_text(f"\n[Processing] {file_name} (from archive)", "cyan"))
    start_time = time.time()

    md5_hash = calculate_hash_from_bytes(file_data, 'md5')
    time.sleep(1)
    typewriter_effect(color_text(f"MD5   : {md5_hash}", "magenta"))

    sha1_hash = calculate_hash_from_bytes(file_data, 'sha1')
    time.sleep(1)
    typewriter_effect(color_text(f"SHA1  : {sha1_hash}", "blue"))

    sha256_hash = calculate_hash_from_bytes(file_data, 'sha256')
    time.sleep(1)
    typewriter_effect(color_text(f"SHA256: {sha256_hash}", "green"))

    # Define hash database file paths using absolute paths
    md5_paths = [f"database\\md5\\md5_hashes_{i}.txt" for i in range(1, 13)]
    sha1_paths = [f"database\\sha1\\sha1_hashes_{i}.txt" for i in range(1, 8)]
    sha256_paths = [f"database\\sha256\\sha256_hashes_{i}.txt" for i in range(1, 8)]
    idx_path = "database\\idx_hash.txt"

    # Added comparison log messages
    typewriter_effect(color_text("Comparing file MD5 hash with our database MD5 hashes...", "cyan"))
    typewriter_effect(color_text("Comparing file SHA1 hash with our database SHA1 hashes...", "cyan"))
    typewriter_effect(color_text("Comparing file SHA256 hash with our database SHA256 hashes...", "cyan"))

    md5_match = check_against_database(md5_hash, md5_paths + [idx_path])
    sha1_match = check_against_database(sha1_hash, sha1_paths + [idx_path])
    sha256_match = check_against_database(sha256_hash, sha256_paths + [idx_path])

    match_count = sum([md5_match, sha1_match, sha256_match])
    match_percentage = (match_count / 3) * 100
    time_taken = time.time() - start_time

    if match_count > 0:
        status = color_text("MALWARE", "red")
        os.makedirs(virus_folder, exist_ok=True)
        # Write the file data to disk in the virus folder
        with open(os.path.join(virus_folder, file_name), 'wb') as f:
            f.write(file_data)
        typewriter_effect(color_text(f"[ALERT] Malware Detected: {file_name} -> Saved to {virus_folder}", "red"))
    else:
        status = color_text("SAFE", "green")
        typewriter_effect(color_text(f"[SAFE] {file_name} is clean.", "green"))

    typewriter_effect(color_text(f"[MATCH PERCENTAGE]: {match_percentage:.2f}%", "yellow"))
    typewriter_effect(color_text(f"[TIME TAKEN]: {time_taken:.4f} seconds", "yellow"))
    results.append([serial_no, file_name, file_ext, status, f"{match_percentage:.2f}%", f"{time_taken:.4f} sec"])

def check_against_database(file_hash, db_paths):
    """Check if the computed file hash exists in any database file."""
    for db_path in db_paths:
        if os.path.exists(db_path):
            with open(db_path, 'r', encoding='utf-8') as f:
                # Compare each line for an exact match after stripping whitespace and converting to lowercase
                for line in f:
                    if file_hash.strip().lower() == line.strip().lower():
                        return True
    return False

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    typewriter_effect(BANNER, fast=True)

def main():
    typewriter_effect(color_text("EXESCAN Launching...", "yellow"), delay=0.05)
    time.sleep(2)
    clear_screen()
    typewriter_effect(BANNER, fast=True)
    
    # Get the user input
    folder_or_file = input(color_text("\nEnter file or folder path: ", "cyan")).strip()

    # If the string starts with an ampersand, remove it and then strip again
    if folder_or_file.startswith("&"):
         folder_or_file = folder_or_file[1:].strip()

    # Remove any surrounding single or double quotes
    folder_or_file = folder_or_file.strip("'\"")

    typewriter_effect("Processed path: " + folder_or_file)

    virus_folder = "database\\infected_files"
    results = []
    serial_no = 1

    if os.path.isfile(folder_or_file):
        file_ext = os.path.splitext(folder_or_file)[1].lower()
        if file_ext in ['.zip', '.rar', '.7z', '.tar']:  # Archive file
            extract_and_scan_archive(folder_or_file, virus_folder, results)
        else:
            process_file(folder_or_file, virus_folder, results, serial_no)
    elif os.path.isdir(folder_or_file):  # Folder: process all files on disk
        for root, _, files in os.walk(folder_or_file):
            for file in files:
                file_path = os.path.join(root, file)
                # NEW FEATURE: Check if the file is an archive and process it accordingly
                file_ext = os.path.splitext(file_path)[1].lower()
                if file_ext in ['.zip', '.rar', '.7z', '.tar']:
                    extract_and_scan_archive(file_path, virus_folder, results)
                else:
                    process_file(file_path, virus_folder, results, serial_no)
                serial_no += 1

    if results:
        typewriter_effect(color_text("\n[FINAL RESULT TABLE]", "cyan"))
        # Print the table normally without the typewriter effect
        print(tabulate(results, headers=["S.No", "File Name", "Type", "Status", "Match %", "Time Taken"], tablefmt="grid"))

def extract_and_scan_archive(archive_path, virus_folder, results):
    serial_no = 1
    try:
        file_ext = os.path.splitext(archive_path)[1].lower()
        # ZIP file handling
        if file_ext == '.zip':
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                # Check for password protection
                try:
                    # Try reading the first file without a password
                    zip_ref.read(zip_ref.namelist()[0])
                    password_required = False
                except RuntimeError:
                    password_required = True

                if password_required:
                    typewriter_effect(color_text(f"\n[INFO] ZIP file is password protected. Please enter the password.", "yellow"))
                    while True:
                        password = input(color_text("Enter Password: ", "cyan"))
                        try:
                            zip_ref.setpassword(password.encode())
                            # Test by trying to read a file
                            zip_ref.read(zip_ref.namelist()[0])
                            typewriter_effect(color_text("[INFO] Password correct. Scanning...", "cyan"))
                            break
                        except RuntimeError:
                            typewriter_effect(color_text("[ERROR] Incorrect password. Please try again.", "red"))
                else:
                    typewriter_effect(color_text(f"\n[INFO] Scanning ZIP contents.", "cyan"))

                for file_name in zip_ref.namelist():
                    file_data = zip_ref.read(file_name)
                    process_archive_file(file_name, file_data, virus_folder, results, serial_no)
                    serial_no += 1

        # RAR file handling
        elif file_ext == '.rar':
            with rarfile.RarFile(archive_path, 'r') as rar_ref:
                if rar_ref.needs_password():
                    typewriter_effect(color_text(f"\n[INFO] RAR file is password protected. Please enter the password.", "yellow"))
                    while True:
                        password = input(color_text("Enter Password: ", "cyan"))
                        try:
                            rar_ref.setpassword(password)
                            # Test reading first file
                            rar_ref.read(rar_ref.namelist()[0])
                            typewriter_effect(color_text("[INFO] Password correct. Scanning...", "cyan"))
                            break
                        except rarfile.BadRarFile:
                            typewriter_effect(color_text("[ERROR] Incorrect password. Please try again.", "red"))
                else:
                    typewriter_effect(color_text(f"\n[INFO] Scanning RAR contents.", "cyan"))

                for file_name in rar_ref.namelist():
                    file_data = rar_ref.read(file_name)
                    process_archive_file(file_name, file_data, virus_folder, results, serial_no)
                    serial_no += 1

        # 7z file handling with password support fix
        elif file_ext == '.7z':
            password = None
            # Open the archive initially without a password
            with py7zr.SevenZipFile(archive_path, mode='r') as z:
                if z.needs_password():
                    typewriter_effect(color_text(f"\n[INFO] 7Z file is password protected. Please enter the password.", "yellow"))
                    while True:
                        p = input(color_text("Enter Password: ", "cyan"))
                        try:
                            with py7zr.SevenZipFile(archive_path, mode='r', password=p) as z_test:
                                names = z_test.getnames()
                                _ = z_test.read([names[0]])
                            typewriter_effect(color_text("[INFO] Password correct. Scanning...", "cyan"))
                            password = p
                            break
                        except (py7zr.exceptions.Bad7zFile, lzma.LZMAError):
                            typewriter_effect(color_text("[ERROR] Incorrect password or corrupt data. Please try again.", "red"))
                else:
                    typewriter_effect(color_text(f"\n[INFO] Scanning 7Z contents.", "cyan"))
            # Re-open the archive with password if needed
            if password:
                with py7zr.SevenZipFile(archive_path, mode='r', password=password) as z:
                    for file_name in z.getnames():
                        data_dict = z.read([file_name])
                        file_data = data_dict[file_name]
                        process_archive_file(file_name, file_data, virus_folder, results, serial_no)
                        serial_no += 1
            else:
                with py7zr.SevenZipFile(archive_path, mode='r') as z:
                    for file_name in z.getnames():
                        data_dict = z.read([file_name])
                        file_data = data_dict[file_name]
                        process_archive_file(file_name, file_data, virus_folder, results, serial_no)
                        serial_no += 1

        # TAR file handling
        elif file_ext == '.tar':
            with tarfile.open(archive_path, 'r') as tar_ref:
                typewriter_effect(color_text(f"\n[INFO] Scanning TAR contents.", "cyan"))
                for file_name in tar_ref.getnames():
                    f = tar_ref.extractfile(file_name)
                    if f is not None:
                        file_data = f.read()
                        process_archive_file(file_name, file_data, virus_folder, results, serial_no)
                        serial_no += 1

        else:
            typewriter_effect(color_text(f"\n[ERROR] Unsupported file format: {archive_path}", "red"))
            return

    except (zipfile.BadZipFile, rarfile.Error, py7zr.exceptions.Bad7zFile, tarfile.TarError) as e:
        typewriter_effect(color_text(f"\n[ERROR] Failed to open {archive_path}: {str(e)}", "red"))

if __name__ == "__main__":
    main()
