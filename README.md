# Lock POP
lockpop is a simple, multi-process brute-force tool for cracking KeePass .kdbx databases using a password wordlist — with optional support for keyfiles. It’s useful for testing, password strength audits, or recovering access to a lost database.

# Features
- Brute-forces password-only or password+keyfile protected KeePass databases
- Uses multiprocessing for fast parallel cracking
- Auto-adjusts thread count to available CPU cores
- Optional entry dump on successful unlock
- Clean, readable CLI output

# Requirements
- Python 3.7+
- pykeepass, install via pip:
```bash
pip install pykeepass
```

# Usage
```bash
python lockpop.py -d vault.kdbx -w wordlist.txt [options]
```
Required:
- -d, --database — Path to the KeePass .kdbx file
- -w, --wordlist — Path to a file with passwords (one per line)

Optional:
- -k, --keyfile — Keyfile path if the database requires one
- -o, --output — If the vault is cracked, print all entries
- -f, --outfile — Write dumped entries to a file instead of stdout
- -t, --threads — Number of processes to run in parallel (default = all cores)

# Example
```bash
python lockpop.py -d myvault.kdbx -w rockyou.txt -k my.key -o -f cracked.txt -t 4
```
This will:
- Attempt to unlock myvault.kdbx
- Use rockyou.txt as the password list
- Provide my.key as a keyfile
- Dump the unlocked entries into cracked.txt
- Use 4 CPU cores to speed things up
