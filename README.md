# GoPasswordManager (go-passmgr-tui)

A small terminal UI password manager written in Go. All secrets are encrypted with AES‑GCM using a key derived from your master password via scrypt. The vault is a single file, portable across platforms.

> Use a strong master password, store backups of your vault file, and keep your system secure. If you forget the master password there is no recovery.


## Requirements

- Go 1.22 or newer

## Dependencies

- github.com/atotto/clipboard
- github.com/gdamore/tcell/v2
- github.com/rivo/tview
- golang.org/x/crypto/scrypt

## Features

- Single encrypted vault file with a short header and AES‑GCM ciphertext
- scrypt key derivation (N=2^15, r=8, p=1) for resistance to brute force
- TUI with search, add, edit, delete, copy to clipboard, and password generator
- No external database, easy to sync as one file


## Build

```bash
git clone https://github.com/devzephyr/GoPasswordManager.git
cd GoPasswordManager
go build -o myapp
```

## Run

```bash
./myapp
```

Or run directly (without building):

```bash
go run .
```


## Usage


- On launch, enter a vault file path and a master password. If the file does not exist, the app creates it.
- The search field filters by service or username.
- Fields: Service, Username, Password, Notes
- Keyboard shortcuts:
  - New entry: Ctrl‑N
  - Generate password: Ctrl‑G
  - Save entry: Enter
  - Delete entry: Del
  - Copy password to clipboard: Ctrl‑C
  - Toggle password visibility: Ctrl‑H
  - Save vault to disk: Ctrl‑S
  - Quit: Ctrl‑Q


## File Format

```
magic:    "GOVLT1\n"        // 7 bytes
salt:     16 bytes
nonce:    12 bytes
length:   4 bytes big‑endian ciphertext length
payload:  AES‑GCM ciphertext of JSON blob
```


The JSON blob contains an array of entries with service, username, password, notes, and updated_at. All of it is encrypted.


## Security Notes


- AES‑GCM provides confidentiality and integrity. Do not edit the vault file by hand.
- scrypt parameters are set for a balance between security and responsiveness on consumer laptops.
- Clipboard contents persist until you clear them. Do not copy secrets on shared machines.
- There is no master password recovery by design. Keep backups.

## License

MIT
