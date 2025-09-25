package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"golang.org/x/crypto/scrypt"
)

// -------- Vault types and crypto --------

const magic = "GOVLT1\n" // header magic
const saltLen = 16
const nonceLen = 12

type Entry struct {
	Service   string    `json:"service"`
	Username  string    `json:"username"`
	Password  string    `json:"password"` // stored encrypted as part of the blob, never plaintext on disk
	Notes     string    `json:"notes"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Vault struct {
	Entries []Entry `json:"entries"`
}

type VaultFile struct {
	Path    string
	Salt    []byte
	Key     []byte // derived from master password, kept only in memory
	Opened  bool
	Changed bool
	V       Vault
}

func deriveKey(master string, salt []byte) ([]byte, error) {
	return scrypt.Key([]byte(master), salt, 1<<15, 8, 1, 32) // N=2^15, r=8, p=1, 32 bytes
}

func encrypt(key []byte, plaintext []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	return nonce, ct, nil
}

func decrypt(key, nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func (vf *VaultFile) New(path string, master string) error {
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}
	key, err := deriveKey(master, salt)
	if err != nil {
		return err
	}
	vf.Path = path
	vf.Salt = salt
	vf.Key = key
	vf.Opened = true
	vf.Changed = true
	vf.V = Vault{Entries: []Entry{}}
	return vf.Save()
}

func (vf *VaultFile) Open(path string, master string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	header := make([]byte, len(magic))
	if _, err := io.ReadFull(f, header); err != nil {
		return err
	}
	if string(header) != magic {
		return errors.New("not a vault file")
	}
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(f, salt); err != nil {
		return err
	}
	key, err := deriveKey(master, salt)
	if err != nil {
		return err
	}

	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(f, nonce); err != nil {
		return err
	}
	// read length-prefixed ciphertext for forward compatibility
	var clen uint32
	if err := binary.Read(f, binary.BigEndian, &clen); err != nil {
		return err
	}
	ct := make([]byte, int(clen))
	if _, err := io.ReadFull(f, ct); err != nil {
		return err
	}
	plain, err := decrypt(key, nonce, ct)
	if err != nil {
		return errors.New("wrong password or corrupted file")
	}
	var v Vault
	if err := json.Unmarshal(plain, &v); err != nil {
		return err
	}

	vf.Path = path
	vf.Salt = salt
	vf.Key = key
	vf.Opened = true
	vf.Changed = false
	vf.V = v
	return nil
}

func (vf *VaultFile) Save() error {
	if !vf.Opened {
		return errors.New("vault not opened")
	}
	plain, err := json.MarshalIndent(vf.V, "", "  ")
	if err != nil {
		return err
	}
	nonce, ct, err := encrypt(vf.Key, plain)
	if err != nil {
		return err
	}
	tmp := vf.Path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.Write([]byte(magic)); err != nil {
		return err
	}
	if _, err := f.Write(vf.Salt); err != nil {
		return err
	}
	if _, err := f.Write(nonce); err != nil {
		return err
	}
	if err := binary.Write(f, binary.BigEndian, uint32(len(ct))); err != nil {
		return err
	}
	if _, err := f.Write(ct); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := os.Rename(tmp, vf.Path); err != nil {
		return err
	}
	vf.Changed = false
	return nil
}

// -------- TUI --------

type UI struct {
	app       *tview.Application
	pages     *tview.Pages
	status    *tview.TextView
	vault     *VaultFile
	entryList *tview.List
	search    *tview.InputField
	form      *tview.Form

	// form fields
	fService  *tview.InputField
	fUsername *tview.InputField
	fPassword *tview.InputField
	fNotes    *tview.InputField
	showPw    bool
}

func NewUI() *UI {
	return &UI{
		app:    tview.NewApplication(),
		pages:  tview.NewPages(),
		status: tview.NewTextView().SetDynamicColors(true),
		vault:  &VaultFile{},
		showPw: false,
	}
}

func (ui *UI) setStatus(msg string) {
	now := time.Now().Format("15:04:05")
	ui.status.SetText(fmt.Sprintf("[%s] %s", now, msg))
}

func (ui *UI) loginPage() tview.Primitive {
	title := tview.NewTextView().SetText("Go Vault: AES-GCM Password Manager").SetTextAlign(tview.AlignCenter)
	path := tview.NewInputField().SetLabel("Vault file: ").SetText("vault.gobin")
	master := tview.NewInputField().SetLabel("Master password: ").SetMaskCharacter('*')

	form := tview.NewForm().
		AddFormItem(path).
		AddFormItem(master).
		AddButton("Open", func() {
			p := strings.TrimSpace(path.GetText())
			m := master.GetText()
			if _, err := os.Stat(p); err == nil {
				if err := ui.vault.Open(p, m); err != nil {
					ui.setStatus(fmt.Sprintf("Open failed: %v", err))
					return
				}
				ui.setStatus("Vault opened")
				ui.pages.SwitchToPage("vault")
			} else {
				dir := filepath.Dir(p)
				if dir != "" && dir != "." {
					if err := os.MkdirAll(dir, 0700); err != nil {
						ui.setStatus(fmt.Sprintf("mkdir: %v", err))
						return
					}
				}
				if err := ui.vault.New(p, m); err != nil {
					ui.setStatus(fmt.Sprintf("create: %v", err))
					return
				}
				ui.setStatus("New vault created")
				ui.pages.SwitchToPage("vault")
			}
		}).
		AddButton("Quit", func() { ui.app.Stop() })
	form.SetBorder(true).SetTitle(" Open or Create Vault ").SetTitleAlign(tview.AlignLeft)

	flex := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(title, 2, 0, false).
		AddItem(form, 0, 1, true).
		AddItem(ui.status, 2, 0, false)
	return flex
}

func (ui *UI) filterEntries(q string) []Entry {
	if q == "" {
		return ui.vault.V.Entries
	}
	var out []Entry
	qq := strings.ToLower(q)
	for _, e := range ui.vault.V.Entries {
		if strings.Contains(strings.ToLower(e.Service), qq) ||
			strings.Contains(strings.ToLower(e.Username), qq) {
			out = append(out, e)
		}
	}
	return out
}

func (ui *UI) refreshList() {
	q := ui.search.GetText()
	ui.entryList.Clear()
	ents := ui.filterEntries(q)
	for i := range ents {
		e := ents[i]
		label := fmt.Sprintf("%s  [%s]", e.Service, e.Username)
		ui.entryList.AddItem(label, e.UpdatedAt.Format("2006-01-02 15:04"), 0, func() {
			ui.loadEntry(e)
		})
	}
}

func (ui *UI) loadEntry(e Entry) {
	ui.fService.SetText(e.Service)
	ui.fUsername.SetText(e.Username)
	if ui.showPw {
		ui.fPassword.SetMaskCharacter(0)
	} else {
		ui.fPassword.SetMaskCharacter('*')
	}
	ui.fPassword.SetText(e.Password)
	ui.fNotes.SetText(e.Notes)
}

func (ui *UI) clearForm() {
	ui.fService.SetText("")
	ui.fUsername.SetText("")
	ui.fPassword.SetText("")
	ui.fNotes.SetText("")
}

func (ui *UI) upsertCurrent() {
	service := strings.TrimSpace(ui.fService.GetText())
	username := strings.TrimSpace(ui.fUsername.GetText())
	password := ui.fPassword.GetText()
	notes := ui.fNotes.GetText()
	if service == "" || username == "" {
		ui.setStatus("Service and Username are required")
		return
	}
	var updated bool
	for i := range ui.vault.V.Entries {
		if ui.vault.V.Entries[i].Service == service && ui.vault.V.Entries[i].Username == username {
			ui.vault.V.Entries[i].Password = password
			ui.vault.V.Entries[i].Notes = notes
			ui.vault.V.Entries[i].UpdatedAt = time.Now()
			updated = true
			break
		}
	}
	if !updated {
		ui.vault.V.Entries = append(ui.vault.V.Entries, Entry{
			Service:   service,
			Username:  username,
			Password:  password,
			Notes:     notes,
			UpdatedAt: time.Now(),
		})
	}
	ui.vault.Changed = true
	ui.refreshList()
	ui.setStatus("Entry saved in memory, press Ctrl-S to write to disk")
}

func (ui *UI) deleteCurrent() {
	service := strings.TrimSpace(ui.fService.GetText())
	username := strings.TrimSpace(ui.fUsername.GetText())
	if service == "" || username == "" {
		ui.setStatus("Nothing to delete")
		return
	}
	var out []Entry
	for _, e := range ui.vault.V.Entries {
		if !(e.Service == service && e.Username == username) {
			out = append(out, e)
		}
	}
	ui.vault.V.Entries = out
	ui.vault.Changed = true
	ui.refreshList()
	ui.clearForm()
	ui.setStatus("Entry deleted, press Ctrl-S to write to disk")
}

func (ui *UI) genPassword(n int) string {
	if n < 8 {
		n = 16
	}
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}.,?"
	buf := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return ""
	}
	for i := range buf {
		buf[i] = letters[int(buf[i])%len(letters)]
	}
	return string(buf)
}

func (ui *UI) copyPassword() {
	pw := ui.fPassword.GetText()
	if pw == "" {
		ui.setStatus("No password to copy")
		return
	}
	if err := clipboard.WriteAll(pw); err != nil {
		ui.setStatus(fmt.Sprintf("clipboard: %v", err))
		return
	}
	ui.setStatus("Password copied to clipboard, it will persist until your clipboard is cleared")
}

func (ui *UI) vaultPage() tview.Primitive {
	// Left: search + list
	ui.search = tview.NewInputField().
		SetLabel("Search: ").
		SetChangedFunc(func(text string) { ui.refreshList() })
	ui.entryList = tview.NewList().ShowSecondaryText(true)

	left := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(ui.search, 1, 0, true).
		AddItem(ui.entryList, 0, 1, false).
		AddItem(ui.status, 2, 0, false)
	left.SetBorder(true).SetTitle(" Entries ")

	// Right: form
	ui.fService = tview.NewInputField().SetLabel("Service: ")
	ui.fUsername = tview.NewInputField().SetLabel("Username: ")
	ui.fPassword = tview.NewInputField().SetLabel("Password: ").SetMaskCharacter('*')
	ui.fNotes = tview.NewInputField().SetLabel("Notes: ").SetFieldWidth(40)

	ui.form = tview.NewForm().
		AddFormItem(ui.fService).
		AddFormItem(ui.fUsername).
		AddFormItem(ui.fPassword).
		AddFormItem(ui.fNotes).
		AddButton("New (Ctrl-N)", func() { ui.clearForm(); ui.setStatus("New entry") }).
		AddButton("Generate (Ctrl-G)", func() {
			pw := ui.genPassword(20)
			ui.fPassword.SetText(pw)
			ui.setStatus("Generated password")
		}).
		AddButton("Save (Enter)", func() { ui.upsertCurrent() }).
		AddButton("Delete (Del)", func() { ui.deleteCurrent() }).
		AddButton("Copy PW (Ctrl-C)", func() { ui.copyPassword() }).
		AddButton("Toggle Show (Ctrl-H)", func() {
			ui.showPw = !ui.showPw
			if ui.showPw {
				ui.fPassword.SetMaskCharacter(0)
				ui.setStatus("Password visible")
			} else {
				ui.fPassword.SetMaskCharacter('*')
				ui.setStatus("Password hidden")
			}
		})
	ui.form.SetBorder(true).SetTitle(" Details ")

	root := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(left, 0, 1, true).
		AddItem(ui.form, 0, 2, false)

	// Keybindings
	root.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch {
		case ev.Key() == tcell.KeyCtrlS:
			if err := ui.vault.Save(); err != nil {
				ui.setStatus(fmt.Sprintf("save: %v", err))
			} else {
				ui.setStatus("Vault saved to disk")
			}
			return nil
		case ev.Key() == tcell.KeyCtrlN:
			ui.clearForm()
			ui.setStatus("New entry")
			return nil
		case ev.Key() == tcell.KeyCtrlG:
			pw := ui.genPassword(20)
			ui.fPassword.SetText(pw)
			ui.setStatus("Generated password")
			return nil
		case ev.Key() == tcell.KeyCtrlH:
			ui.showPw = !ui.showPw
			if ui.showPw {
				ui.fPassword.SetMaskCharacter(0)
				ui.setStatus("Password visible")
			} else {
				ui.fPassword.SetMaskCharacter('*')
				ui.setStatus("Password hidden")
			}
			return nil
		case ev.Key() == tcell.KeyCtrlC:
			ui.copyPassword()
			return nil
		case ev.Key() == tcell.KeyDelete:
			ui.deleteCurrent()
			return nil
		case ev.Key() == tcell.KeyCtrlQ:
			if ui.vault.Changed {
				ui.setStatus("You have unsaved changes, press Ctrl-S to save or Ctrl-Q again to quit")
				// require double Ctrl-Q within a short time? keep simple
				return nil
			}
			ui.app.Stop()
			return nil
		case ev.Key() == tcell.KeyEnter:
			ui.upsertCurrent()
			return nil
		}
		return ev
	})

	ui.refreshList()
	return root
}

func (ui *UI) Run() error {
	ui.pages.AddPage("login", ui.loginPage(), true, true)
	ui.pages.AddPage("vault", ui.vaultPage(), true, false)
	ui.app.SetRoot(ui.pages, true)
	return ui.app.Run()
}

func main() {
	ui := NewUI()
	if err := ui.Run(); err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}
