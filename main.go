package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/term"
)

const (
	DB_PATH = "encrypted.db"
)

type Entry struct {
	Login    string
	Password string
}

func main() {
	putCmd := flag.NewFlagSet("put", flag.ExitOnError)
	getCmd := flag.NewFlagSet("get", flag.ExitOnError)

	if len(os.Args) < 2 {
		fmt.Println("put or get subcommand is required")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "put":
		putCmd.Parse(os.Args[2:])
	case "get":
		getCmd.Parse(os.Args[2:])
	default:
		fmt.Println("put or get subcommand is required")
		os.Exit(1)
	}

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		panic(err)
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	fmt.Print("Enter password: ")
	passkey, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		panic(err)
	}

	entries := ReadDb(passkey)

	fmt.Println()

	if getCmd.Parsed() {
		login := getCmd.Arg(0)
		for _, entry := range entries {
			if entry.Login == login {
				fmt.Println(entry.Password)
			}
		}
	}

	if putCmd.Parsed() {
		login := putCmd.Arg(0)
		fmt.Printf("Enter password for %s:", login)
		password, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			panic(err)
		}

		updated := false

		for i, entry := range entries {
			if entry.Login == login {
				entries[i].Password = string(password)
				updated = true
				break
			}
		}

		if !updated {
			entries = append(entries, Entry{login, string(password)})
		}

		WriteDb(passkey, entries)
	}
}

func GetDbFilePath() string {
	homedir, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}
	return filepath.Join(homedir, DB_PATH)
}

func DeriveKey(password []byte, salt []byte) []byte {
	return pbkdf2.Key(password, salt, 4096, 32, sha256.New)
}

func ReadDb(passkey []byte) []Entry {
	_, err := os.Stat(GetDbFilePath())
	if os.IsNotExist(err) {
		return []Entry{}
	}

	data, err := os.ReadFile(GetDbFilePath())
	if err != nil {
		panic(err)
	}
	salt := data[:32]
	ciphertext := data[32:]
	key := DeriveKey(passkey, salt)

	c, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		panic(err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		panic("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err)
	}

	var entries []Entry
	err = json.Unmarshal([]byte(plaintext), &entries)
	if err != nil {
		panic(err)
	}
	return entries
}

func WriteDb(passkey []byte, entries []Entry) {
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		panic(err)
	}

	key := DeriveKey(passkey, salt)

	c, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		panic(err)
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		panic(err)
	}

	data, err := json.Marshal(entries)
	if err != nil {
		panic(err)
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	err = os.WriteFile(GetDbFilePath(), append(salt, ciphertext...), 0600)
	if err != nil {
		panic(err)
	}
}
