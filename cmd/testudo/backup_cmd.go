package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/noahzmr/testudo/internal/backup"
	"github.com/noahzmr/testudo/internal/config"
)

// cmdBackup writes, checks and restores encrypted backups of a node.
func cmdBackup(args []string) error {
	const usage = "usage: testudo backup <create --out FILE | inspect --in FILE | restore --in FILE [--force]> [--storage DIR] [--passphrase-file FILE]"
	if len(args) == 0 {
		return errors.New(usage)
	}
	cfg := config.Default()
	fs := flag.NewFlagSet("backup "+args[0], flag.ExitOnError)
	storageDir := fs.String("storage", cfg.StorageDir, "storage directory")
	out := fs.String("out", "", "create: the archive to write (created with mode 0600)")
	in := fs.String("in", "", "inspect, restore: the archive to read")
	passFile := fs.String("passphrase-file", "", "read the passphrase from this file (first line); otherwise $TESTUDO_BACKUP_PASSPHRASE, otherwise a prompt")
	force := fs.Bool("force", false, "restore: replace the configuration this node has")
	_ = fs.Parse(args[1:])

	switch args[0] {
	case "create":
		if *out == "" {
			return errors.New(usage)
		}
		pass, err := passphrase(*passFile, true)
		if err != nil {
			return err
		}
		f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		m, err := backup.Create(f, *storageDir, pass)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			os.Remove(*out)
			return err
		}
		fmt.Printf("wrote %s: model record %d, %d files\n", *out, m.ModelIndex, len(m.Files))
		fmt.Println("keep the passphrase apart from the archive; without it the archive cannot be read")
		return nil
	case "inspect", "restore":
		if *in == "" {
			return errors.New(usage)
		}
		pass, err := passphrase(*passFile, false)
		if err != nil {
			return err
		}
		f, err := os.Open(*in)
		if err != nil {
			return err
		}
		defer f.Close()
		if args[0] == "inspect" {
			m, _, err := backup.Open(f, pass)
			if err != nil {
				return err
			}
			fmt.Printf("created %s, model record %d\n", m.Created.Format("2006-01-02 15:04:05 MST"), m.ModelIndex)
			for _, name := range m.Files {
				fmt.Println("  " + name)
			}
			return nil
		}
		m, err := backup.Restore(f, *storageDir, pass, *force)
		if err != nil {
			return err
		}
		fmt.Printf("restored model record %d and %d files into %s\n", m.ModelIndex, len(m.Files), *storageDir)
		fmt.Println("start testudo: it applies the restored configuration; a cluster member joins its cluster again with a token")
		return nil
	}
	return fmt.Errorf("unknown backup subcommand %q\n%s", args[0], usage)
}

// passphrase reads the backup passphrase from a file, the environment or
// the terminal; a new one is asked for twice.
func passphrase(file string, confirm bool) ([]byte, error) {
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		line, _, _ := strings.Cut(string(b), "\n")
		return []byte(strings.TrimRight(line, "\r")), nil
	}
	if v := os.Getenv("TESTUDO_BACKUP_PASSPHRASE"); v != "" {
		return []byte(v), nil
	}
	rd := bufio.NewReader(os.Stdin)
	ask := func(prompt string) (string, error) {
		fmt.Fprint(os.Stderr, prompt)
		line, err := rd.ReadString('\n')
		if err != nil && line == "" {
			return "", fmt.Errorf("read passphrase: %w", err)
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	p, err := ask("Backup passphrase: ")
	if err != nil {
		return nil, err
	}
	if confirm {
		again, err := ask("Again: ")
		if err != nil {
			return nil, err
		}
		if again != p {
			return nil, errors.New("the passphrases differ")
		}
	}
	return []byte(p), nil
}
