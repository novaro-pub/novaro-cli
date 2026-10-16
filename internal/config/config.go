// Package config keeps what novaro login made: the API's address, the
// market, the device's name and the key, the key in the OS keychain when
// there is one and in the config file (0600) when there is none.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/zalando/go-keyring"
)

// keyringService names novaro's entries in the OS keychain.
const keyringService = "novaro"

// Profile is the config file's content.
type Profile struct {
	APIBase    string `json:"api_base"`
	Market     string `json:"market"`
	DeviceName string `json:"device_name,omitempty"`
	KeyPrefix  string `json:"key_prefix,omitempty"`
	// KeyExpiresAt is unix seconds; 0 for a key that does not expire.
	KeyExpiresAt int64 `json:"key_expires_at,omitempty"`
	// Key is set only when no keychain took it.
	Key string `json:"key,omitempty"`
}

// Store reads and writes the profile and its key.
type Store struct {
	// Path is the config file.
	Path string
	// Keyring is the OS keychain; tests replace it.
	Keyring Keyring
}

// Keyring is the part of go-keyring novaro uses.
type Keyring interface {
	Set(service, user, secret string) error
	Get(service, user string) (string, error)
	Delete(service, user string) error
}

type osKeyring struct{}

func (osKeyring) Set(s, u, p string) error        { return keyring.Set(s, u, p) }
func (osKeyring) Get(s, u string) (string, error) { return keyring.Get(s, u) }
func (osKeyring) Delete(s, u string) error        { return keyring.Delete(s, u) }

// Default is the store in the user's config directory, or in
// $NOVARO_CONFIG_DIR when set.
func Default() (*Store, error) {
	dir := os.Getenv("NOVARO_CONFIG_DIR")
	if dir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return nil, err
		}
		dir = filepath.Join(base, "novaro")
	}
	return &Store{Path: filepath.Join(dir, "config.json"), Keyring: osKeyring{}}, nil
}

// ErrNotLoggedIn is Load's answer when login has not run.
var ErrNotLoggedIn = errors.New("not logged in: run novaro login, or pass --api-key")

// Load reads the profile and its key.
func (s *Store) Load() (Profile, string, error) {
	b, err := os.ReadFile(s.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return Profile{}, "", ErrNotLoggedIn
	}
	if err != nil {
		return Profile{}, "", err
	}
	var p Profile
	if err := json.Unmarshal(b, &p); err != nil {
		return Profile{}, "", fmt.Errorf("%s: %w", s.Path, err)
	}
	if p.Key != "" {
		return p, p.Key, nil
	}
	key, err := s.Keyring.Get(keyringService, p.APIBase)
	if errors.Is(err, keyring.ErrNotFound) {
		return p, "", ErrNotLoggedIn
	}
	if err != nil {
		return p, "", fmt.Errorf("the OS keychain: %w", err)
	}
	return p, key, nil
}

// Save writes p and key: key to the keychain, or into the file when the
// keychain refuses it (a server without one); fallback says which.
func (s *Store) Save(p Profile, key string) (inFile bool, err error) {
	p.Key = ""
	if err := s.Keyring.Set(keyringService, p.APIBase, key); err != nil {
		p.Key = key
		inFile = true
	}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o700); err != nil {
		return false, err
	}
	tmp := s.Path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return false, err
	}
	return inFile, os.Rename(tmp, s.Path)
}

// Clear removes the key and the profile. Neither being there is not an
// error.
func (s *Store) Clear() error {
	p, _, err := s.Load()
	if err != nil && !errors.Is(err, ErrNotLoggedIn) {
		return err
	}
	if p.APIBase != "" {
		if err := s.Keyring.Delete(keyringService, p.APIBase); err != nil && !errors.Is(err, keyring.ErrNotFound) {
			return fmt.Errorf("the OS keychain: %w", err)
		}
	}
	if err := os.Remove(s.Path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// Expired says whether p's key has expired at now.
func (p Profile) Expired(now time.Time) bool {
	return p.KeyExpiresAt != 0 && !now.Before(time.Unix(p.KeyExpiresAt, 0))
}
