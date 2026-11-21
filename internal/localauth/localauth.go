// Package localauth checks the passwords and one-time codes of the model's
// local users. The user object says who the user is and what they may do;
// the bcrypt hash and the TOTP secret live in the secret store under names
// derived from the user's id, so they reach every cluster member through
// the store's replication and never enter the configuration log.
package localauth

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"

	"github.com/noahzmr/testudo/internal/auth"
	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/model"
)

// Secrets is where hashes and TOTP secrets are kept. secrets.Store
// implements it.
type Secrets interface {
	Get(name string) ([]byte, error)
	Put(name string, value []byte) error
	Delete(name string) error
	Has(name string) bool
}

var (
	// ErrInvalid covers an unknown user and a wrong password or code alike.
	ErrInvalid = errors.New("invalid credentials")
	// ErrTOTPRequired means the password was right and a code is needed.
	ErrTOTPRequired = errors.New("one-time code required")
	// ErrDisabled means the account may not log in.
	ErrDisabled = errors.New("account disabled")
)

// MinPassword is the shortest password accepted when one is set.
const MinPassword = 10

// PasswordEntry and TOTPEntry name a user's secrets.
func PasswordEntry(userID string) string { return "user-" + userID + "-password" }
func TOTPEntry(userID string) string     { return "user-" + userID + "-totp" }

// Find returns the local user with a user name, or nil.
func Find(st *confstore.State, username string) *model.User {
	if st == nil {
		return nil
	}
	for _, e := range st.List(model.KindUser) {
		if u := e.(*model.User); u.Source == "local" && u.Username == username {
			return u
		}
	}
	return nil
}

// dummy keeps a login for an unknown name about as slow as one for a known
// name, so the time taken does not tell which names exist.
var dummy, _ = bcrypt.GenerateFromPassword([]byte("testudo-no-such-user"), bcrypt.DefaultCost)

// Authenticate checks a local user's password and, when the user has a
// second factor, the code.
func Authenticate(st *confstore.State, sec Secrets, username, password, code string, now time.Time) (*model.User, error) {
	u := Find(st, username)
	hash := dummy
	if u != nil {
		if h, err := sec.Get(PasswordEntry(u.ID)); err == nil {
			hash = h
		}
	}
	if bcrypt.CompareHashAndPassword(hash, []byte(password)) != nil || u == nil || string(hash) == string(dummy) {
		return nil, ErrInvalid
	}
	if u.Disabled {
		return nil, ErrDisabled
	}
	if secret, err := sec.Get(TOTPEntry(u.ID)); err == nil && len(secret) > 0 {
		if strings.TrimSpace(code) == "" {
			return nil, ErrTOTPRequired
		}
		if !auth.ValidateTOTP(string(secret), strings.TrimSpace(code), now) {
			return nil, ErrInvalid
		}
	}
	return u, nil
}

// Verify checks a user's password only.
func Verify(sec Secrets, userID, password string) bool {
	h, err := sec.Get(PasswordEntry(userID))
	return err == nil && bcrypt.CompareHashAndPassword(h, []byte(password)) == nil
}

// SetPassword stores a new password for a user.
func SetPassword(sec Secrets, userID, password string) error {
	if utf8.RuneCountInString(password) < MinPassword {
		return errors.New("the password needs at least 10 characters")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return sec.Put(PasswordEntry(userID), h)
}

// SetHash stores an existing bcrypt hash, for imported users.
func SetHash(sec Secrets, userID, hash string) error {
	if _, err := bcrypt.Cost([]byte(hash)); err != nil {
		return errors.New("not a bcrypt hash")
	}
	return sec.Put(PasswordEntry(userID), []byte(hash))
}

// HasPassword reports whether a user can log in with a password at all.
func HasPassword(sec Secrets, userID string) bool { return sec.Has(PasswordEntry(userID)) }

// MFAEnrolled reports whether a user has a second factor.
func MFAEnrolled(sec Secrets, userID string) bool { return sec.Has(TOTPEntry(userID)) }

// EnrollTOTP gives a user a new TOTP secret and returns the otpauth URI to
// show once. An existing secret is replaced: that is how a lost
// authenticator is recovered.
func EnrollTOTP(sec Secrets, u *model.User, issuer string) (string, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	if err := sec.Put(TOTPEntry(u.ID), []byte(secret)); err != nil {
		return "", err
	}
	if issuer == "" {
		issuer = "Testudo"
	}
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	return "otpauth://totp/" + url.PathEscape(issuer+":"+u.Username) + "?" + q.Encode(), nil
}

// SetTOTPSecret stores an existing base32 TOTP secret, for imported users.
func SetTOTPSecret(sec Secrets, userID, secret string) error {
	return sec.Put(TOTPEntry(userID), []byte(secret))
}

// DisableTOTP removes a user's second factor.
func DisableTOTP(sec Secrets, userID string) error {
	if !sec.Has(TOTPEntry(userID)) {
		return nil
	}
	return sec.Delete(TOTPEntry(userID))
}

// Forget removes a user's secrets, after the user object is gone.
func Forget(sec Secrets, userID string) {
	for _, n := range []string{PasswordEntry(userID), TOTPEntry(userID)} {
		if sec.Has(n) {
			_ = sec.Delete(n)
		}
	}
}

// NewPassword returns a random 16-character password for a first
// administrator: about 93 bits, letters and digits that are not confused
// with each other.
func NewPassword() (string, error) {
	const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	out := make([]byte, 0, 16)
	buf := make([]byte, 32)
	for len(out) < 16 {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for _, b := range buf {
			// Reject the top values so every character is equally likely.
			if int(b) < 256-256%len(alphabet) && len(out) < 16 {
				out = append(out, alphabet[int(b)%len(alphabet)])
			}
		}
	}
	return string(out), nil
}
