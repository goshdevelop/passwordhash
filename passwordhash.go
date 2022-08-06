package passwordhash

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

var (
	defaultSaltLength = 8
	defaultIterations = 50000
	defaultSaltChars  = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

//Config keeps PasswordHash config params
type Config struct {
	saltLength int
	iterations int
	saltChars  string
}

//PasswordHash provides generation and checking user password hash
type PasswordHash struct {
	config *Config
}

//NewPasswordHash return new PasswordHash struct
func NewPasswordHash(cfg *Config) *PasswordHash {

	if cfg.saltLength == 0 {
		cfg.saltLength = defaultSaltLength
	}
	if cfg.iterations == 0 {
		cfg.iterations = defaultIterations
	}
	if cfg.saltChars == "" {
		cfg.saltChars = defaultSaltChars
	}

	passwordHash := &PasswordHash{
		config: cfg,
	}

	return passwordHash
}

//GeneratePasswordHash create hash
func (passwordHash *PasswordHash) GeneratePasswordHash(password string) string {
	salt := passwordHash.generateSalt()
	hash := passwordHash.hashInternal(salt, password)
	return fmt.Sprintf("pbkdf2:sha256:%v$%s$%s", passwordHash.config.iterations, salt, hash)
}

//CheckPasswordHash check hash
func (passwordHash *PasswordHash) CheckPasswordHash(password string, hash string) bool {
	if strings.Count(hash, "$") < 2 {
		return false
	}
	pwdHashList := strings.Split(hash, "$")
	return pwdHashList[2] == passwordHash.hashInternal(pwdHashList[1], password)
}

func (passwordHash *PasswordHash) generateSalt() string {
	var bytes = make([]byte, passwordHash.config.saltLength)
	rand.Read(bytes)
	for k, v := range bytes {
		bytes[k] = passwordHash.config.saltChars[v%byte(len(passwordHash.config.saltChars))]
	}
	return string(bytes)
}

func (passwordHash *PasswordHash) hashInternal(salt string, password string) string {
	hash := pbkdf2.Key([]byte(password), []byte(salt), passwordHash.config.iterations, 32, sha256.New)
	return hex.EncodeToString(hash)
}
