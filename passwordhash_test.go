package passwordhash

import "testing"

var testPasswordHash = NewPasswordHash(&Config{saltLength: 8, iterations: 50000, saltChars: "1"})

func TestGenerateSalt(t *testing.T) {
	res := testPasswordHash.generateSalt()

	if res != "11111111" {
		t.Error("Expected 11111111, got ", res)
	}
}

func TestHashInternal(t *testing.T) {
	res := testPasswordHash.hashInternal("qsZ48XV1", "password")

	if res != "7048e66228436d95aca401a9e2afc31b6c485988122bc9d08e6c3e715966d3fc" {
		t.Error("Expected 7048e66228436d95aca401a9e2afc31b6c485988122bc9d08e6c3e715966d3fc, got ", res)
	}
}

func TestGeneratePasswordHash(t *testing.T) {
	res := testPasswordHash.GeneratePasswordHash("password")

	if res != "pbkdf2:sha256:50000$11111111$c913752258e16bc55ab4de092c2a2438dab97eb658711e35461676acc33166a9" {
		t.Error("Expected pbkdf2:sha256:50000$11111111$c913752258e16bc55ab4de092c2a2438dab97eb658711e35461676acc33166a9, got ", res)
	}
}

func TestCheckPasswordHash(t *testing.T) {
	res := testPasswordHash.CheckPasswordHash("password", "pbkdf2:sha256:50000$qsZ48XV1$7048e66228436d95aca401a9e2afc31b6c485988122bc9d08e6c3e715966d3fc")

	if res != true {
		t.Error("Expected true, got ", res)
	}
}
