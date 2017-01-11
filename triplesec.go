package gosecurefile

import (
	"bytes"
	"crypto/rand"
	"io"
	"io/ioutil"
	"os"

	tripsec "github.com/dsjr2006/go-triplesec"

	"github.com/uber-go/zap"
)

var Logger = zap.New(
	zap.NewJSONEncoder(),
	zap.DebugLevel,
) // Creates new zap logger

func init() {

}

func EncryptTripleSec(filepath string, destination string, passphrase string) {
	// Check passphrase length
	if len(passphrase) < 12 {
		Logger.Fatal("Passphrase must be at least 12 chars.")
	}
	Logger.Debug("Encrypt Triple Sec Received new file for encryption",
		zap.String("File", filepath),
	)

	// Make Random 16 byte salt
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		Logger.Fatal("Could not create random salt.",
			zap.Error(err),
		)
	}

	cipher, err := tripsec.NewCipher([]byte(passphrase), salt)
	if err != nil {
		Logger.Fatal("Error creating new triple sec cipher.",
			zap.Error(err),
		)
	}

	// Open file for reading
	file, err := os.Open(filepath)
	defer file.Close()
	if err != nil {
		Logger.Fatal("Error opening file.",
			zap.Error(err),
			zap.String("File", filepath),
		)
	}

	buffer := bytes.NewBuffer(nil)
	if _, err := io.Copy(buffer, file); err != nil {
		Logger.Fatal("Could not create buffer",
			zap.Error(err),
		)
	}

	// Encrypt item
	encryptedItem, err := cipher.Encrypt(buffer.Bytes())
	if err != nil {
		Logger.Fatal("Error encrypting item.",
			zap.Error(err),
		)
	}
	ioutil.WriteFile(destination, encryptedItem, 0644)
}
