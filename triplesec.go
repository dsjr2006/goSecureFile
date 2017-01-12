package gosecurefile

import (
	"bytes"
	"crypto/rand"
	"io"
	"io/ioutil"
	"os"

	pb "gopkg.in/cheggaaa/pb.v1"

	tripsec "github.com/dsjr2006/go-triplesec"

	"github.com/uber-go/zap"
)

var Logger = zap.New(
	zap.NewJSONEncoder(),
	zap.DebugLevel,
) // Creates new zap logger

func init() {

}

func EncryptTripleSec(filepath string, destination string, passphrase []byte) {
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

	cipher, err := tripsec.NewCipher(passphrase, salt)
	if err != nil {
		Logger.Fatal("Error creating new triple sec cipher.",
			zap.Error(err),
		)
	}

	// Open file for reading
	file, err := os.Open(filepath)
	fileInfo, err := file.Stat()
	defer file.Close()
	if err != nil {
		Logger.Fatal("Error opening file.",
			zap.Error(err),
			zap.String("File", filepath),
		)
	}
	bar := pb.New64(fileInfo.Size()).SetUnits(pb.U_BYTES)
	bar.Start()

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
} // Encrypts item at origin to provided destination, requires min char passphrase as []byte

/*
// The MagicBytes are the four bytes prefixed to every TripleSec
// ciphertext, 1c 94 d7 de.
var MagicBytes = [4]byte{0x1c, 0x94, 0xd7, 0xde}
*/
func DecryptTripleSec(filepath string, destination string, passphrase []byte) {
	Logger.Debug("Decrypt Triple Sec Received new file for decryption",
		zap.String("File", filepath),
	)

	cipher, err := tripsec.NewCipher(passphrase, nil)
	if err != nil {
		Logger.Fatal("Error creating new triple sec cipher for decryption.",
			zap.Error(err),
		)
	}

	// Open file for reading
	file, err := os.Open(filepath)
	fileInfo, err := file.Stat()
	defer file.Close()
	if err != nil {
		Logger.Fatal("Error opening file.",
			zap.Error(err),
			zap.String("File", filepath),
		)
	}

	bar := pb.New64(fileInfo.Size()).SetUnits(pb.U_BYTES)
	bar.Start()

	buffer := bytes.NewBuffer(nil)
	if _, err := io.Copy(buffer, file); err != nil {
		Logger.Fatal("Could not create buffer",
			zap.Error(err),
		)
	}

	// Decrypt item
	decryptedItem, err := cipher.Decrypt(buffer.Bytes())
	if err != nil {
		Logger.Fatal("Error decrypting item.",
			zap.Error(err),
		)
	}
	ioutil.WriteFile(destination, decryptedItem, 0644)

	return
}
