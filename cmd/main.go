package main

import (
	"fmt"
	"os"

	gosec "github.com/dsjr2006/gosecurefile"
	"github.com/howeyc/gopass"
	"github.com/uber-go/zap"
	"github.com/urfave/cli"
)

var logger = zap.New(
	zap.NewJSONEncoder(),
	zap.DebugLevel,
) // Creates new zap logger

func main() {
	app := cli.NewApp()
	app.Name = "triplesecgo"
	app.Version = "0.1.0"
	app.Description = "TripleSecGo"
	app.Usage = "[global options] Origin Destination"
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "debug,d",
			Usage: "-debug,-d",
		},
	}
	app.Commands = []cli.Command{
		{
			Name:        "encrypt",
			Aliases:     []string{"e"},
			Usage:       "[global options] encrypt /orig-path /dest-path",
			Description: "Encrypt file using TripleSec encryption.",
			Action: func(c *cli.Context) error {

				gosec.EncryptTripleSec(c.Args().Get(0), c.Args().Get(1), getPasswordConfirm(true))

				return nil
			},
		},
		{
			Name:        "decrypt",
			Aliases:     []string{"e"},
			Usage:       "[global options] decrypt /orig-path /dest-path",
			Description: "Decrypt file using TripleSec",
			Action: func(c *cli.Context) error {
				gosec.DecryptTripleSec(c.Args().Get(0), c.Args().Get(1), getPasswordConfirm(false))
				return nil
			},
		},
	}

	app.Run(os.Args)
}
func getPasswordConfirm(confirm bool) []byte {
	tries := 0
	var pass []byte = nil
	var err error

	for {
		fmt.Printf("Passphrase: ")
		pass, err = gopass.GetPasswdMasked()
		if err != nil {
			logger.Fatal("Unable to obtain passphrase from stdin")
		}
		tries++
		if len(pass) < 12 && tries <= 2 {
			fmt.Println("Passphrase must be at least 12 chars")
			continue
		}
		if len(pass) < 12 {
			fmt.Println("Passphrase must be at least 12 chars")
			logger.Fatal("Passphrase must be at least 12 chars, too many tries.")
		} else {
			break
		}
	}

	if confirm == true {
		fmt.Printf("Confirm:    ")
		confirm, err := gopass.GetPasswdMasked()
		if err != nil {
			logger.Fatal("Unable to obtain passphrase from stdin")
		}
		if string(pass) != string(confirm) {
			fmt.Println("Passphrases do not match")
			logger.Fatal("Passphrases did not match")
		}
		confirm = nil
	}

	return pass
} // Optionally confirm entered password
