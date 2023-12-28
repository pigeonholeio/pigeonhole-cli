package common

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"

	log "github.com/sirupsen/logrus"

	"os"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/pigeonholeio/pigeonhole-cli/sdk"
	"github.com/spf13/viper"
)

func CreateGPGKey(name string, email string) (string, string, crypto.Key) {
	rsaKey, _ := crypto.GenerateKey(name, email, "rsa", 4096)

	pubKey, _ := rsaKey.GetArmoredPublicKeyWithCustomHeaders("https://pigeono.io", "PigeonHole v1.0")
	privKey, _ := rsaKey.ArmorWithCustomHeaders("https://pigeono.io", "PigeonHole v1.0")
	return pubKey, privKey, *rsaKey

}

func EncryptFile(filePath string, armoredPubKeys []string) (encryptedFilePath string, err error) {
	var publicKeyRing *crypto.KeyRing

	for _, armoredPubKey := range armoredPubKeys {
		publicKeyObj, err := crypto.NewKeyFromArmored(armoredPubKey)
		if err != nil {
			return "", err
		}

		if publicKeyRing == nil {
			publicKeyRing, err = crypto.NewKeyRing(publicKeyObj)
			if err != nil {
				return "", err
			}
		} else {
			err = publicKeyRing.AddKey(publicKeyObj)
			if err != nil {
				return "", err
			}
		}
	}

	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	pr, pw := io.Pipe()
	defer pw.Close()

	messageMeta := crypto.PlainMessageMetadata{
		IsBinary: true,
		Filename: filePath,
		ModTime:  32423423, // Consider using a meaningful value or parameter for ModTime
	}

	tmpFile, err := ioutil.TempFile(os.TempDir(), "pigeonhole")
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()

	go func() {
		defer pw.Close()
		pt, err := publicKeyRing.EncryptStream(pw, &messageMeta, nil)
		if err != nil {
			log.Println(err)
			return
		}

		if _, err := io.Copy(pt, file); err != nil {
			log.Println(err)
			return
		}
		pt.Close()
	}()

	if _, err = io.Copy(tmpFile, pr); err != nil {
		return "", err
	}

	return tmpFile.Name(), nil
}
func DecryptBytes(input []byte, destinationPath string) (decryptedFilePath string, err error) {
	armoredPrivKey, _ := DecodeFromBase64(viper.GetViper().GetString("key.latest.private"))
	keyObj, err := crypto.NewKeyFromArmored(armoredPrivKey)
	if err != nil {
		return "", err
	}

	privKeyRing, err := crypto.NewKeyRing(keyObj)
	if err != nil {
		return "", err
	}
	os.MkdirAll(destinationPath, os.ModePerm)

	tmpFile, err := ioutil.TempFile(destinationPath, "pigeonhole-")
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()

	// Open a file for writing the decrypted data

	fwrite, err := os.OpenFile(tmpFile.Name(), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return "", err
	}
	defer fwrite.Close()
	reader := bytes.NewReader(input)

	// Decrypt the data from the input reader
	decryptReader, err := privKeyRing.DecryptStream(reader, nil, 0)
	if err != nil {
		os.RemoveAll(tmpFile.Name())
		return "", err
	}

	// Copy the decrypted data to the file
	_, err = io.Copy(fwrite, decryptReader)
	if err != nil {
		os.RemoveAll(tmpFile.Name())
		return "", err
	}

	// Close the file
	err = fwrite.Close()
	if err != nil {
		return "", err
	}

	return tmpFile.Name(), nil
}

// func DecryptFile(filePath string) (decryptedFilePath string) {
// 	armoredPrivKey := viper.GetViper().GetString("key.latest.private")
// 	keyObj, err := crypto.NewKeyFromArmored(armoredPrivKey)
// 	privKeyRing, err := crypto.NewKeyRing(keyObj)
// 	tmpFile, err := ioutil.TempFile(os.TempDir(), "pigeonhole")

// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	fi, err := os.Open(filePath)
// 	if err != nil {
// 		panic(err)
// 	}
// 	defer fi.Close()

// 	fwrite, err := os.OpenFile(tmpFile.Name(), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
// 	log.Debug(fmt.Sprintf("Decrypting file to: %s", tmpFile.Name()))
// 	if err != nil {
// 		panic(err)
// 	}
// 	defer fwrite.Close()
// 	log.Debug("uh ok")
// 	// pipeReader, pipeWriter := io.Pipe()

// 	decryptReader, err := privKeyRing.DecryptStream(fi, nil, 0)

// 	if err != nil {
// 		log.Fatalln(err)
// 	}

// 	log.Debug("Copying pipewriter")
// 	// io.Copy(pipeWriter, fi)
// 	log.Debug("Copying decryptReader")
// 	io.Copy(fwrite, decryptReader)

// 	// if err != nil {
// 	// 	log.Fatalln(err)
// 	// }

// 	err = fwrite.Close()

// 	// fmt.Println("Decrypted file: ", tmpFile.Name())
// 	return tmpFile.Name()
// }

func GetUserGPGArmoredPubKeysFromIdSlice(recipients []string) ([]string, error) {
	params := sdk.UserGetParams{}
	params.Id = &recipients
	users, _ := GlobalPigeonHoleClient.UserGetWithResponse(GlobalCtx, &params)
	var keys []string
	for _, x := range *users.JSON200 {
		if len(*x.Keys) > 0 {
			for _, k := range *x.Keys {
				decoded, _ := base64.StdEncoding.DecodeString(*k.KeyData)
				keys = append(keys, string(decoded))
			}

		}
	}
	if len(keys) > 0 {
		return keys, nil
	} else {
		return nil, fmt.Errorf("No keys for recipients")
	}
}
