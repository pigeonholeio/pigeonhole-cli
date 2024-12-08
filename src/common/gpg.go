package common

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/pigeonholeio/pigeonhole-cli/logger"
	"github.com/pigeonholeio/pigeonhole-cli/sdk"
	"github.com/spf13/viper"
)

func CreateGPGKey(name string, email string) (string, string, string, crypto.Key) {
	// Generate the RSA key
	logger.Log.Debugf("Creating new GPG key for %s at %s", name, email)
	rsaKey, _ := crypto.GenerateKey(name, email, "rsa", 4096)

	// Get the armored public key and private key
	pubKey, _ := rsaKey.GetArmoredPublicKeyWithCustomHeaders("https://pigeono.io", "PigeonHole v1.0")
	privKey, _ := rsaKey.ArmorWithCustomHeaders("https://pigeono.io", "PigeonHole v1.0")

	// Compute the thumbprint of the public key
	pubKeyBytes, _ := rsaKey.GetPublicKey() // Get the public key bytes (assumes this is in DER or PKIX format)
	thumbprint := computeThumbprint(pubKeyBytes)

	// Return the public key, private key, thumbprint, and the RSA key itself
	return pubKey, privKey, thumbprint, *rsaKey
}

// Function to compute the SHA-256 thumbprint of the public key
func computeThumbprint(pubKeyBytes []byte) string {
	// Compute the SHA-256 hash of the public key
	hash := sha256.Sum256(pubKeyBytes)

	// Encode the hash as base64 for easy display
	thumbprint := base64.RawURLEncoding.EncodeToString(hash[:])

	return thumbprint
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
		ModTime:  32423423,
	}

	tmpFile, err := os.CreateTemp(os.TempDir(), "pigeonhole-*.enc.tmp")
	logger.Log.Debugf("Creating tmp file: %s", tmpFile.Name())
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()

	go func() {
		defer pw.Close()
		pt, err := publicKeyRing.EncryptStream(pw, &messageMeta, nil)
		if err != nil {
			logger.Log.Error(err)
			return
		}

		if _, err := io.Copy(pt, file); err != nil {
			logger.Log.Error(err)
			return
		}
		pt.Close()
	}()

	if _, err = io.Copy(tmpFile, pr); err != nil {
		return "", err
	}
	logger.Log.Debugf("Returning encFileName: %s", tmpFile.Name())
	return tmpFile.Name(), nil
}
func DecryptBytes(input []byte, destinationPath string) (decryptedTmpFilePath string, err error) {
	armoredPrivKey, _ := DecodeFromBase64(viper.GetViper().GetString("key.latest.private"))
	keyObj, err := crypto.NewKeyFromArmored(armoredPrivKey)
	if err != nil {
		return "", err
	}

	privKeyRing, err := crypto.NewKeyRing(keyObj)
	if err != nil {
		return "", err
	}
	logger.Log.Debugf("creating directories to: %s", destinationPath)
	os.MkdirAll(destinationPath, os.ModePerm)

	tmpFile, err := os.CreateTemp(destinationPath, "pigeonhole-*.tmp")
	if err != nil {
		return "", err
	}

	defer tmpFile.Close()

	// Open a file for writing the decrypted data
	logger.Log.Debugf("creating tmp file for decryption: %s", tmpFile.Name())
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
		logger.Log.Debugf(err.Error())
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

func GetUserGPGArmoredPubKeysFromIdSlice(recipients []string) ([]string, error) {
	params := sdk.UserGetParams{}
	params.Id = &recipients
	users, _ := GlobalPigeonHoleClient.UserGetWithResponse(GlobalCtx, &params)
	// spew.Dump(users)
	// spew.Dump(users)
	var keys []string
	for _, user := range *users.JSON200 {
		logger.Log.Debugf("Found %d key(s) for recipient %s ", len(*user.Keys), *user.Email)
		for _, k := range *user.Keys {
			decoded, err := base64.StdEncoding.DecodeString(*k.KeyData)
			if err != nil {
				return nil, err
			}
			keys = append(keys, string(decoded))
		}
	}

	if len(keys) > 0 {
		return keys, nil
	} else {
		return nil, fmt.Errorf("No keys for recipients")
	}
}
