package common

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/Pallinder/go-randomdata"
	"github.com/drewstinnett/go-output-format/formatter"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/pigeonholeio/pigeonhole-cli/sdk"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func DisplayHelp(cmd *cobra.Command, args []string) {
	if len(args) == 0 {
		cmd.Help()
		os.Exit(0)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {

	return f(req)
}

// 	client, _ := sdk.NewClientWithResponses(viper.GetString("api.url"))
// 	return *client
// }

func NewIdPClient(token string, timeout int) (sdk.ClientWithResponses, context.Context) {
	client, ctx := sdk.PigeonholeClient(viper.GetString("api.url"), token, timeout)
	return client, ctx
}
func getOutputFormatter() *formatter.Config {
	return &formatter.Config{
		Format: viper.GetString("output.format"),
	}
}
func ArrOutputData(data *[]interface{}) {
	for i, s := range *data {
		logrus.Debug(i)
		OutputData(s)
	}
}

func OutputData(data interface{}) {
	x := getOutputFormatter()
	out, _ := formatter.OutputData(data, x)
	fmt.Println(string(out))
}

func NewPigeonHoleClient(timeout int) (sdk.ClientWithResponses, context.Context) {
	client, ctx := sdk.PigeonholeClient(viper.GetString("api.url"), viper.GetString("auth.token"), timeout)
	return client, ctx
}

func decodeJWT(tokenStr string) (map[string]interface{}, error) {
	// Splitting the token into parts
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token received")
	}

	// Decode the payload part (second part)
	payload, err := jwt.NewParser().DecodeSegment(parts[1])
	if err != nil {
		return nil, fmt.Errorf("error decoding token: %v", err)
	}

	// Unmarshal the JSON payload into a map
	var claims map[string]interface{}
	err = json.Unmarshal(payload, &claims)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling token payload: %v", err)
	}

	return claims, nil
}

func DecodePigeonHoleJWT() (map[string]interface{}, error) {
	return decodeJWT(viper.GetString("auth.token"))
}

// EncodeToBase64 takes a string and returns its base64 encoded version
func EncodeToBase64(input string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(input))
	return encoded
}
func DecodeFromBase64(input string) (string, error) {
	decodedBytes, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return "", err
	}
	return string(decodedBytes), nil
}

func GenerateCodeWord(numWords int) string {
	words := make([]string, numWords+1)
	// words[0] = randomdata.Adjective()
	words[0] = randomdata.Adjective()
	for i := 0; i < numWords; i++ {
		words[i+1] = randomdata.Noun()
	}

	return strings.Join(words, "-")
}

var GlobalPigeonHoleClient sdk.ClientWithResponses
var GlobalCtx context.Context

func SecureDelete(filePath string) error {
	// Open the file
	file, err := os.OpenFile(filePath, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer file.Close()

	// Get file size
	info, err := file.Stat()
	if err != nil {
		return err
	}
	fileSize := info.Size()

	// Overwrite the file with random data
	data := make([]byte, fileSize)
	_, err = rand.Read(data) // You can also use zeros instead of random data
	if err != nil {
		return err
	}
	_, err = file.WriteAt(data, 0)
	if err != nil {
		return err
	}

	// Truncate the file (optional)
	err = file.Truncate(0)
	if err != nil {
		return err
	}

	// Close the file before deleting
	err = file.Close()
	if err != nil {
		return err
	}

	// Delete the file
	err = os.Remove(filePath)
	if err != nil {
		return err
	}

	return nil
}

func CompressPath(src string, buf io.Writer) error {
	// tar > gzip > buf
	zr := gzip.NewWriter(buf)
	tw := tar.NewWriter(zr)

	// is file a folder?
	fi, err := os.Stat(src)
	if err != nil {
		return err
	}
	mode := fi.Mode()
	if mode.IsRegular() {
		// get header
		header, err := tar.FileInfoHeader(fi, src)
		if err != nil {
			return err
		}
		// write header
		if err := tw.WriteHeader(header); err != nil {
			return err
		}
		// get content
		data, err := os.Open(src)
		if err != nil {
			return err
		}
		if _, err := io.Copy(tw, data); err != nil {
			return err
		}
	} else if mode.IsDir() { // folder

		// walk through every file in the folder
		filepath.Walk(src, func(file string, fi os.FileInfo, err error) error {
			// generate tar header
			header, err := tar.FileInfoHeader(fi, file)
			if err != nil {
				return err
			}

			// must provide real name
			// (see https://golang.org/src/archive/tar/common.go?#L626)
			header.Name = filepath.ToSlash(file)

			// write header
			if err := tw.WriteHeader(header); err != nil {
				return err
			}
			// if not a dir, write file content
			if !fi.IsDir() {
				data, err := os.Open(file)
				if err != nil {
					return err
				}
				if _, err := io.Copy(tw, data); err != nil {
					return err
				}
			}
			return nil
		})
	} else {
		return fmt.Errorf("error: file type not supported")
	}

	// produce tar
	if err := tw.Close(); err != nil {
		return err
	}
	// produce gzip
	if err := zr.Close(); err != nil {
		return err
	}
	//
	return nil
}

// // check for path traversal and correct forward slashes
// func validRelPath(p string) bool {
// 	if p == "" || strings.Contains(p, `\`) || strings.HasPrefix(p, "/") || strings.Contains(p, "../") {
// 		return false
// 	}
// 	return true
// }

func DecompressFile(src string, dst string) error {
	// ungzip
	file, _ := os.OpenFile(src, os.O_RDONLY, os.ModePerm)
	zr, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	// untar
	tr := tar.NewReader(zr)

	// uncompress each element
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			return err
		}
		target := header.Name

		// add dst + re-format slashes according to system
		target = filepath.Join(dst, header.Name)
		// if no join is needed, replace with ToSlash:
		// target = filepath.ToSlash(header.Name)

		// check the type
		switch header.Typeflag {

		// if its a dir and it doesn't exist create it (with 0755 permission)
		case tar.TypeDir:
			if _, err := os.Stat(target); err != nil {
				if err := os.MkdirAll(target, 0755); err != nil {
					return err
				}
			}
		// if it's a file create it (with same permission)
		case tar.TypeReg:
			fileToWrite, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				return err
			}
			// copy over contents
			if _, err := io.Copy(fileToWrite, tr); err != nil {
				return err
			}
			// manually close here after each file operation; defering would cause each file close
			// to wait until all operations have completed.
			fileToWrite.Close()
		}
	}

	//
	return nil
}

func ShredFile(path string) error {
	return os.Remove(path)
}

func KeysExist() bool {
	if viper.GetString("key.latest.private") != "" {
		return true
	}
	return false
}

func GenerateKeys() error {
	fmt.Print("Creating and pushing your new GPG key...")

	if viper.GetString("auth.token") == "" {
		return fmt.Errorf("not logged in")
	}

	claims, _ := DecodePigeonHoleJWT()
	for k, v := range claims {
		logrus.Debugf("JWT claim: %s = %v", k, v)
	}

	pub, priv, _, thumbprint := CreateGPGKey(
		claims["name"].(string),
		claims["preferred_username"].(string),
	)

	b64Priv := EncodeToBase64(priv)
	b64Pub := EncodeToBase64(pub)

	viper.Set("key.latest.public", b64Pub)
	viper.Set("key.latest.private", b64Priv)

	only := true
	ref, _ := os.Hostname()

	req := sdk.NewKey{
		KeyData:    &b64Pub,
		Reference:  &ref,
		Only:       &only,
		Force:      &only,
		Thumbprint: &thumbprint,
	}

	// GlobalPigeonHoleClient, GlobalCtx = NewPigeonHoleClient()
	resp, err := GlobalPigeonHoleClient.UserMeKeyPostWithResponse(GlobalCtx, req)
	if err != nil {
		return err
	}

	logrus.Debugf("Pigeonhole API returned status: %d", resp.StatusCode())

	if resp.StatusCode() == 201 {
		if err := viper.WriteConfig(); err != nil {
			return fmt.Errorf("failed to write config: %w", err)
		}
		fmt.Println("done!")
		return nil
	}

	// Map status codes to messages using a single switch
	var msg string
	switch resp.StatusCode() {
	case 400:
		msg = resp.JSON400.Message
	case 401:
		msg = resp.JSON401.Message
	case 403:
		msg = resp.JSON403.Message
	case 500:
		msg = resp.JSON500.Message
	default:
		msg = "unexpected status code"
	}

	return fmt.Errorf("failed: %s (%d)", msg, resp.StatusCode())
}
