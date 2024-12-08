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

	"github.com/fatih/color"

	"github.com/Pallinder/go-randomdata"
	"github.com/drewstinnett/go-output-format/formatter"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/pigeonholeio/pigeonhole-cli/logger"
	"github.com/pigeonholeio/pigeonhole-cli/sdk"
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

func NewIdPClient(token string) (sdk.ClientWithResponses, context.Context) {
	client, ctx := sdk.PigeonholeClient(viper.GetString("api.url"), token)

	return client, ctx
}
func contains(slice []string, item string) bool {
	for _, element := range slice {
		if element == item {
			return true
		}
	}
	return false
}
func GetOutputFormats() []string {
	return formatter.GetFormats()
}
func colorizeOutput(output string) string {
	colorKey := color.New(color.FgCyan).SprintFunc()    // Cyan for keys
	colorValue := color.New(color.FgGreen).SprintFunc() // Green for values

	var colorized strings.Builder

	lines := strings.Split(output, "\n")

	for _, line := range lines {
		parts := strings.SplitN(line, ": ", 2)

		if len(parts) == 2 {
			colorized.WriteString(colorKey(parts[0]) + ": " + colorValue(parts[1]) + "\n")
		} else {
			colorized.WriteString(line + "\n")
		}
	}

	return colorized.String()
}

func getOutputFormatter() *formatter.Config {
	var format string
	if contains(formatter.GetFormats(), viper.GetString("outputFormat")) {
		format = viper.GetString("outputFormat")
	} else {
		format = "yaml"
	}
	return &formatter.Config{
		Format: format,
	}
}
func ArrOutputData(data *[]interface{}) {
	for i, s := range *data {
		logger.Log.Debug(i)
		OutputData(s)
	}
}

func OutputData(data interface{}) {
	x := getOutputFormatter()
	out, _ := formatter.OutputData(data, x)
	colorizedOutput := colorizeOutput(string(out))

	fmt.Println(colorizedOutput)
}

func NewPigeonHoleClient() (sdk.ClientWithResponses, context.Context) {
	client, ctx := sdk.PigeonholeClient(viper.GetString("api.url"), viper.GetString("auth.token"))
	return client, ctx
}

func decodeJWT(tokenStr string) (map[string]interface{}, error) {
	logger.Log.Debugf("decoding JWT token")
	logger.Log.Tracef("TOKEN: %s", tokenStr)
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
	logger.Log.Debugf("total claims found on token: %d", len(claims))
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
	words := make([]string, numWords)

	words[0] = randomdata.Adjective()
	for i := 0; i < numWords; i++ {
		words[i] = randomdata.Noun()
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

		target = filepath.Join(dst, header.Name)

		switch header.Typeflag {

		// if its a dir and it doesn't exist create it (with 0755 permission)
		case tar.TypeDir:
			if _, err := os.Stat(target); err != nil {
				if err := os.MkdirAll(target, 0700); err != nil {
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
	return nil
}

func ShredFile(path string) error {
	logger.Log.Debugf("Shredding local file: %s", path)
	return os.Remove(path)
}

func KeysExist() bool {
	if viper.GetString("key.latest.private") != "" {
		return true
	}
	return false
}

func GenerateKeys(name string, preferred_username string) (bool, error) {
	pub, priv, thumbprint, _ := CreateGPGKey(name, preferred_username)
	b64_priv := EncodeToBase64(priv)
	b64_pub := EncodeToBase64(pub)

	viper.Set("key.latest.public", b64_pub)
	viper.Set("key.latest.private", b64_priv)
	viper.Set("key.latest.thumbprint", thumbprint)
	only := true
	n, err := os.Hostname()

	x := sdk.NewKey{
		KeyData:    &b64_pub,
		Reference:  &n,
		Only:       &only,
		Force:      &only,
		Thumbprint: &thumbprint,
	}

	f, err := GlobalPigeonHoleClient.UserMeKeyPostWithResponse(GlobalCtx, x)
	if err != nil {
		logger.Log.Debugf(err.Error())
	}
	errorMsg := ""
	if f.StatusCode() == 201 {
		logger.Log.Debugf("writing config")
		viper.Set("debug", false)
		viper.WriteConfig()
		fmt.Println("done!")
		return true, nil
	} else if f.StatusCode() == 400 {
		logger.Log.Debugf("\nfailed: %s\n", f.JSON400.Message)
		errorMsg = f.JSON400.Message
	} else if f.StatusCode() == 401 {
		logger.Log.Debugf("\nfailed: %s\n", f.JSON401.Message)
		errorMsg = f.JSON401.Message
	} else if f.StatusCode() == 403 {
		logger.Log.Debugf("\nfailed: %s\n", f.JSON403.Message)
		errorMsg = f.JSON403.Message
	} else if f.StatusCode() == 500 {
		logger.Log.Debugf("\nfailed: %s\n", f.JSON500.Message)
		errorMsg = f.JSON500.Message
	}
	return false, fmt.Errorf(errorMsg)
}

func ValidateLocalKeys() bool {
	key := viper.GetString("key.latest.thumbprint")
	if key == "" {
		fmt.Println("No local key, generate one using: \n	pigeonhole keys init")
		os.Exit(1)
	}

	x, err := GlobalPigeonHoleClient.UserMeKeyValidateThumbprintGetWithResponse(GlobalCtx, key)
	if err != nil {
		logger.Log.Fatalf("ERROR: %s", err.Error())
	}

	switch x.StatusCode() {
	case 200:
		logger.Log.Debugf("Key with thumbprint is available at the remote: %s\n", viper.GetString("key.latest.thumbprint"))
		return true
	default:
		logger.Log.Debugf("Key with thumbprint '%s' not available remotely")
	}
	return false
}
