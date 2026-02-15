package sdk

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

func UploadStdin(response SecretEnvelopeResponse) error {
	err := performUpload(os.Stdin, &response, *response.S3Info.Url)
	if err != nil {
		return fmt.Errorf("Oops! %s", err.Error())
	}
	return nil
}

func UploadFile(response SecretEnvelopeResponse, filePath string) error {
	logrus.Debugf("\nUploadFile: trying to upload file: %s", filePath)
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	err = performPutUpload(file, response)

	if err != nil {
		return fmt.Errorf("Oops! %s", err.Error())
	}
	return nil
}

func addFieldsToWriter(writer *multipart.Writer, response *SecretEnvelopeResponse) error {

	fieldsValue := reflect.ValueOf(response.S3Info.Fields).Elem()
	for i := 0; i < fieldsValue.NumField(); i++ {
		field := fieldsValue.Field(i)

		fieldName := strings.Replace(fieldsValue.Type().Field(i).Tag.Get("json"), ",omitempty", "", 1)

		if field.Kind() == reflect.Ptr && !field.IsNil() {
			fieldValue := field.Elem().Interface()
			logrus.Debug(fmt.Sprintf("ADDING: %s with value %s", fieldName, fieldValue))
			switch v := fieldValue.(type) {
			case string:
				if err := writer.WriteField(fieldName, v); err != nil {
					return err
				}
			case []string:
				for _, val := range v {
					if err := writer.WriteField(fieldName, val); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}
func performPutUpload(reader io.Reader, envelope SecretEnvelopeResponse) error {
	var buf bytes.Buffer
	n, err := io.Copy(&buf, reader)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PUT", *envelope.S3Info.Url, &buf)
	if err != nil {
		return err
	}

	// Set ContentLength correctly
	req.ContentLength = n

	req.Header.Set("x-amz-meta-recipient_ids", strings.Join(*envelope.S3Info.Fields.XAmzMetaRecipientIds, ","))
	req.Header.Set("x-amz-meta-reference", *envelope.S3Info.Fields.XAmzMetaReference)
	req.Header.Set("x-amz-meta-sender_id", *envelope.S3Info.Fields.XAmzMetaSenderId)
	req.Header.Set("x-amz-meta-onetime", strconv.FormatBool(*envelope.Onetime))
	req.Header.Set("x-amz-meta-expiration", strconv.FormatInt(envelope.Expiration.Unix(), 10))

	// req.Header.Set("X-Amz-Meta-reference", *envelope.S3Info.Fields.XAmzMetaReference)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		body, _ := io.ReadAll(resp.Body)
		logrus.Debugf("Error from S3 API: %s", string(body))
		return fmt.Errorf("upload failed: %s", string(body))
	}

	// req, err := http.NewRequest("PUT", *envelope.S3Info.Url, reader)
	// spew.Dump(*envelope.S3Info.Url)
	// if err != nil {
	// 	return err
	// }

	// // ids := *envelope.S3Info.Fields.XAmzMetaRecipientIds
	// // req.Header.Set("Content-Type", "application/octet-stream")
	// // req.Header.Set("x-amz-meta-recipient_ids", strings.Join(ids, ","))
	// // req.Header.Set("x-amz-meta-reference", *envelope.S3Info.Fields.XAmzMetaReference)
	// // req.Header.Set("x-amz-meta-sender_id", *envelope.S3Info.Fields.XAmzMetaSenderId)
	// req.Header.Set("Content-Type", "application/octet-stream")
	// var buf bytes.Buffer
	// size, _ := io.Copy(&buf, reader)
	// req.ContentLength = size
	// client := &http.Client{}
	// resp, err := client.Do(req)

	// if err != nil {
	// 	return err
	// }
	// defer resp.Body.Close()
	// // spew.Dump(resp.StatusCode)
	// // spew.Dump(req.Header)

	// if resp.StatusCode != http.StatusOK {
	// 	body, _ := io.ReadAll(resp.Body)
	// 	return fmt.Errorf("upload failed: %s", string(body))
	// }
	return nil
}

func performUpload(reader io.Reader, response *SecretEnvelopeResponse, callURL string) error {
	var buffer bytes.Buffer

	mpWriter := multipart.NewWriter(&buffer)

	// fmt.Println(*response.S3Info.Fields.Key)
	if err := addFieldsToWriter(mpWriter, response); err != nil {
		return err
	}
	part, err := mpWriter.CreatePart(textproto.MIMEHeader{
		"Content-Disposition": []string{"form-data; name=\"file\"; filename=\"" + *response.S3Info.Fields.Key + "\""},
		"Content-Type":        []string{"application/octet-stream"}, // Set the appropriate MIME type
	})

	if _, err = io.Copy(part, reader); err != nil {
		panic(err)
	}
	mpWriter.Close()
	logrus.Debugf("HTTP POST URL: %s", callURL)

	request, err := http.NewRequest("POST", callURL, &buffer)
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", mpWriter.FormDataContentType())
	client := &http.Client{}
	responseHTTP, err := client.Do(request)
	if err != nil {
		return err
	}
	if responseHTTP.StatusCode == http.StatusBadRequest {
		return fmt.Errorf("Secret rejected for exceeding your quota")
		// fmt.Println("")
	} else if responseHTTP.StatusCode != http.StatusNoContent {
		bytes, _ := io.ReadAll(responseHTTP.Body)
		fmt.Println(string(bytes))
		return fmt.Errorf("Something went wrong with the file upload")
	}
	// else {
	// 	fmt.Println(fmt.Sprintf("Secret encrypted and posted successfully as %s!", *response.S3Info.Fields.XAmzMetaReference))
	// }
	return nil
}
