package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func s3timestamp() string {
	return time.Now().UTC().Format(time.RFC1123Z)
}

func s3sign(secret string, strs ...string) string {
	hash := hmac.New(sha1.New, []byte(secret))
	hash.Write([]byte(strings.Join(strs, "\n")))

	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
}

// s3configpath is re-read on every call, so rotating the S3 key only
// requires editing the file, not rebuilding or restarting maas.
func s3put(fname string, contentmd5 string, s3configpath string) (result string, err error) {
	conf, err := s3config_get(s3configpath)
	if err != nil {
		return
	}

	content, err := ioutil.ReadFile(fname)
	if err != nil {
		return
	}

	contenttype := http.DetectContentType(content)

	timestamp := s3timestamp()

	destination := strings.Join([]string{conf.Bucket, conf.Directory, filepath.Base(fname)}, "/")

	if conf.Directory == "/" {
		destination = strings.Replace(destination, "///", "/", 1)
	}

	signature := s3sign(
		conf.Secret,
		"PUT",
		contentmd5,
		contenttype,
		timestamp,
		"x-amz-acl:"+conf.ACL,
		"/"+destination,
	)

	endpoint := fmt.Sprintf("https://%s/%s", conf.Provider, destination)

	client := &http.Client{}

	q, _ := http.NewRequest("PUT", endpoint, bytes.NewReader(content))
	q.Header.Add("Date", timestamp)
	q.Header.Add("Content-Type", contenttype)
	q.Header.Add("Content-MD5", contentmd5)
	q.Header.Add("X-AMZ-ACL", conf.ACL)
	q.Header.Add("Authorization", fmt.Sprintf("AWS %s:%s", conf.Key, signature))

	r, err := client.Do(q)
	if err != nil {
		return
	}

	if r.StatusCode == 200 {
		err = os.Remove(fname)
		result = endpoint
	} else {
		err = errors.New(fmt.Sprintf("mås S3: got a %d status code. Kept %s", r.StatusCode, fname))
	}

	return
}
