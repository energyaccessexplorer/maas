package main

import (
	"encoding/json"
	"os"
)

type s3config struct {
	Key       string `json:"key"`
	Secret    string `json:"secret"`
	Provider  string `json:"provider"`
	Bucket    string `json:"bucket"`
	Directory string `json:"directory"`
	ACL       string `json:"acl"`
}

func s3config_get(path string) (conf s3config, err error) {
	j, err := os.ReadFile(path)
	if err != nil {
		return
	}

	err = json.Unmarshal(j, &conf)

	return
}
