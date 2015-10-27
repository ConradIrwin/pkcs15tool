// Package pkcs1v15tool provides a tool to sign messages using the scheme described in
// PKCS1v15. Its main use is in JWTs
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

func main() {

	var keyfile string
	var formatBase64 bool
	var formatBinary bool
	var formatHex bool

	flag.StringVar(&keyfile, "key", "", "The private key file (in PEM format) to sign with")
	flag.BoolVar(&formatBase64, "base64", false, "Print output in URL-safe base64")
	flag.BoolVar(&formatBinary, "binary", false, "Print output bytes with no encoding")
	flag.BoolVar(&formatHex, "hex", false, "Print output in hex")

	flag.Parse()

	if formatHex && formatBinary || formatHex && formatBase64 || formatBinary && formatBase64 {
		fmt.Fprintln(os.Stderr, "multiple format flags provided")
		fmt.Fprintln(os.Stderr, "Usage of ./pkcs15tool:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	var format func([]byte) string

	if formatHex {
		format = hex.EncodeToString
	} else if formatBinary {
		format = func(x []byte) string { return string(x) }
	} else {
		format = base64.RawURLEncoding.EncodeToString
	}

	if keyfile == "" {
		fmt.Fprintln(os.Stderr, "no value for flag -key provided")
		fmt.Fprintln(os.Stderr, "Usage of ./pkcs15tool:")
		flag.PrintDefaults()
		os.Exit(1)
	}
	exitStatus := 0

	key, err := open(keyfile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if len(flag.Args()) == 0 {
		signature, err := sign(key, os.Stdin)
		if err != nil {
			fmt.Println(err)
			exitStatus++
		}
		fmt.Println(format(signature))
	} else {
		for _, file := range flag.Args() {
			f, err := os.Open(file)
			if err != nil {
				fmt.Println(err)
				exitStatus++
				continue
			}
			signature, err := sign(key, f)
			if err != nil {
				fmt.Println(err)
			}

			fmt.Println(format(signature))
		}
	}

	os.Exit(exitStatus)
}

func open(keyfile string) (*rsa.PrivateKey, error) {

	bytes, err := ioutil.ReadFile(keyfile)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, fmt.Errorf("%s: no valid PEM data found", keyfile)
	} else if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("%s: expected PRIVATE KEY, got %s", keyfile, block.Type)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaKey, ok := key.(*rsa.PrivateKey)

	if !ok {
		return nil, fmt.Errorf("")

	} else {
		return rsaKey, nil
	}
}

func sign(priv *rsa.PrivateKey, contents io.Reader) ([]byte, error) {

	hash := sha256.New()
	_, err := io.Copy(hash, contents)
	if err != nil {
		return nil, err
	}

	sha256 := hash.Sum([]byte{})

	return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sha256)
}
