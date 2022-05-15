package utils

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
)

var client *http.Client
var allowInsecure = true
var rootCAs *x509.CertPool

func init() {
	// Get the SystemCertPool, continue with an empty pool on error
	rootCAs, _ = x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		panic(err.Error())
	}

	client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: allowInsecure,
				RootCAs:            rootCAs,
			},
		},
		Jar: jar,
	}
}

func AllowInsecureCerts(allow bool) {
	allowInsecure = allow
}

func AddCustomCA(pemEncodedCert []byte) error {
	if ok := rootCAs.AppendCertsFromPEM(bytes.TrimSpace(pemEncodedCert)); !ok {
		return errors.New("could not append cert")
	}

	client.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: allowInsecure,
			RootCAs:            rootCAs,
		},
	}
	return nil
}

func Request(uri string, headers map[string]string, postBody []byte, result interface{}) ([]byte, error) {
	var req *http.Request
	var err error

	if postBody != nil {
		req, err = http.NewRequest(http.MethodPost, uri, bytes.NewReader(postBody))
	} else {
		req, err = http.NewRequest(http.MethodGet, uri, nil)
	}

	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "okhttp/3.10.0")
	if headers != nil {
		for k, v := range headers {
			req.Header.Set(k, v)
		}
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	var body []byte

	defer res.Body.Close()

	if res.ContentLength == -1 {
		body, err = ioutil.ReadAll(res.Body)
	} else {
		body = make([]byte, res.ContentLength)
		_, err = io.ReadFull(res.Body, body)
	}

	if err == nil {
		err = json.Unmarshal(body, &result)
	}

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return body, fmt.Errorf("http status %d : %s", res.StatusCode, res.Status)
	}

	return body, err
}
