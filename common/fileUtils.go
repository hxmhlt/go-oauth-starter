package common
import (
	"bufio"
	"os"
	"strings"
	"log"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"path/filepath"
)

type AppConfigProperties map[string]string

func ReadFromFile(filePath string) ([]byte,error){

	abs,err := filepath.Abs(filePath)
	if err != nil {
		fmt.Printf("File %s not found !!! ERROR: %s\n", filePath,err)
	    return nil,err
	}
	return ioutil.ReadFile(abs)
}

func ReadPropertiesFile(filename string) (AppConfigProperties, error) {
	config := AppConfigProperties{}

	if len(filename) == 0 {
		return config, nil
	}
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if equal := strings.Index(line, "="); equal >= 0 {
			if key := strings.TrimSpace(line[:equal]); len(key) > 0 {
				value := ""
				if len(line) > equal {
					value = strings.TrimSpace(line[equal+1:])
				}
				config[key] = value
			}
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
		return nil, err
	}

	return config, nil
}

// LoadCertficateAndKeyFromFile reads file, divides into key and certificates
func LoadCertficateAndKeyFromFile(path string) (*tls.Certificate, error) {
	raw, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cert tls.Certificate
	for {
		block, rest := pem.Decode(raw)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, block.Bytes)
		} else {
			cert.PrivateKey, err = parsePrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("Failure reading private key from \"%s\": %s", path, err)
			}
		}
		raw = rest
	}

	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("No certificate found in \"%s\"", path)
	} else if cert.PrivateKey == nil {
		return nil, fmt.Errorf("No private key found in \"%s\"", path)
	}

	return &cert, nil
}

// LoadCertificateDirectory globs all .pem files in given directory, parses them
// for certs (and private keys) and returns them
//func LoadCertificateDirectory(dir string) ([]tls.Certificate, error) {
//	// read certificate files
//	certficateFiles, err := filepath.Glob(filepath.Join(dir, "*.pem"))
//	if err != nil {
//		return nil, fmt.Errorf("Failed to scan certificate dir \"%s\": %s", dir, err)
//	}
//	sort.Strings(certficateFiles)
//	certs := make([]tls.Certificate, 0)
//	for _, file := range certficateFiles {
//		cert, err := LoadCertficateAndKeyFromFile(file)
//		if err != nil {
//			fmt.Errorf("common(tls): %s", err)
//		} else {
//			certs = append(certs, &cert)
//		}
//	}
//	return certs, nil
//}

func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, fmt.Errorf("Found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("Failed to parse private key")
}