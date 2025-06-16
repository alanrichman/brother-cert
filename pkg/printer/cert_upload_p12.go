package printer

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"software.sslmate.com/src/go-pkcs12"
)

// helper funcs to create p12 from pem

var errUnsupportedKey = errors.New("printer: error: only rsa keys are supported")

// keyPemToKey returns the private key from pemBytes
func keyPemToKey(keyPem []byte) (key *rsa.PrivateKey, err error) {
	// decode private key
	keyPemBlock, _ := pem.Decode(keyPem)
	if keyPemBlock == nil {
		return nil, errors.New("printer: key pem block did not decode")
	}

	// parsing depends on block type
	switch keyPemBlock.Type {
	case "RSA PRIVATE KEY": // PKCS1
		var rsaKey *rsa.PrivateKey
		rsaKey, err = x509.ParsePKCS1PrivateKey(keyPemBlock.Bytes)
		if err != nil {
			return nil, err
		}

		// basic sanity check
		err = rsaKey.Validate()
		if err != nil {
			return nil, err
		}

		return rsaKey, nil

	case "PRIVATE KEY": // PKCS8
		pkcs8K, err := x509.ParsePKCS8PrivateKey(keyPemBlock.Bytes)
		if err != nil {
			return nil, err
		}

		switch pkcs8Key := pkcs8K.(type) {
		case *rsa.PrivateKey:
			// basic sanity check
			err = pkcs8Key.Validate()
			if err != nil {
				return nil, err
			}

			return pkcs8Key, nil

		default:
			// fallthrough
		}

	default:
		// fallthrough
	}

	return nil, errUnsupportedKey
}

// TODO: This function needs to be capable of determining the length of the chain (with 0 as an option)

// certPemToCerts returns the certificate from cert pem bytes. if the pem
// bytes contain more than one certificate, the first is returned as the
// certificate and the 2nd is returned as the only member of an array. The
// rest of the chain is discarded as more than 2 certs are too big to fit
// on the printer
func certPemToCerts(certPem []byte) (cert *x509.Certificate, certChain []*x509.Certificate, err error) {
	var certPemBlock *pem.Block
	var rest []byte
	certChain = []*x509.Certificate{}
	for {
		// Decode current cert
		certPemBlock, rest = pem.Decode(certPem)
		if certPemBlock == nil {
			return nil, nil, errors.New("printer: cert pem block did not decode")
		}

		x509, err := x509.ParseCertificate(certPemBlock.Bytes)
		if err != nil {
			return nil, nil, err
		}

		// Write cert to output
		if cert == nil {
			cert = x509
		} else {
			certChain = append(certChain, x509)
		}

		// Last cert is done
		if len(rest) == 0 || rest == nil {
			break
		}

		// Advance to next cert
		certPem = rest
	}

	return cert, certChain, nil
}

// makeModernPfx returns the pkcs12 pfx data for the given key and cert pem
func makeModernPfx(keyPem, certPem []byte, password string) (pfxData []byte, err error) {
	// get private key
	key, err := keyPemToKey(keyPem)
	if err != nil {
		return nil, err
	}

	// get cert and chain (if there is a chain)
	cert, certChain, err := certPemToCerts(certPem)
	if err != nil {
		return nil, err
	}

	// encode using modern pkcs12 standard
	pfxData, err = pkcs12.Modern.Encode(key, cert, certChain, password)
	if err != nil {
		return nil, err
	}

	return pfxData, nil
}
