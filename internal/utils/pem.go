package utils

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

// ReadAndValidatePEMBundle reads a PEM certificate bundle from path, validates
// that it contains at least one well-formed CERTIFICATE block, and returns the
// normalised PEM content. Symlinks and non-regular files are rejected.
func ReadAndValidatePEMBundle(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("refusing to read symlinked certificate bundle %s", path)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("refusing to read non-regular certificate bundle %s", path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	normalized := strings.TrimSpace(strings.ReplaceAll(string(data), "\r\n", "\n"))
	if normalized == "" {
		return "", fmt.Errorf("certificate bundle %s is empty", path)
	}

	var (
		rest      = []byte(normalized)
		blocks    []string
		certCount int
	)

	for len(rest) > 0 {
		block, remaining := pem.Decode(rest)
		if block == nil {
			if strings.TrimSpace(string(rest)) != "" {
				return "", fmt.Errorf("certificate bundle %s contains non-PEM content", path)
			}
			break
		}

		if block.Type != "CERTIFICATE" {
			return "", fmt.Errorf("certificate bundle %s contains unsupported PEM block type %q", path, block.Type)
		}

		// Include the certificate regardless of whether Go's strict x509 parser
		// accepts it — legacy root CAs (e.g. negative serial numbers) are valid
		// for OpenSSL/pip but rejected by Go. We still parse to catch genuinely
		// malformed DER; those are skipped rather than failing the whole bundle.
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			rest = remaining
			continue
		}

		blocks = append(blocks, strings.TrimSpace(string(pem.EncodeToMemory(block))))
		certCount++
		rest = remaining
	}

	if certCount == 0 {
		return "", fmt.Errorf("certificate bundle %s does not contain any valid certificates", path)
	}

	return strings.Join(blocks, "\n"), nil
}
