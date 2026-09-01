package trustsync

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"go.uber.org/zap"
)

// inventoryCert is the per-certificate projection logged for operator-placed
// (local) trust material. Subjects and fingerprints are non-sensitive
// provenance; the certificate itself never appears.
type inventoryCert struct {
	Origin   string    `json:"origin"` // always "local" — managed certs are counted, not listed
	File     string    `json:"file"`
	Subject  string    `json:"subject"`
	SHA256   string    `json:"sha256"`
	NotAfter time.Time `json:"notAfter"`
}

// inventoryError names a trust-directory file that failed to parse. A
// broken file beside working ones would otherwise be invisible: the engine
// serves the union of whatever loads, and nothing else reports what didn't.
type inventoryError struct {
	File  string `json:"file"`
	Error string `json:"error"`
}

// LogInventory writes one structured "trust inventory" event for the
// engine's trust directory: the managed bundle (synced from the trust
// service) as a count plus a whole-file hash, and every other certificate —
// operator-placed local trust material — named in full with origin, file,
// subject and fingerprint. The split is deliberate: managed material mirrors
// the trust service's own published state, while a hand-placed PEM in this
// directory exists nowhere else, so this log is its only record. Emitted at
// startup (what the engine loaded) and after every managed-bundle rewrite
// (what is now on disk — the engine picks it up on restart).
func LogInventory(log *zap.Logger, dir, managedName string) {
	if log == nil {
		return
	}
	if managedName == "" {
		managedName = defaultManagedName
	}
	if dir == "" {
		log.Info("trust inventory", zap.String("dir", ""),
			zap.String("state", "not_configured"))
		return
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		log.Warn("trust inventory", zap.String("dir", dir),
			zap.String("state", "unreadable"), zap.Error(err))
		return
	}

	managedPresent := false
	managedCount := 0
	managedSHA := ""
	var locals []inventoryCert
	var errs []inventoryError

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		switch strings.ToLower(filepath.Ext(e.Name())) {
		case ".pem", ".crt", ".cer", ".der":
		default:
			continue
		}
		raw, rerr := os.ReadFile(filepath.Join(dir, e.Name())) //nolint:gosec // operator-controlled trust material
		if rerr != nil {
			errs = append(errs, inventoryError{File: e.Name(), Error: rerr.Error()})
			continue
		}
		certs, perr := parseCertificates(raw)
		if e.Name() == managedName {
			managedPresent = true
			managedCount = len(certs)
			sum := sha256.Sum256(raw)
			managedSHA = hex.EncodeToString(sum[:])
			if perr != nil {
				errs = append(errs, inventoryError{File: e.Name(), Error: perr.Error()})
			}
			continue
		}
		if perr != nil {
			errs = append(errs, inventoryError{File: e.Name(), Error: perr.Error()})
			continue
		}
		for _, c := range certs {
			sum := sha256.Sum256(c.Raw)
			locals = append(locals, inventoryCert{
				Origin:   "local",
				File:     e.Name(),
				Subject:  c.Subject.String(),
				SHA256:   hex.EncodeToString(sum[:]),
				NotAfter: c.NotAfter,
			})
		}
	}
	sort.Slice(locals, func(i, j int) bool { return locals[i].SHA256 < locals[j].SHA256 })

	fields := []zap.Field{
		zap.String("dir", dir),
		zap.Bool("managed_present", managedPresent),
		zap.Int("managed_count", managedCount),
		zap.Int("local_count", len(locals)),
	}
	if managedSHA != "" {
		fields = append(fields, zap.String("managed_sha256", managedSHA))
	}
	if len(locals) > 0 {
		fields = append(fields, zap.Any("local_certs", locals))
	}
	if len(errs) > 0 {
		fields = append(fields, zap.Any("errors", errs))
	}
	log.Info("trust inventory", fields...)
}

// parseCertificates reads every CERTIFICATE block from PEM, falling back to
// a single DER certificate.
func parseCertificates(raw []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return out, err
		}
		out = append(out, cert)
	}
	if len(out) > 0 {
		return out, nil
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, err
	}
	return []*x509.Certificate{cert}, nil
}
