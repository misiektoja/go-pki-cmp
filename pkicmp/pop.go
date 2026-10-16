package pkicmp

import (
	"bytes"
	"crypto/hmac"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"

	compositemldsa "github.com/misiektoja/go-composite-mldsa"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// POPOptions configures [VerifyPOPWithOptions].
type POPOptions struct {
	// AllowSHA1Signatures accepts a signature proof made with
	// sha1WithRSAEncryption or ecdsa-with-SHA1, which RFC 9481 §7.1 deprecates.
	AllowSHA1Signatures bool

	// SharedSecret verifies the publicKeyMAC of a proof that carries
	// poposkInput. Pass the secret that protected the request. A proof with a
	// publicKeyMAC is refused when it is empty.
	SharedSecret []byte
	// MinMACIterationCount and MaxMACIterationCount bound the publicKeyMAC
	// iteration count as [VerifyOptions] bounds message protection. Zero
	// selects the defaults.
	MinMACIterationCount int
	MaxMACIterationCount int

	// Sender is the authenticated sender of the request. A poposkInput that
	// names a sender must name this one. Such a proof is refused when it is nil.
	Sender *GeneralName

	// AllowPoposkInputVariants accepts the poposkInput that the Insta Certifier
	// 10 cmpclient sends. The client includes it although the template carries
	// both the subject and the public key. It signs the element with its [0]
	// tag rather than the POPOSigningKeyInput SEQUENCE, computes the
	// publicKeyMAC over the subjectPublicKey bits rather than the DER
	// SubjectPublicKeyInfo and encodes the sender as a bare Name rather than a
	// directoryName.
	//
	// The signature and the MAC are still verified, so the proof still shows
	// possession of the private key and knowledge of the shared secret. Such a
	// proof does not cover the template, which only the message protection
	// then binds.
	AllowPoposkInputVariants bool
}

// VerifyPOP verifies the Proof of Possession signature on a CertReqMsg.
// RFC 4211 §4: Only signature POP is supported; raVerified is rejected.
// Returns nil if POP is valid or not present.
func VerifyPOP(reqMsg *CertReqMsg) error {
	return VerifyPOPWithOptions(reqMsg, POPOptions{})
}

// VerifyPOPWithOptions verifies the Proof of Possession signature on a CertReqMsg as [VerifyPOP] does, applying opts.
//
// A signature proof normally covers the DER CertRequest. RFC 4211 §4.1 lets a
// request whose template lacks the subject carry poposkInput instead. The
// signature then covers that structure and its authInfo is checked as well: a
// publicKeyMAC against opts.SharedSecret or a sender against opts.Sender. A
// poposkInput beside a template with both subject and public key is refused
// unless opts.AllowPoposkInputVariants is set. RFC 9483 §4.1.1 prohibits
// poposkInput altogether, which a caller enforcing that profile checks
// separately.
func VerifyPOPWithOptions(reqMsg *CertReqMsg, opts POPOptions) error {
	if reqMsg.Popo == nil {
		return nil // No POP present — allowed for some profiles.
	}
	if reqMsg.Popo.RAVerified {
		return &ParseError{Detail: "raVerified POP not supported"}
	}
	if reqMsg.Popo.Signature == nil {
		return nil // Other POP types not verified here.
	}

	// Get public key from cert template.
	if len(reqMsg.CertReq.CertTemplate.PublicKey) == 0 {
		return &ParseError{Detail: "no public key in template for POP verification"}
	}
	pub, err := ParsePublicKey(reqMsg.CertReq.CertTemplate.PublicKey)
	if err != nil {
		return fmt.Errorf("pkicmp: parse public key for POP: %w", err)
	}

	signed, err := popSignedData(reqMsg, opts)
	if err != nil {
		return err
	}

	composite, ok, err := compositeSignatureAlgorithm(reqMsg.Popo.Signature.Algorithm)
	if err != nil {
		return err
	}
	key, isComposite := pub.(*compositemldsa.PublicKey)
	if ok || isComposite {
		// A composite algorithm fixes both component keys, so it must match the requested key exactly.
		if !ok || !isComposite || key.Algorithm() != composite {
			return errors.New("pkicmp: POP algorithm does not match the requested public key")
		}
		return firstValid(signed, func(data []byte) error {
			return compositemldsa.Verify(key, data, reqMsg.Popo.Signature.Signature, nil)
		})
	}

	// Verify signature using the algorithm from popoSigningKey.
	sigAlg, err := signatureAlgorithm(reqMsg.Popo.Signature.Algorithm, opts.AllowSHA1Signatures)
	if err != nil {
		return err
	}

	// Create a minimal x509.Certificate to use CheckSignature.
	verifier := &x509.Certificate{PublicKey: pub}
	return firstValid(signed, func(data []byte) error {
		return verifier.CheckSignature(sigAlg, data, reqMsg.Popo.Signature.Signature)
	})
}

// popSignedData returns the encodings the POP signature may cover, after
// checking the authInfo of a poposkInput.
func popSignedData(reqMsg *CertReqMsg, opts POPOptions) ([][]byte, error) {
	input := reqMsg.Popo.Signature.PoposkInput
	if input == nil {
		// Use the raw DER captured during parsing.
		if len(reqMsg.CertReq.Raw) == 0 {
			return nil, &ParseError{Detail: "no raw CertRequest DER available for POP verification"}
		}
		return [][]byte{reqMsg.CertReq.Raw}, nil
	}
	if len(input.raw) == 0 {
		return nil, &ParseError{Detail: "no raw poposkInput DER available for POP verification"}
	}
	template := reqMsg.CertReq.CertTemplate
	// RFC 4211 §4.1: poposkInput MUST be omitted when the template contains both
	// the subject and the public key, so that the signature covers the template.
	if (len(template.RawSubject) > 0 || len(template.Subject.DirectoryName) > 0) && !opts.AllowPoposkInputVariants {
		return nil, &ParseError{Detail: "poposkInput not allowed when the template contains the subject and public key"}
	}
	if !bytes.Equal(input.PublicKey, template.PublicKey) {
		return nil, errors.New("pkicmp: poposkInput public key does not match the template")
	}
	switch {
	case input.Sender != nil:
		if !poposkInputSenderMatches(input.Sender, opts) {
			return nil, errors.New("pkicmp: poposkInput sender does not match the authenticated sender")
		}
	case input.PublicKeyMAC != nil:
		if err := verifyPublicKeyMAC(input, opts); err != nil {
			return nil, err
		}
	default:
		return nil, &ParseError{Detail: detailPoposkInputAuthMissing}
	}
	// RFC 4211 §4.1 signs the DER POPOSigningKeyInput SEQUENCE. The Insta Certifier 10
	// cmpclient signs the element as it appears in the message, with its [0] tag.
	signed := [][]byte{wrapASN1(cbasn1.SEQUENCE, input.raw)}
	if opts.AllowPoposkInputVariants {
		signed = append(signed, wrapASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), input.raw))
	}
	return signed, nil
}

// poposkInputSenderMatches reports whether a poposkInput sender names opts.Sender.
// Names are compared by their DER encoding, so the string types must agree too.
func poposkInputSenderMatches(sender *GeneralName, opts POPOptions) bool {
	if opts.Sender == nil {
		return false
	}
	want := generalNameDER(opts.Sender)
	if bytes.Equal(generalNameDER(sender), want) {
		return true
	}
	// The Insta Certifier 10 cmpclient encodes the sender as a bare Name, without the
	// directoryName [4] tag of the GeneralName that RFC 4211 §4.1 specifies.
	if opts.AllowPoposkInputVariants && len(sender.Raw) > 0 && cbasn1.Tag(sender.Raw[0]) == cbasn1.SEQUENCE {
		name := NewDirectoryNameFromRawDER(sender.Raw)
		return bytes.Equal(generalNameDER(&name), want)
	}
	return false
}

// verifyPublicKeyMAC checks the PasswordBasedMac of a poposkInput publicKeyMAC
// against the shared secret.
func verifyPublicKeyMAC(input *popoSigningKeyInput, opts POPOptions) error {
	if len(opts.SharedSecret) == 0 {
		return &VerificationError{
			Reason: ReasonMissingSharedSecret,
			Err:    errors.New("poposkInput publicKeyMAC needs the shared secret"),
		}
	}
	// RFC 4211 §4.1: the algorithm shall be PasswordBasedMac.
	if !input.PublicKeyMAC.Algorithm.Algorithm.Equal(oidPasswordBasedMac) {
		return &VerificationError{
			Reason: ReasonUnsupportedAlgorithm,
			Err:    fmt.Errorf("publicKeyMAC algorithm %v", input.PublicKeyMAC.Algorithm.Algorithm),
		}
	}
	var p pbmParameter
	params := cryptobyte.String(input.PublicKeyMAC.Algorithm.Parameters)
	if err := p.unmarshal(&params); err != nil {
		return err
	}
	err := validatePBMIterationCount(p.IterationCount, opts.MinMACIterationCount, opts.MaxMACIterationCount)
	if err != nil {
		return err
	}
	hash, err := hashFromOID(p.OWF.Algorithm)
	if err != nil || !hash.Available() {
		return &VerificationError{Reason: ReasonUnsupportedAlgorithm, Err: fmt.Errorf("publicKeyMAC OWF %v", p.OWF.Algorithm)}
	}
	macHash, err := hmacHashFromOID(p.MAC.Algorithm)
	if err != nil || !macHash.Available() {
		return &VerificationError{Reason: ReasonUnsupportedAlgorithm, Err: fmt.Errorf("publicKeyMAC MAC %v", p.MAC.Algorithm)}
	}
	k, err := derivePBMKey(opts.SharedSecret, p.Salt, p.IterationCount, hash, macHash)
	if err != nil {
		return &VerificationError{Reason: ReasonUnsupportedAlgorithm, Err: err}
	}
	// RFC 4211 §4.1 MACs the DER SubjectPublicKeyInfo. The Insta Certifier 10
	// cmpclient MACs only the subjectPublicKey bits.
	macked := [][]byte{input.PublicKey}
	if opts.AllowPoposkInputVariants {
		keyBits, err := subjectPublicKeyBits(input.PublicKey)
		if err != nil {
			return err
		}
		macked = append(macked, keyBits)
	}
	for _, data := range macked {
		mac := hmac.New(macHash.New, k)
		mac.Write(data)
		if subtle.ConstantTimeCompare(mac.Sum(nil), input.PublicKeyMAC.Value) == 1 {
			return nil
		}
	}
	return &VerificationError{Reason: ReasonBadMAC, Err: errors.New("poposkInput publicKeyMAC does not verify")}
}

// subjectPublicKeyBits returns the key bits of a DER SubjectPublicKeyInfo.
func subjectPublicKeyBits(spki []byte) ([]byte, error) {
	s := cryptobyte.String(spki)
	var seq cryptobyte.String
	var bits asn1.BitString
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) || !seq.SkipASN1(cbasn1.SEQUENCE) ||
		!seq.ReadASN1BitString(&bits) || bits.BitLength%8 != 0 {
		return nil, &ParseError{Detail: "invalid poposkInput publicKey"}
	}
	return bits.Bytes, nil
}

// wrapASN1 encodes content as one element with the given tag.
func wrapASN1(tag cbasn1.Tag, content []byte) []byte {
	var b cryptobyte.Builder
	b.AddASN1(tag, func(b *cryptobyte.Builder) { b.AddBytes(content) })
	return b.BytesOrPanic()
}

// generalNameDER returns the DER encoding of a GeneralName for comparison.
func generalNameDER(g *GeneralName) []byte {
	var b cryptobyte.Builder
	g.marshal(nil, &b)
	der, err := b.Bytes()
	if err != nil {
		return nil
	}
	return der
}

// firstValid returns nil when verify accepts any candidate. Otherwise it returns the error for the first one.
func firstValid(candidates [][]byte, verify func([]byte) error) error {
	var first error
	for _, data := range candidates {
		err := verify(data)
		if err == nil {
			return nil
		}
		if first == nil {
			first = err
		}
	}
	return first
}
