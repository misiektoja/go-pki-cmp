package pkicmp

import (
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

const (
	PVNO1 = 1 // CMP1999 CMPv1 (not supported)
	PVNO2 = 2 // CMP2000 CMPv2
	PVNO3 = 3 // CMP2021 CMPv3
)

// MessageOptions configures PKIMessage header fields.
type MessageOptions struct {
	Sender        GeneralName
	Recipient     GeneralName
	TransactionID []byte // auto-generated (16 random bytes) if nil
	SenderNonce   []byte // auto-generated (16 random bytes) if nil
	RecipNonce    []byte // echo from previous message
}

// NewPKIMessage creates a PKIMessage with the given body and header options.
// TransactionID and SenderNonce default to 128 bits of random data per
// RFC 9810 §5.1.1. Sets MessageTime to time.Now(). Panics if random number
// generation fails — this indicates a broken system (crypto/rand failure is
// unrecoverable; Go's own crypto/tls panics on this condition).
func NewPKIMessage(body *PKIBody, opts MessageOptions) *PKIMessage {
	txnID := opts.TransactionID
	if txnID == nil {
		txnID = make([]byte, 16)
		if _, err := rand.Read(txnID); err != nil {
			panic("pkicmp: crypto/rand.Read failed: " + err.Error())
		}
	}
	senderNonce := opts.SenderNonce
	if senderNonce == nil {
		senderNonce = make([]byte, 16)
		if _, err := rand.Read(senderNonce); err != nil {
			panic("pkicmp: crypto/rand.Read failed: " + err.Error())
		}
	}

	return &PKIMessage{
		Header: PKIHeader{
			PVNO:          PVNO2,
			Sender:        opts.Sender,
			Recipient:     opts.Recipient,
			MessageTime:   time.Now(),
			TransactionID: txnID,
			SenderNonce:   senderNonce,
			RecipNonce:    opts.RecipNonce,
		},
		Body: body,
	}
}

// All types that participate in recursive DER encoding implement:
//
//     marshal(mctx *marshalContext, b *cryptobyte.Builder)
//     unmarshal(s *cryptobyte.String) error
//
// PKIMessage is the top-level entry point and instead exposes the standard
// encoding.BinaryMarshaler / encoding.BinaryUnmarshaler interfaces, delegating
// to the internal marshal/unmarshal methods of its components.
// New types added to the encoding tree must implement both methods.

// marshalContext holds state and configuration for the marshaling process.
type marshalContext struct {
	// MinRequiredPVNO is the minimum Protocol Version Number (PVNO) required
	// by the features used in the message.
	// Per RFC 9810 §7: "Version cmp2021 SHOULD only be used if cmp2021 syntax
	// is needed for the request being sent or for the expected response."
	MinRequiredPVNO int
}

// PKIMessage per RFC 9810 §5.1.
//
//	PKIMessage ::= SEQUENCE {
//	    header           PKIHeader,
//	    body             PKIBody,
//	    protection   [0] PKIProtection OPTIONAL,
//	    extraCerts   [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate
//	                  OPTIONAL }
type PKIMessage struct {
	// Header contains routing, identity, and transaction metadata.
	Header PKIHeader
	// Body contains the operation payload (for example IR, CR, IP, CP, or poll).
	Body *PKIBody
	// Protection is the signature or MAC over header+body.
	Protection []byte
	// ExtraCerts provides optional helper certificates for path building.
	ExtraCerts []CMPCertificate

	// rawHeader is the exact DER-encoded header element used for protection verification.
	rawHeader []byte
	// rawBody is the exact DER-encoded body element used for protection verification.
	rawBody []byte
}

// PKIHeader per RFC 9810 §5.1.1.
//
//	PKIHeader ::= SEQUENCE {
//	   pvno                INTEGER     { cmp1999(1), cmp2000(2),
//	                                     cmp2021(3) },
//	   sender              GeneralName,
//	   recipient           GeneralName,
//	   messageTime     [0] GeneralizedTime         OPTIONAL,
//	   protectionAlg   [1] AlgorithmIdentifier{ALGORITHM, {...}}
//	                       OPTIONAL,
//	   senderKID       [2] KeyIdentifier           OPTIONAL,
//	   recipKID        [3] KeyIdentifier           OPTIONAL,
//	   transactionID   [4] OCTET STRING            OPTIONAL,
//	   senderNonce     [5] OCTET STRING            OPTIONAL,
//	   recipNonce      [6] OCTET STRING            OPTIONAL,
//	   freeText        [7] PKIFreeText             OPTIONAL,
//	   generalInfo     [8] SEQUENCE SIZE (1..MAX) OF
//	                       InfoTypeAndValue     OPTIONAL
//	}
type PKIHeader struct {
	// PVNO selects CMP syntax/version expectations for this message.
	PVNO int
	// Sender identifies who created the message.
	Sender GeneralName
	// Recipient identifies the intended CA/RA endpoint.
	Recipient GeneralName
	// MessageTime is the sender timestamp used for freshness checks.
	MessageTime time.Time
	// ProtectionAlg tells verifiers which signature/MAC algorithm to use.
	ProtectionAlg *AlgorithmIdentifier
	// SenderKID points to the sender key used for protection.
	SenderKID []byte
	// RecipKID points to the recipient key expected to verify/decrypt.
	RecipKID []byte
	// TransactionID correlates all messages in one enrollment flow.
	TransactionID []byte
	// SenderNonce is a client-generated anti-replay nonce.
	SenderNonce []byte
	// RecipNonce should echo the peer nonce from the previous message.
	RecipNonce []byte
	// FreeText carries human-readable diagnostics.
	FreeText PKIFreeText
	// GeneralInfo carries typed extensions and protocol hints.
	GeneralInfo []InfoTypeAndValue

	// messageTimePresent records that messageTime was on the wire. The zero
	// time is a legal GeneralizedTime, so MessageTime alone cannot tell an
	// absent field from a peer that sent 00010101000000Z.
	messageTimePresent bool
}

// HasMessageTime reports whether the header carries a messageTime.
func (h *PKIHeader) HasMessageTime() bool { return h.messageTimePresent || !h.MessageTime.IsZero() }

// ParsePKIMessage parses the DER encoding of a PKIMessage.
func ParsePKIMessage(der []byte) (*PKIMessage, error) {
	msg := &PKIMessage{}
	if err := msg.UnmarshalBinary(der); err != nil {
		return nil, err
	}
	return msg, nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
//
// A failure after the header was decoded returns a [ParseError] whose Header
// field holds a copy of that header.
func (m *PKIMessage) UnmarshalBinary(data []byte) error {
	s := cryptobyte.String(data)
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return &ParseError{Detail: "invalid PKIMessage sequence"}
	}

	// PKIHeader
	var rawHeader cryptobyte.String
	var headerTag cbasn1.Tag
	if !seq.ReadAnyASN1Element(&rawHeader, &headerTag) {
		return &ParseError{Detail: "missing PKIHeader"}
	}
	m.rawHeader = rawHeader
	if err := m.Header.unmarshal(&rawHeader); err != nil {
		return err
	}
	if err := m.unmarshalAfterHeader(&s, &seq); err != nil {
		return withHeader(err, m.Header)
	}
	return nil
}

// withHeader attaches a copy of header to err, a failure to decode the message after that header.
func withHeader(err error, header PKIHeader) error {
	if pe, ok := errors.AsType[*ParseError](err); ok {
		pe.Header = &header
		return err
	}
	return &ParseError{Detail: "invalid PKIMessage", Err: err, Header: &header}
}

// unmarshalAfterHeader decodes the body, protection and extraCerts that follow the header in seq
// and checks that the extraCerts wrapper, seq and s, the input after the message, hold no trailing
// data.
func (m *PKIMessage) unmarshalAfterHeader(s, seq *cryptobyte.String) error {
	// PKIBody
	var rawBody cryptobyte.String
	var bodyTag cbasn1.Tag
	if !seq.ReadAnyASN1Element(&rawBody, &bodyTag) {
		return &ParseError{Detail: "missing PKIBody"}
	}
	m.rawBody = rawBody
	var body PKIBody
	if err := body.unmarshal(&rawBody); err != nil {
		return err
	}
	m.Body = &body

	// protection [0] PKIProtection OPTIONAL
	if seq.PeekASN1Tag(cbasn1.Tag(0).ContextSpecific().Constructed()) {
		var protectionSeq cryptobyte.String
		if !seq.ReadASN1(&protectionSeq, cbasn1.Tag(0).ContextSpecific().Constructed()) {
			return &ParseError{Detail: "invalid protection tag"}
		}
		var bitString cryptobyte.String
		if !protectionSeq.ReadASN1(&bitString, cbasn1.BIT_STRING) {
			return &ParseError{Detail: "invalid protection BIT STRING"}
		}
		var unused uint8
		if !bitString.ReadUint8(&unused) {
			return &ParseError{Detail: "invalid protection unused bits"}
		}
		m.Protection = bitString
	}

	// extraCerts [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate OPTIONAL
	if seq.PeekASN1Tag(cbasn1.Tag(1).ContextSpecific().Constructed()) {
		var extraCertsSeq cryptobyte.String
		if !seq.ReadASN1(&extraCertsSeq, cbasn1.Tag(1).ContextSpecific().Constructed()) {
			return &ParseError{Detail: "invalid extraCerts tag"}
		}
		var certsSeq cryptobyte.String
		if !extraCertsSeq.ReadASN1(&certsSeq, cbasn1.SEQUENCE) {
			return &ParseError{Detail: "invalid extraCerts sequence"}
		}
		for !certsSeq.Empty() {
			var cert CMPCertificate
			if err := cert.unmarshal(&certsSeq); err != nil {
				return err
			}
			m.ExtraCerts = append(m.ExtraCerts, cert)
		}
		// The wrapper is EXPLICIT, so nothing may follow the SEQUENCE inside it.
		if !extraCertsSeq.Empty() {
			return &ParseError{Detail: "trailing data inside extraCerts"}
		}
	}

	if !seq.Empty() {
		return &ParseError{Detail: "trailing data inside PKIMessage sequence"}
	}

	if !s.Empty() {
		return &ParseError{Detail: "trailing data after PKIMessage"}
	}

	return nil
}

// MarshalBinary implements encoding.BinaryMarshaler.
func (m *PKIMessage) MarshalBinary() ([]byte, error) {
	if m.Body == nil {
		return nil, &ParseError{Detail: detailMissingMessageBody}
	}

	// 1. Marshal body first to discover required PVNO
	mctx := &marshalContext{MinRequiredPVNO: PVNO2}
	if m.Header.PVNO > PVNO2 {
		mctx.MinRequiredPVNO = m.Header.PVNO
	}

	var bodyBuilder cryptobyte.Builder
	m.Body.marshal(mctx, &bodyBuilder)
	bodyBytes, err := bodyBuilder.Bytes()
	if err != nil {
		return nil, err
	}

	// 2. Update Header PVNO
	m.Header.PVNO = mctx.MinRequiredPVNO

	// 3. Marshal full message
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		m.Header.marshal(mctx, b)
		b.AddBytes(bodyBytes)
		m.marshalTrailer(mctx, b)
	})
	return b.Bytes()
}

// marshalForNesting encodes the message for a nested body, reusing the header
// and body bytes a protected message was protected over.
//
// Re-encoding a received header from its decoded fields need not reproduce the
// original bytes, and any difference would invalidate the protection the
// receiver of the nested message verifies.
func (m *PKIMessage) marshalForNesting() ([]byte, error) {
	if len(m.Protection) == 0 || len(m.rawHeader) == 0 || len(m.rawBody) == 0 {
		return m.MarshalBinary()
	}
	mctx := &marshalContext{MinRequiredPVNO: max(m.Header.PVNO, PVNO2)}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(m.rawHeader)
		b.AddBytes(m.rawBody)
		m.marshalTrailer(mctx, b)
	})
	return b.Bytes()
}

// marshalTrailer adds the optional protection and extraCerts fields that follow the body.
func (m *PKIMessage) marshalTrailer(mctx *marshalContext, b *cryptobyte.Builder) {
	if len(m.Protection) > 0 {
		b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.BIT_STRING, func(b *cryptobyte.Builder) {
				b.AddUint8(0) // No unused bits for now
				b.AddBytes(m.Protection)
			})
		})
	}

	if len(m.ExtraCerts) > 0 {
		b.AddASN1(cbasn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				for _, cert := range m.ExtraCerts {
					cert.marshal(mctx, b)
				}
			})
		})
	}
}

func (h *PKIHeader) unmarshal(s *cryptobyte.String) error {
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return &ParseError{Detail: "invalid PKIHeader sequence"}
	}

	// pvno
	var pvno int64
	if !seq.ReadASN1Integer(&pvno) {
		return &ParseError{Detail: "invalid pvno"}
	}
	h.PVNO = int(pvno)

	// sender
	if err := h.Sender.unmarshal(&seq); err != nil {
		return &ParseError{Detail: "sender", Err: err}
	}

	// recipient
	if err := h.Recipient.unmarshal(&seq); err != nil {
		return &ParseError{Detail: "recipient", Err: err}
	}

	// messageTime [0] GeneralizedTime OPTIONAL
	if seq.PeekASN1Tag(cbasn1.Tag(0).ContextSpecific().Constructed()) {
		var sub cryptobyte.String
		if !seq.ReadASN1(&sub, cbasn1.Tag(0).ContextSpecific().Constructed()) {
			return &ParseError{Detail: "invalid messageTime tag"}
		}
		if !sub.ReadASN1GeneralizedTime(&h.MessageTime) {
			return &ParseError{Detail: "invalid messageTime"}
		}
		h.messageTimePresent = true
	}

	// protectionAlg [1] AlgorithmIdentifier OPTIONAL
	if seq.PeekASN1Tag(cbasn1.Tag(1).ContextSpecific().Constructed()) {
		var sub cryptobyte.String
		if !seq.ReadASN1(&sub, cbasn1.Tag(1).ContextSpecific().Constructed()) {
			return &ParseError{Detail: "invalid protectionAlg tag"}
		}
		h.ProtectionAlg = &AlgorithmIdentifier{}
		if err := h.ProtectionAlg.unmarshal(&sub); err != nil {
			return err
		}
	}

	// senderKID [2] KeyIdentifier OPTIONAL (OCTET STRING)
	if err := readOptionalOctetString(&seq, 2, "senderKID", &h.SenderKID); err != nil {
		return err
	}

	// recipKID [3] KeyIdentifier OPTIONAL
	if err := readOptionalOctetString(&seq, 3, "recipKID", &h.RecipKID); err != nil {
		return err
	}

	// transactionID [4] OCTET STRING OPTIONAL
	if err := readOptionalOctetString(&seq, 4, "transactionID", &h.TransactionID); err != nil {
		return err
	}

	// senderNonce [5] OCTET STRING OPTIONAL
	if err := readOptionalOctetString(&seq, 5, "senderNonce", &h.SenderNonce); err != nil {
		return err
	}

	// recipNonce [6] OCTET STRING OPTIONAL
	if err := readOptionalOctetString(&seq, 6, "recipNonce", &h.RecipNonce); err != nil {
		return err
	}

	// freeText [7] PKIFreeText OPTIONAL
	if seq.PeekASN1Tag(cbasn1.Tag(7).ContextSpecific().Constructed()) {
		var sub cryptobyte.String
		if !seq.ReadASN1(&sub, cbasn1.Tag(7).ContextSpecific().Constructed()) {
			return &ParseError{Detail: "invalid freeText tag"}
		}
		if err := h.FreeText.unmarshal(&sub); err != nil {
			return err
		}
	}

	// generalInfo [8] SEQUENCE OF InfoTypeAndValue OPTIONAL
	return h.unmarshalGeneralInfo(&seq)
}

// readOptionalOctetString reads an optional [tagNum] header field that wraps an OCTET STRING into out.
func readOptionalOctetString(seq *cryptobyte.String, tagNum uint8, name string, out *[]byte) error {
	tag := cbasn1.Tag(tagNum).ContextSpecific().Constructed()
	if !seq.PeekASN1Tag(tag) {
		return nil
	}
	var sub cryptobyte.String
	if !seq.ReadASN1(&sub, tag) {
		return &ParseError{Detail: "invalid " + name + " tag"}
	}
	if !sub.ReadASN1Bytes(out, cbasn1.OCTET_STRING) {
		return &ParseError{Detail: "invalid " + name}
	}
	return nil
}

// unmarshalGeneralInfo reads the optional generalInfo [8] header field.
func (h *PKIHeader) unmarshalGeneralInfo(seq *cryptobyte.String) error {
	if !seq.PeekASN1Tag(cbasn1.Tag(8).ContextSpecific().Constructed()) {
		return nil
	}
	var sub cryptobyte.String
	if !seq.ReadASN1(&sub, cbasn1.Tag(8).ContextSpecific().Constructed()) {
		return &ParseError{Detail: "invalid generalInfo tag"}
	}
	var giSeq cryptobyte.String
	if !sub.ReadASN1(&giSeq, cbasn1.SEQUENCE) {
		return &ParseError{Detail: "invalid generalInfo sequence"}
	}
	for !giSeq.Empty() {
		var itv InfoTypeAndValue
		if err := itv.unmarshal(&giSeq); err != nil {
			return err
		}
		h.GeneralInfo = append(h.GeneralInfo, itv)
	}
	return nil
}

func (h *PKIHeader) marshal(mctx *marshalContext, b *cryptobyte.Builder) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(int64(h.PVNO))
		h.Sender.marshal(mctx, b)
		h.Recipient.marshal(mctx, b)

		if h.HasMessageTime() {
			b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				// X.690 §11.7: DER GeneralizedTime MUST be UTC.
				b.AddASN1GeneralizedTime(h.MessageTime.UTC())
			})
		}

		if h.ProtectionAlg != nil {
			b.AddASN1(cbasn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				h.ProtectionAlg.marshal(mctx, b)
			})
		}

		if len(h.SenderKID) > 0 {
			b.AddASN1(cbasn1.Tag(2).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.OCTET_STRING, func(b *cryptobyte.Builder) {
					b.AddBytes(h.SenderKID)
				})
			})
		}

		if len(h.RecipKID) > 0 {
			b.AddASN1(cbasn1.Tag(3).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.OCTET_STRING, func(b *cryptobyte.Builder) {
					b.AddBytes(h.RecipKID)
				})
			})
		}

		if len(h.TransactionID) > 0 {
			b.AddASN1(cbasn1.Tag(4).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.OCTET_STRING, func(b *cryptobyte.Builder) {
					b.AddBytes(h.TransactionID)
				})
			})
		}

		if len(h.SenderNonce) > 0 {
			b.AddASN1(cbasn1.Tag(5).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.OCTET_STRING, func(b *cryptobyte.Builder) {
					b.AddBytes(h.SenderNonce)
				})
			})
		}

		if len(h.RecipNonce) > 0 {
			b.AddASN1(cbasn1.Tag(6).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.OCTET_STRING, func(b *cryptobyte.Builder) {
					b.AddBytes(h.RecipNonce)
				})
			})
		}

		if len(h.FreeText) > 0 {
			b.AddASN1(cbasn1.Tag(7).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				h.FreeText.marshal(mctx, b)
			})
		}

		if len(h.GeneralInfo) > 0 {
			b.AddASN1(cbasn1.Tag(8).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					for _, itv := range h.GeneralInfo {
						itv.marshal(mctx, b)
					}
				})
			})
		}
	})
}

// NewCertProfileInfo returns the id-it-certProfile generalInfo item naming
// the requested certificate profiles (RFC 9810 §5.1.1.4). RFC 9483 §3.1
// sends one name.
func NewCertProfileInfo(names ...string) InfoTypeAndValue {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		for _, name := range names {
			b.AddASN1(cbasn1.UTF8String, func(b *cryptobyte.Builder) {
				b.AddBytes([]byte(name))
			})
		}
	})
	return InfoTypeAndValue{InfoType: oidCertProfile, InfoValue: b.BytesOrPanic()}
}

// CertProfile extracts the first certProfile name from the generalInfo header field.
// RFC 9810 §5.1.1.4: id-it-certProfile carries a SEQUENCE OF UTF8String.
// Returns empty string if not present.
func (h *PKIHeader) CertProfile() string {
	for _, itv := range h.GeneralInfo {
		if itv.InfoType.Equal(oidCertProfile) {
			var profiles []string
			if _, err := asn1.Unmarshal(itv.InfoValue, &profiles); err == nil && len(profiles) > 0 {
				return profiles[0]
			}
		}
	}
	return ""
}

// ProtectedData returns the DER-encoded ProtectedPart (SEQUENCE { header, body })
// that is signed or MAC'd when protecting the message.
// The message must have been protected first (e.g. via [Credentials.Protect]).
// This is primarily useful for testing scenarios that require manual signature
// construction (for example, to forge an invalid signature for server rejection tests).
// RFC 9810 §5.1.3.
func (m *PKIMessage) ProtectedData() ([]byte, error) {
	return m.protectedPart()
}

// protectedPart computes the DER-encoded ProtectedPart (SEQUENCE { header, body })
// used as input to both protection and verification.
// RFC 9810 §5.1.3.
func (m *PKIMessage) protectedPart() ([]byte, error) {
	if m.Body == nil {
		return nil, &ParseError{Detail: detailMissingMessageBody}
	}
	if len(m.rawHeader) == 0 || len(m.rawBody) == 0 {
		return nil, &ParseError{Detail: "raw header or body missing"}
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(m.rawHeader)
		b.AddBytes(m.rawBody)
	})
	return b.Bytes()
}
