package pkicmp

import (
	"crypto/x509"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// PKIBody per RFC 9810 §5.1.2.
//
// PKIBody ::= CHOICE {       -- message-specific body elements
//
//	    ir       [0]  CertReqMessages,        --Initialization Request
//	    ip       [1]  CertRepMessage,         --Initialization Response
//	    cr       [2]  CertReqMessages,        --Certification Request
//	    cp       [3]  CertRepMessage,         --Certification Response
//	    p10cr    [4]  CertificationRequest,   --imported from [RFC2986]
//	    popdecc  [5]  POPODecKeyChallContent, --pop Challenge
//	    popdecr  [6]  POPODecKeyRespContent,  --pop Response
//	    kur      [7]  CertReqMessages,        --Key Update Request
//	    kup      [8]  CertRepMessage,         --Key Update Response
//	    krr      [9]  CertReqMessages,        --Key Recovery Request
//	    krp      [10] KeyRecRepContent,       --Key Recovery Response
//	    rr       [11] RevReqContent,          --Revocation Request
//	    rp       [12] RevRepContent,          --Revocation Response
//	    ccr      [13] CertReqMessages,        --Cross-Cert. Request
//	    ccp      [14] CertRepMessage,         --Cross-Cert. Response
//	    ckuann   [15] CAKeyUpdContent,        --CA Key Update Ann.
//	    cann     [16] CertAnnContent,         --Certificate Ann.
//	    rann     [17] RevAnnContent,          --Revocation Ann.
//	    crlann   [18] CRLAnnContent,          --CRL Announcement
//	    pkiconf  [19] PKIConfirmContent,      --Confirmation
//	    nested   [20] NestedMessageContent,   --Nested Message
//	    genm     [21] GenMsgContent,          --General Message
//	    genp     [22] GenRepContent,          --General Response
//	    error    [23] ErrorMsgContent,        --Error Message
//	    certConf [24] CertConfirmContent,     --Certificate Confirm
//	    pollReq  [25] PollReqContent,         --Polling Request
//	    pollRep  [26] PollRepContent          --Polling Response
//	}
//
// PKIBody handles the CHOICE elements by lazily parsing the underlying
// CHOICE variant. An PKIBody instance only ever represents a single CHOICE variant
// determined at parse time.
//
// PKIBody is not thread-safe. Concurrent access must be synchronized by the caller.
type PKIBody struct {
	// Type identifies which CMP body variant is present.
	Type  BodyType
	Raw   []byte // Raw DER of the CHOICE element (including context tag)
	dirty bool   // true when constructed or modified; marshal re-encodes instead of using Raw
	err   error

	// Lazy parsed fields (pointers to the decoded types)
	ir       *CertReqMessages
	ip       *CertRepMessage
	cr       *CertReqMessages
	cp       *CertRepMessage
	p10cr    *x509.CertificateRequest
	popdecc  *POPODecKeyChallContent
	popdecr  *POPODecKeyRespContent
	kur      *CertReqMessages
	kup      *CertRepMessage
	rr       *RevReqContent
	rp       *RevRepContent
	certConf *CertConfirmContent
	pkiConf  *PKIConfirmContent
	pollReq  *PollReqContent
	pollRep  *PollRepContent
	errorMsg *ErrorMsgContent
	nested   []*PKIMessage
	genm     *GenMsgContent
	genp     *GenRepContent
}

type BodyType cbasn1.Tag

const (
	classContextSpecific = 0x80 // bit 8 set
	classConstructed     = 0x20 // bit 6 set
)

const (
	BodyTypeIR       = BodyType(0 | classContextSpecific | classConstructed)
	BodyTypeIP       = BodyType(1 | classContextSpecific | classConstructed)
	BodyTypeCR       = BodyType(2 | classContextSpecific | classConstructed)
	BodyTypeCP       = BodyType(3 | classContextSpecific | classConstructed)
	BodyTypeP10CR    = BodyType(4 | classContextSpecific | classConstructed)
	BodyTypePopDecC  = BodyType(5 | classContextSpecific | classConstructed) // RFC 9810 §5.2.8.3.3: POPODecKeyChallContent
	BodyTypePopDecR  = BodyType(6 | classContextSpecific | classConstructed) // RFC 9810 §5.2.8.3.3: POPODecKeyRespContent
	BodyTypeKUR      = BodyType(7 | classContextSpecific | classConstructed)
	BodyTypeKUP      = BodyType(8 | classContextSpecific | classConstructed)
	BodyTypeRR       = BodyType(11 | classContextSpecific | classConstructed)
	BodyTypeRP       = BodyType(12 | classContextSpecific | classConstructed)
	BodyTypePKIConf  = BodyType(19 | classContextSpecific | classConstructed)
	BodyTypeNested   = BodyType(20 | classContextSpecific | classConstructed) // RFC 9810 §5.1.2: NestedMessageContent
	BodyTypeGenM     = BodyType(21 | classContextSpecific | classConstructed) // RFC 9810 §5.3.19: GenMsgContent
	BodyTypeGenP     = BodyType(22 | classContextSpecific | classConstructed) // RFC 9810 §5.3.20: GenRepContent
	BodyTypeError    = BodyType(23 | classContextSpecific | classConstructed)
	BodyTypeCertConf = BodyType(24 | classContextSpecific | classConstructed)
	BodyTypePollReq  = BodyType(25 | classContextSpecific | classConstructed)
	BodyTypePollRep  = BodyType(26 | classContextSpecific | classConstructed)
)

// String returns the short lowercase name for the body type, e.g. "ir", "ip".
func (t BodyType) String() string {
	switch t {
	case BodyTypeIR:
		return "ir"
	case BodyTypeIP:
		return "ip"
	case BodyTypeCR:
		return "cr"
	case BodyTypeCP:
		return "cp"
	case BodyTypeP10CR:
		return "p10cr"
	case BodyTypePopDecC:
		return "popdecc"
	case BodyTypePopDecR:
		return "popdecr"
	case BodyTypeKUR:
		return "kur"
	case BodyTypeKUP:
		return "kup"
	case BodyTypeRR:
		return "rr"
	case BodyTypeRP:
		return "rp"
	case BodyTypePKIConf:
		return "pkiconf"
	case BodyTypeNested:
		return "nested"
	case BodyTypeGenM:
		return "genm"
	case BodyTypeGenP:
		return "genp"
	case BodyTypeError:
		return "error"
	case BodyTypeCertConf:
		return "certConf"
	case BodyTypePollReq:
		return "pollReq"
	case BodyTypePollRep:
		return "pollRep"
	default:
		return fmt.Sprintf("BodyType(%d)", int(t))
	}
}

func (b *PKIBody) unmarshal(s *cryptobyte.String) error {
	b.Raw = []byte(*s)
	var content cryptobyte.String
	var tag cbasn1.Tag
	if !s.ReadAnyASN1(&content, &tag) {
		return &ParseError{Detail: "missing PKIBody tag"}
	}
	if tag.ContextSpecific() != tag {
		return &ParseError{Detail: fmt.Sprintf("invalid PKIBody tag: %d", tag)}
	}
	b.Type = BodyType(tag)
	return nil
}

func (b *PKIBody) marshal(mctx *marshalContext, builder *cryptobyte.Builder) {
	if len(b.Raw) > 0 && !b.dirty {
		builder.AddBytes(b.Raw)
		return
	}

	builder.AddASN1(cbasn1.Tag(b.Type), func(builder *cryptobyte.Builder) {
		switch b.Type {
		case BodyTypeIR:
			b.ir.marshal(mctx, builder)
		case BodyTypeIP:
			b.ip.marshal(mctx, builder)
		case BodyTypeCR:
			b.cr.marshal(mctx, builder)
		case BodyTypeCP:
			b.cp.marshal(mctx, builder)
		case BodyTypeP10CR:
			builder.AddBytes(b.p10cr.Raw)
		case BodyTypePopDecC:
			b.popdecc.marshal(mctx, builder)
		case BodyTypePopDecR:
			b.popdecr.marshal(mctx, builder)
		case BodyTypeKUR:
			b.kur.marshal(mctx, builder)
		case BodyTypeKUP:
			b.kup.marshal(mctx, builder)
		case BodyTypeRR:
			b.rr.marshal(mctx, builder)
		case BodyTypeRP:
			b.rp.marshal(mctx, builder)
		case BodyTypeCertConf:
			b.certConf.marshal(mctx, builder)
		case BodyTypePKIConf:
			b.pkiConf.marshal(mctx, builder)
		case BodyTypePollReq:
			b.pollReq.marshal(mctx, builder)
		case BodyTypePollRep:
			b.pollRep.marshal(mctx, builder)
		case BodyTypeError:
			b.errorMsg.marshal(mctx, builder)
		case BodyTypeGenM:
			b.genm.marshal(mctx, builder)
		case BodyTypeGenP:
			b.genp.marshal(mctx, builder)
		case BodyTypeNested:
			if len(b.nested) == 0 {
				builder.SetError(&ParseError{Detail: "nested body requires at least one message"})
				return
			}
			builder.AddASN1(cbasn1.SEQUENCE, func(builder *cryptobyte.Builder) {
				for _, msg := range b.nested {
					if msg == nil {
						builder.SetError(&ParseError{Detail: "nil message in nested body"})
						return
					}
					der, err := msg.marshalForNesting()
					if err != nil {
						builder.SetError(err)
						return
					}
					builder.AddBytes(der)
				}
			})
		default:
			// Should not happen if correctly constructed
			builder.AddBytes(b.Raw)
		}
	})
}

// Getters

func (b *PKIBody) IR() (*CertReqMessages, error) {
	if b.Type != BodyTypeIR {
		return nil, &ParseError{Detail: fmt.Sprintf("body is not ir (type %s)", b.Type)}
	}
	if b.ir == nil && b.err == nil {
		b.ir = &CertReqMessages{}
		b.err = b.unmarshalBodyContent(b.ir)
	}
	return b.ir, b.err
}

func (b *PKIBody) CR() (*CertReqMessages, error) {
	if b.Type != BodyTypeCR {
		return nil, &ParseError{Detail: fmt.Sprintf("body is not cr (type %s)", b.Type)}
	}
	if b.cr == nil && b.err == nil {
		b.cr = &CertReqMessages{}
		b.err = b.unmarshalBodyContent(b.cr)
	}
	return b.cr, b.err
}

func (b *PKIBody) KUR() (*CertReqMessages, error) {
	if b.Type != BodyTypeKUR {
		return nil, &ParseError{Detail: fmt.Sprintf("body is not kur (type %s)", b.Type)}
	}
	if b.kur == nil && b.err == nil {
		b.kur = &CertReqMessages{}
		b.err = b.unmarshalBodyContent(b.kur)
	}
	return b.kur, b.err
}

// CertReqMessages returns the CertReqMessages for IR, CR, or KUR body types.
// This is a convenience method that dispatches to the appropriate getter.
func (b *PKIBody) CertReqMessages() (*CertReqMessages, error) {
	switch b.Type {
	case BodyTypeIR:
		return b.IR()
	case BodyTypeCR:
		return b.CR()
	case BodyTypeKUR:
		return b.KUR()
	default:
		return nil, &ParseError{Detail: fmt.Sprintf("body type %s is not a cert request", b.Type)}
	}
}

func (b *PKIBody) KUP() (*CertRepMessage, error) {
	if b.Type != BodyTypeKUP {
		return nil, &ParseError{Detail: fmt.Sprintf("body is not kup (type %s)", b.Type)}
	}
	if b.kup == nil && b.err == nil {
		b.kup = &CertRepMessage{}
		b.err = b.unmarshalBodyContent(b.kup)
	}
	return b.kup, b.err
}

func (b *PKIBody) P10CR() (*x509.CertificateRequest, error) {
	if b.Type != BodyTypeP10CR {
		return nil, &ParseError{Detail: fmt.Sprintf("body is not p10cr (type %s)", b.Type)}
	}
	if b.p10cr != nil || b.err != nil {
		return b.p10cr, b.err
	}

	if len(b.Raw) == 0 {
		var builder cryptobyte.Builder
		builder.AddASN1(cbasn1.Tag(BodyTypeP10CR), func(b2 *cryptobyte.Builder) {
			b2.AddBytes(b.p10cr.Raw)
		})
		var err error
		b.Raw, err = builder.Bytes()
		if err != nil {
			b.err = err
			return nil, err
		}
	}
	s := cryptobyte.String(b.Raw)
	var sub cryptobyte.String
	if !s.ReadASN1(&sub, cbasn1.Tag(BodyTypeP10CR)) {
		b.err = &ParseError{Detail: "invalid p10cr body"}
		return nil, b.err
	}
	b.p10cr, b.err = x509.ParseCertificateRequest(sub)
	return b.p10cr, b.err
}

// PopDecC returns the challenges of a popdecc body (RFC 9810 §5.2.8.3.3).
func (b *PKIBody) PopDecC() (*POPODecKeyChallContent, error) {
	if b.Type != BodyTypePopDecC {
		return nil, &ParseError{Detail: fmt.Sprintf("body is not popdecc (type %s)", b.Type)}
	}
	if b.popdecc == nil && b.err == nil {
		b.popdecc = &POPODecKeyChallContent{}
		b.err = b.unmarshalBodyContent(b.popdecc)
	}
	return b.popdecc, b.err
}

// PopDecR returns the answers of a popdecr body (RFC 9810 §5.2.8.3.3).
func (b *PKIBody) PopDecR() (*POPODecKeyRespContent, error) {
	if b.Type != BodyTypePopDecR {
		return nil, &ParseError{Detail: fmt.Sprintf("body is not popdecr (type %s)", b.Type)}
	}
	if b.popdecr == nil && b.err == nil {
		b.popdecr = &POPODecKeyRespContent{}
		b.err = b.unmarshalBodyContent(b.popdecr)
	}
	return b.popdecr, b.err
}

func (b *PKIBody) CP() (*CertRepMessage, error) {
	if b.Type != BodyTypeCP {
		return nil, &ParseError{Detail: fmt.Sprintf("body is not cp (type %s)", b.Type)}
	}
	if b.cp == nil && b.err == nil {
		b.cp = &CertRepMessage{}
		b.err = b.unmarshalBodyContent(b.cp)
	}
	return b.cp, b.err
}

func (b *PKIBody) IP() (*CertRepMessage, error) {
	if b.Type != BodyTypeIP {
		return nil, &ParseError{Detail: fmt.Sprintf("body is not ip (type %s)", b.Type)}
	}
	if b.ip == nil && b.err == nil {
		b.ip = &CertRepMessage{}
		b.err = b.unmarshalBodyContent(b.ip)
	}
	return b.ip, b.err
}

// RR returns the revocation request content (RFC 9810 §5.3.9).
func (b *PKIBody) RR() (*RevReqContent, error) {
	if b.Type != BodyTypeRR {
		return nil, &ParseError{Detail: fmt.Sprintf("body is not rr (type %s)", b.Type)}
	}
	if b.rr == nil && b.err == nil {
		b.rr = &RevReqContent{}
		b.err = b.unmarshalBodyContent(b.rr)
	}
	return b.rr, b.err
}

// RP returns the revocation response content (RFC 9810 §5.3.10).
func (b *PKIBody) RP() (*RevRepContent, error) {
	if b.Type != BodyTypeRP {
		return nil, &ParseError{Detail: fmt.Sprintf("body is not rp (type %s)", b.Type)}
	}
	if b.rp == nil && b.err == nil {
		b.rp = &RevRepContent{}
		b.err = b.unmarshalBodyContent(b.rp)
	}
	return b.rp, b.err
}

func (b *PKIBody) CertConf() (*CertConfirmContent, error) {
	if b.Type != BodyTypeCertConf {
		return nil, &ParseError{Detail: fmt.Sprintf("body is not certConf (type %s)", b.Type)}
	}
	if b.certConf == nil && b.err == nil {
		b.certConf = &CertConfirmContent{}
		b.err = b.unmarshalBodyContent(b.certConf)
	}
	return b.certConf, b.err
}

func (b *PKIBody) PKIConf() (*PKIConfirmContent, error) {
	if b.Type != BodyTypePKIConf {
		return nil, &ParseError{Detail: fmt.Sprintf("body is not pkiconf (type %s)", b.Type)}
	}
	if b.pkiConf == nil && b.err == nil {
		b.pkiConf = &PKIConfirmContent{}
		b.err = b.unmarshalBodyContent(b.pkiConf)
	}
	return b.pkiConf, b.err
}

func (b *PKIBody) PollReq() (*PollReqContent, error) {
	if b.Type != BodyTypePollReq {
		return nil, &ParseError{Detail: fmt.Sprintf("body is not pollReq (type %s)", b.Type)}
	}
	if b.pollReq == nil && b.err == nil {
		b.pollReq = &PollReqContent{}
		b.err = b.unmarshalBodyContent(b.pollReq)
	}
	return b.pollReq, b.err
}

func (b *PKIBody) PollRep() (*PollRepContent, error) {
	if b.Type != BodyTypePollRep {
		return nil, &ParseError{Detail: fmt.Sprintf("body is not pollRep (type %s)", b.Type)}
	}
	if b.pollRep == nil && b.err == nil {
		b.pollRep = &PollRepContent{}
		b.err = b.unmarshalBodyContent(b.pollRep)
	}
	return b.pollRep, b.err
}

func (b *PKIBody) Error() (*ErrorMsgContent, error) {
	if b.Type != BodyTypeError {
		return nil, &ParseError{Detail: fmt.Sprintf("body is not error (type %s)", b.Type)}
	}
	if b.errorMsg == nil && b.err == nil {
		b.errorMsg = &ErrorMsgContent{}
		b.err = b.unmarshalBodyContent(b.errorMsg)
	}
	return b.errorMsg, b.err
}

// GenM returns the general message content (RFC 9810 §5.3.19).
func (b *PKIBody) GenM() (*GenMsgContent, error) {
	if b.Type != BodyTypeGenM {
		return nil, &ParseError{Detail: fmt.Sprintf("body is not genm (type %s)", b.Type)}
	}
	if b.genm == nil && b.err == nil {
		b.genm = &GenMsgContent{}
		b.err = b.unmarshalBodyContent(b.genm)
	}
	return b.genm, b.err
}

// GenP returns the general response content (RFC 9810 §5.3.20).
func (b *PKIBody) GenP() (*GenRepContent, error) {
	if b.Type != BodyTypeGenP {
		return nil, &ParseError{Detail: fmt.Sprintf("body is not genp (type %s)", b.Type)}
	}
	if b.genp == nil && b.err == nil {
		b.genp = &GenRepContent{}
		b.err = b.unmarshalBodyContent(b.genp)
	}
	return b.genp, b.err
}

// Nested returns the messages carried by a nested [20] body.
//
// RFC 9810 §5.1.3.5 and RFC 4210 §5.1.3.4 both define NestedMessageContent as
// PKIMessages, a SEQUENCE SIZE (1..MAX) OF PKIMessage.
func (b *PKIBody) Nested() ([]*PKIMessage, error) {
	if b.Type != BodyTypeNested {
		return nil, &ParseError{Detail: fmt.Sprintf("body is not nested (type %s)", b.Type)}
	}
	if b.nested == nil && b.err == nil {
		b.nested, b.err = parseNestedMessages(b.Raw)
	}
	return b.nested, b.err
}

// parseNestedMessages decodes the PKIMessages inside a DER nested [20] body element.
func parseNestedMessages(raw []byte) ([]*PKIMessage, error) {
	s := cryptobyte.String(raw)
	var content, seq cryptobyte.String
	if !s.ReadASN1(&content, cbasn1.Tag(BodyTypeNested)) || !content.ReadASN1(&seq, cbasn1.SEQUENCE) || !content.Empty() {
		return nil, &ParseError{Detail: "invalid nested body content"}
	}
	var msgs []*PKIMessage
	for !seq.Empty() {
		var elem cryptobyte.String
		if !seq.ReadASN1Element(&elem, cbasn1.SEQUENCE) {
			return nil, &ParseError{Detail: "invalid message in nested body"}
		}
		msg, err := ParsePKIMessage(elem)
		if err != nil {
			return nil, &ParseError{Detail: "nested message", Err: err}
		}
		msgs = append(msgs, msg)
	}
	if len(msgs) == 0 {
		return nil, &ParseError{Detail: "nested body contains no messages"}
	}
	return msgs, nil
}

func (b *PKIBody) unmarshalBodyContent(p interface {
	unmarshal(s *cryptobyte.String) error
	marshal(mctx *marshalContext, b *cryptobyte.Builder)
}) error {
	if len(b.Raw) == 0 {
		var builder cryptobyte.Builder
		// Use a temporary context for this internal marshaling
		p.marshal(&marshalContext{MinRequiredPVNO: PVNO2}, &builder)
		var err error
		b.Raw, err = builder.Bytes()
		if err != nil {
			return err
		}
	}
	s := cryptobyte.String(b.Raw)
	var sub cryptobyte.String
	if !s.ReadASN1(&sub, cbasn1.Tag(b.Type)) {
		return &ParseError{Detail: fmt.Sprintf("invalid body content for type %s", b.Type)}
	}
	return p.unmarshal(&sub)
}

// Constructors

func NewIRBody(req *CertReqMessages) *PKIBody {
	return &PKIBody{Type: BodyTypeIR, ir: req, dirty: true}
}

func NewCRBody(req *CertReqMessages) *PKIBody {
	return &PKIBody{Type: BodyTypeCR, cr: req, dirty: true}
}

func NewKURBody(req *CertReqMessages) *PKIBody {
	return &PKIBody{Type: BodyTypeKUR, kur: req, dirty: true}
}

func NewKUPBody(rep *CertRepMessage) *PKIBody {
	return &PKIBody{Type: BodyTypeKUP, kup: rep, dirty: true}
}

func NewP10CRBody(csr *x509.CertificateRequest) *PKIBody {
	return &PKIBody{Type: BodyTypeP10CR, p10cr: csr, dirty: true}
}

// NewPopDecCBody creates a popdecc body carrying proof-of-possession challenges (RFC 9810 §5.2.8.3.3).
func NewPopDecCBody(challenges *POPODecKeyChallContent) *PKIBody {
	return &PKIBody{Type: BodyTypePopDecC, popdecc: challenges, dirty: true}
}

// NewPopDecRBody creates a popdecr body carrying the answers to a popdecc (RFC 9810 §5.2.8.3.3).
func NewPopDecRBody(answers *POPODecKeyRespContent) *PKIBody {
	return &PKIBody{Type: BodyTypePopDecR, popdecr: answers, dirty: true}
}

func NewCPBody(rep *CertRepMessage) *PKIBody {
	return &PKIBody{Type: BodyTypeCP, cp: rep, dirty: true}
}

func NewIPBody(rep *CertRepMessage) *PKIBody {
	return &PKIBody{Type: BodyTypeIP, ip: rep, dirty: true}
}

// NewRRBody creates a revocation request body (RFC 9810 §5.3.9).
func NewRRBody(req *RevReqContent) *PKIBody {
	return &PKIBody{Type: BodyTypeRR, rr: req, dirty: true}
}

// NewRPBody creates a revocation response body (RFC 9810 §5.3.10).
func NewRPBody(rep *RevRepContent) *PKIBody {
	return &PKIBody{Type: BodyTypeRP, rp: rep, dirty: true}
}

func NewCertConfBody(conf *CertConfirmContent) *PKIBody {
	return &PKIBody{Type: BodyTypeCertConf, certConf: conf, dirty: true}
}

func NewPKIConfBody() *PKIBody {
	return &PKIBody{Type: BodyTypePKIConf, pkiConf: &PKIConfirmContent{}, dirty: true}
}

func NewPollReqBody(req *PollReqContent) *PKIBody {
	return &PKIBody{Type: BodyTypePollReq, pollReq: req, dirty: true}
}

func NewPollRepBody(rep *PollRepContent) *PKIBody {
	return &PKIBody{Type: BodyTypePollRep, pollRep: rep, dirty: true}
}

func NewErrorBody(err *ErrorMsgContent) *PKIBody {
	return &PKIBody{Type: BodyTypeError, errorMsg: err, dirty: true}
}

// NewGenMBody creates a general message body (RFC 9810 §5.3.19). RFC 9483 §4.3
// sends exactly one item.
func NewGenMBody(items ...InfoTypeAndValue) *PKIBody {
	content := GenMsgContent(items)
	return &PKIBody{Type: BodyTypeGenM, genm: &content, dirty: true}
}

// NewGenPBody creates a general response body (RFC 9810 §5.3.20).
func NewGenPBody(items ...InfoTypeAndValue) *PKIBody {
	content := GenRepContent(items)
	return &PKIBody{Type: BodyTypeGenP, genp: &content, dirty: true}
}

// NewNestedBody creates a nested [20] body carrying one or more messages (RFC 9810 §5.1.3.5).
//
// A protected message keeps the exact header and body bytes its protection was
// computed over, so a received message is forwarded without breaking its
// protection. An unprotected message is encoded from its fields.
func NewNestedBody(msgs ...*PKIMessage) *PKIBody {
	return &PKIBody{Type: BodyTypeNested, nested: msgs, dirty: true}
}
