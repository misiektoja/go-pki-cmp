package client

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"slices"
	"time"

	"github.com/misiektoja/go-pki-cmp/cms"
	"github.com/misiektoja/go-pki-cmp/internal/certpath"
	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// enroll performs the full CMP enrollment transaction:
// request → [popdecc → popdecr] → response → [poll] → certConf → pkiConf
// (RFC 9810 §5.3.1–§5.3.4, Appendix C.4). proof is the key of a request that
// proves possession by decryption, and nil for a signature proof.
func (c *Client) enroll(ctx context.Context, reqBody *pkicmp.PKIBody, expectedRepType pkicmp.BodyType, creds pkicmp.Credentials, opts *requestOptions, requestedKey crypto.PublicKey, proof *decryptionProof) (*EnrollResult, error) {
	certReqIDs, err := answeringCertReqIDs(reqBody)
	if err != nil {
		return nil, err
	}

	// The encrypted certificate, the popdecc challenge and a centrally
	// generated private key come back as EnvelopedData, which needs cmp2021,
	// so RFC 9810 §7 and RFC 9483 §4.1.6 ask for pvno 3.
	opts.cmp2021 = proof != nil || opts.centralKeyGeneration
	msg, err := c.newRequest(reqBody, creds, opts)
	if err != nil {
		return nil, err
	}

	cmpResp, vr, err := c.exchangeFirst(ctx, msg, creds)
	if err != nil {
		return nil, err
	}
	resp := cmpResp.message
	// Keep the signer authenticated here so the rest of the operation can still
	// be verified when the server stops sending extraCerts.
	var knownSigner *x509.Certificate
	if vr != nil {
		knownSigner = vr.ProtectionCertificate
	}

	// The delayed request a final response may refer back to is the popdecr when there was a challenge.
	delayed := msg.Header
	if resp.Body.Type == pkicmp.BodyTypePopDecC {
		popdecr, answered, answeredVR, err := c.answerChallenge(ctx, msg, resp, creds, proof, knownSigner)
		if err != nil {
			return nil, cmpResp.wrapError(err)
		}
		cmpResp, resp, delayed = answered, answered.message, popdecr.Header
		if answeredVR != nil {
			vr = answeredVR
			if vr.ProtectionCertificate != nil {
				knownSigner = vr.ProtectionCertificate
			}
		}
	}

	if resp.Body.Type == pkicmp.BodyTypeError {
		return nil, cmpResp.wrapError(parseErrorResponse(resp))
	}

	if resp.Body.Type != expectedRepType {
		return nil, cmpResp.wrapError(&Error{Op: fmt.Sprintf("unexpected response body type: %d", resp.Body.Type)})
	}

	certResp, rep, err := extractCertRespAndRep(resp, expectedRepType)
	if err != nil {
		return nil, cmpResp.wrapError(err)
	}

	txn := &enrollment{
		header:          msg.Header,
		requestType:     reqBody.Type,
		expectedRepType: expectedRepType,
		certReqIDs:      certReqIDs,
		requestedKey:    requestedKey,
		proof:           proof,
		central:         opts.centralKeyGeneration,
		creds:           creds,
	}
	if certResp.Status.Status == pkicmp.StatusWaiting {
		if err := checkCertReqID(certResp, certReqIDs); err != nil {
			return nil, cmpResp.wrapError(err)
		}
		state := &pollState{
			delayed:     delayed,
			recipNonce:  resp.Header.SenderNonce,
			certReqID:   certResp.CertReqID,
			knownSigner: knownSigner,
		}
		if opts.deferredPolling {
			pending, err := txn.pending(state)
			if err != nil {
				return nil, err
			}
			return &EnrollResult{Pending: pending}, nil
		}
		return c.pollEnrollment(ctx, txn, state, false)
	}
	return c.finishEnrollment(ctx, txn, cmpResp, vr, knownSigner, certResp, rep)
}

// enrollment holds what the end of an enrollment transaction needs from its first request.
type enrollment struct {
	// header is the header of the first request, whose names, transaction ID,
	// version and senderKID every later message repeats.
	header          pkicmp.PKIHeader
	requestType     pkicmp.BodyType
	expectedRepType pkicmp.BodyType
	certReqIDs      []int64
	// requestedKey is nil when central is set.
	requestedKey crypto.PublicKey
	proof        *decryptionProof
	// central marks a request that asked the CA to generate the key pair.
	central bool
	creds   pkicmp.Credentials
}

// pollEnrollment polls for the final response to a waiting enrollment and
// finishes it. With once set it sends one pollReq and returns the pending state
// while the CA still waits. A poll that stops while the request still waits
// returns a [PendingError].
func (c *Client) pollEnrollment(ctx context.Context, txn *enrollment, state *pollState, once bool) (*EnrollResult, error) {
	cmpResp, vr, err := c.poll(ctx, state, txn.creds, once)
	if err != nil {
		if state.waiting {
			if pending, pendingErr := txn.pending(state); pendingErr == nil {
				return nil, &PendingError{Pending: pending, Err: err}
			}
		}
		return nil, err
	}
	if cmpResp == nil {
		pending, err := txn.pending(state)
		if err != nil {
			return nil, err
		}
		return &EnrollResult{Pending: pending}, nil
	}
	certResp, rep, err := extractCertRespAndRep(cmpResp.message, txn.expectedRepType)
	if err != nil {
		return nil, cmpResp.wrapError(err)
	}
	return c.finishEnrollment(ctx, txn, cmpResp, vr, state.knownSigner, certResp, rep)
}

// finishEnrollment checks the final certificate response of an enrollment,
// verifies the certificate and confirms it unless the CA granted implicit
// confirmation.
func (c *Client) finishEnrollment(ctx context.Context, txn *enrollment, cmpResp *cmpHTTPResponse, vr *pkicmp.VerifyResult, knownSigner *x509.Certificate, certResp *pkicmp.CertResponse, rep *pkicmp.CertRepMessage) (*EnrollResult, error) {
	resp := cmpResp.message
	if certResp.Status.Status != pkicmp.StatusAccepted && certResp.Status.Status != pkicmp.StatusGrantedWithMods {
		return nil, cmpResp.wrapError(certResp.Status.AsError())
	}

	cert, err := extractCertificate(certResp, txn.proof)
	if err != nil {
		return nil, cmpResp.wrapError(err)
	}

	caPubs := parseCMPCertificates(rep.CAPubs)
	extraCerts := parseCMPCertificates(resp.ExtraCerts)
	trustPool := c.enrollmentTrustPool(vr, caPubs)

	// A grant of implicit confirmation ends the transaction with this response
	// (RFC 9810 §5.1.1.1). It is honored even when the request did not ask for
	// it, as OpenSSL does, because the CA has closed the transaction and would
	// refuse a certConf.
	implicit := hasImplicitConfirm(&resp.Header)
	conf := &certConfirmation{
		header: txn.header, resp: resp, creds: txn.creds, trustPool: trustPool, knownSigner: knownSigner, implicit: implicit,
	}

	// The rejection repeats the CA's certReqId, since that is the value the CA
	// uses to find the certificate.
	if err := checkCertReqID(certResp, txn.certReqIDs); err != nil {
		return nil, c.rejectCertificate(ctx, conf, cert, certResp.CertReqID,
			"certReqId does not match the request", cmpResp.wrapError(err))
	}

	// RFC 9810 §8.9: Verify the issued certificate against trusted CAs.
	if trustPool != nil {
		if err := verifyIssuedCertificate(cert, trustPool, slices.Concat(extraCerts, caPubs)); err != nil {
			return nil, c.rejectCertificate(ctx, conf, cert, certResp.CertReqID,
				"certificate validation failed", cmpResp.wrapError(&Error{Op: "verify certificate trust", Err: err}))
		}
	}

	if err := checkIssuedKey(cert, txn.requestedKey); err != nil {
		return nil, c.rejectCertificate(ctx, conf, cert, certResp.CertReqID,
			"certificate does not certify the requested public key", cmpResp.wrapError(err))
	}

	var generated *GeneratedKey
	if txn.central {
		var responder *x509.Certificate
		if vr != nil {
			responder = vr.ProtectionCertificate
		}
		candidates := slices.Concat(extraCerts, caPubs)
		generated, err = c.openGeneratedKey(certResp, cert, txn.creds, trustPool, candidates, responder)
		if err != nil {
			return nil, c.rejectCertificate(ctx, conf, cert, certResp.CertReqID,
				"the generated private key cannot be used", cmpResp.wrapError(err))
		}
	}

	if !implicit {
		// RFC 9810 requires an explicit hash when the signature does not identify one.
		certStatus, err := pkicmp.NewCertStatus(cert, certResp.CertReqID)
		if err != nil {
			return nil, cmpResp.wrapError(&Error{Op: "compute certHash", Err: err})
		}
		if err := c.sendCertConf(ctx, conf, certStatus); err != nil {
			return nil, &ConfirmationError{Certificate: cert, Err: err}
		}
	}

	return &EnrollResult{
		Certificate:       cert,
		CAPubs:            caPubs,
		ExtraCertificates: extraCerts,
		ImplicitConfirm:   implicit,
		GeneratedKey:      generated,
	}, nil
}

// hasImplicitConfirm reports whether h carries id-it-implicitConfirm in generalInfo.
func hasImplicitConfirm(h *pkicmp.PKIHeader) bool {
	oid := pkicmp.ImplicitConfirmInfoValue().InfoType
	return slices.ContainsFunc(h.GeneralInfo, func(item pkicmp.InfoTypeAndValue) bool { return item.InfoType.Equal(oid) })
}

// isCertificateRequest reports whether t is a body type that implicit confirmation applies to.
func isCertificateRequest(t pkicmp.BodyType) bool {
	return t == pkicmp.BodyTypeIR || t == pkicmp.BodyTypeCR || t == pkicmp.BodyTypeKUR || t == pkicmp.BodyTypeP10CR
}

// parseCMPCertificates parses certs and skips the entries that do not parse.
func parseCMPCertificates(certs []pkicmp.CMPCertificate) []*x509.Certificate {
	var parsed []*x509.Certificate
	for _, cert := range certs {
		if pc, err := cert.Parse(); err == nil {
			parsed = append(parsed, pc)
		}
	}
	return parsed
}

// enrollmentTrustPool returns the configured trusted CAs extended with caPubs when the response was
// MAC-verified and [WithoutCAPubsTrust] is not set.
func (c *Client) enrollmentTrustPool(vr *pkicmp.VerifyResult, caPubs []*x509.Certificate) *x509.CertPool {
	// caPubs extend the configured trusted CAs only when the response was
	// protected with the shared secret (RFC 9810 §5.3.2).
	if c.ignoreCAPubsTrust || vr == nil || !vr.MACVerified || len(caPubs) == 0 {
		return c.trustedCAs
	}
	var pool *x509.CertPool
	if c.trustedCAs != nil {
		pool = c.trustedCAs.Clone()
	} else {
		pool = x509.NewCertPool()
	}
	for _, ca := range caPubs {
		pool.AddCert(ca)
	}
	return pool
}

// verifyIssuedCertificate verifies that cert chains to roots, taking issuers from candidates.
func verifyIssuedCertificate(cert *x509.Certificate, roots *x509.CertPool, candidates []*x509.Certificate) error {
	// RFC 9810 §5.1: extraCerts carries the certificates needed to build the
	// path. A CA that issues from an intermediate returns that intermediate
	// there, so without it the chain cannot be completed against a trust
	// anchor that is the root. caPubs are candidates too, because a composite
	// ML-DSA issuer is only found among the candidates, even when it is also
	// a trust anchor.
	return certpath.Verify(cert, roots, candidates, time.Now())
}

// certConfirmation holds what a certConf needs from the enrollment exchange it confirms.
type certConfirmation struct {
	header      pkicmp.PKIHeader   // header of the first request of the operation
	resp        *pkicmp.PKIMessage // response that carried the certificate
	creds       pkicmp.Credentials
	trustPool   *x509.CertPool
	knownSigner *x509.Certificate
	implicit    bool // the response granted implicit confirmation
}

// sendCertConf sends a certConf carrying status and checks that the CA answers with pkiConf.
func (c *Client) sendCertConf(ctx context.Context, conf *certConfirmation, status pkicmp.CertStatus) error {
	confMsg := pkicmp.NewPKIMessage(
		pkicmp.NewCertConfBody(&pkicmp.CertConfirmContent{status}),
		pkicmp.MessageOptions{
			Sender:     conf.header.Sender,
			Recipient:  conf.header.Recipient,
			RecipNonce: conf.resp.Header.SenderNonce,
		},
	)
	confMsg.Header.TransactionID = conf.header.TransactionID
	// The messages of one transaction keep the version of its first request.
	confMsg.Header.PVNO = conf.header.PVNO
	// Preserve senderKID across all messages in this transaction (RFC 9810 §5.1.1).
	// For signature-based creds, ProtectWithSignature will overwrite this with the
	// cert SubjectKeyId; for MAC-based creds it must be set explicitly.
	confMsg.Header.SenderKID = conf.header.SenderKID

	if err := conf.creds.Protect(confMsg); err != nil {
		return &Error{Op: "protect certConf", Err: err}
	}

	confDER, err := confMsg.MarshalBinary()
	if err != nil {
		return &Error{Op: "marshal certConf", Err: err}
	}

	confHTTPResp, err := c.sendHTTP(ctx, confDER)
	if err != nil {
		return &Error{Op: "certConf exchange", Err: err}
	}

	// RFC 9810 §5.3.18: The server MUST respond with PKIConf.
	confCMPResp, err := confHTTPResp.parse("parse PKIConf")
	if err != nil {
		return err
	}
	confResp := confCMPResp.message

	if _, err := c.verifyResponse(confMsg, confResp, conf.creds, conf.trustPool, conf.knownSigner); err != nil {
		return confCMPResp.wrapError(withUnverifiedStatus(confResp, &Error{Op: "verify PKIConf", Err: err}))
	}

	if confResp.Body.Type == pkicmp.BodyTypeError {
		return confCMPResp.wrapError(parseErrorResponse(confResp))
	}

	if confResp.Body.Type != pkicmp.BodyTypePKIConf {
		return confCMPResp.wrapError(&Error{Op: fmt.Sprintf("expected PKIConf but got body type %d", confResp.Body.Type)})
	}
	return nil
}

// rejectCertificate reports a refused certificate to the CA with a rejecting certConf and returns reason.
func (c *Client) rejectCertificate(ctx context.Context, conf *certConfirmation, cert *x509.Certificate, certReqID int64, text string, reason error) error {
	// RFC 9483 §3.6.1: an end entity that refuses a newly issued certificate
	// MUST say so in certConf and await pkiConf, so the CA can revoke or log it
	// instead of waiting for the confirmation to expire. With implicit
	// confirmation granted the same section ends the operation without a
	// message, because the CA has closed the transaction.
	if conf.implicit {
		return reason
	}
	status, err := pkicmp.NewCertStatus(cert, certReqID)
	if err == nil {
		status.StatusInfo = &pkicmp.PKIStatusInfo{Status: pkicmp.StatusRejection, StatusString: pkicmp.PKIFreeText{text}}
		err = c.sendCertConf(ctx, conf, status)
	}
	if err != nil {
		// A CA treats a missing certConf as a rejection as well (RFC 9483
		// §4.1.1), so the outcome stands. The failure is kept as text only, so
		// that pkicmp.HasFailure reports the reason and not the CA's answer.
		//nolint:errorlint // err must stay out of the chain so errors.As cannot find the CA's PKIStatusError.
		return fmt.Errorf("%w (rejection not confirmed by the CA: %v)", reason, err)
	}
	return reason
}

// certificateSubject returns a certificate's subject as a directoryName with its original encoding.
func certificateSubject(cert *x509.Certificate) pkicmp.GeneralName {
	if len(cert.RawSubject) > 0 {
		return pkicmp.NewDirectoryNameFromRawDER(cert.RawSubject)
	}
	return pkicmp.NewDirectoryName(cert.Subject)
}

// newRequest builds and protects the first message of an operation.
func (c *Client) newRequest(reqBody *pkicmp.PKIBody, creds pkicmp.Credentials, opts *requestOptions) (*pkicmp.PKIMessage, error) {
	if creds == nil {
		return nil, &Error{Op: "protect request", Err: fmt.Errorf("no credentials provided")}
	}
	sender := pkicmp.GeneralName{}
	if opts.sender != nil {
		sender = pkicmp.NewDirectoryName(*opts.sender)
	} else if sc, ok := creds.(*pkicmp.SignatureCredentials); ok && sc.Certificate() != nil {
		// RFC 9810 §C.5/C.6: sender name SHOULD be present for CR/KUR. RFC 9483 §3.1 makes it the
		// protection certificate's subject, sent as encoded so a CA comparing bytes finds it.
		sender = certificateSubject(sc.Certificate())
	}

	recipient := pkicmp.GeneralName{}
	if !isEmptyName(c.recipient) {
		recipient = pkicmp.NewDirectoryName(c.recipient)
	}

	msg := pkicmp.NewPKIMessage(reqBody, pkicmp.MessageOptions{
		Sender:    sender,
		Recipient: recipient,
	})
	if opts.cmp2021 {
		msg.Header.PVNO = pkicmp.PVNO3
	}

	for _, cert := range c.extraCerts {
		msg.ExtraCerts = append(msg.ExtraCerts, pkicmp.CMPCertificate{Raw: cert.Raw})
	}

	// RFC 9810 §5.1.1: senderKID identifies the key used for protection.
	// For MAC-protected requests it carries the reference number of the shared secret.
	msg.Header.SenderKID = opts.senderKID
	if opts.implicitConfirm && isCertificateRequest(reqBody.Type) {
		msg.Header.GeneralInfo = append(msg.Header.GeneralInfo, pkicmp.ImplicitConfirmInfoValue())
	}
	if opts.certProfile != "" {
		msg.Header.GeneralInfo = append(msg.Header.GeneralInfo, pkicmp.NewCertProfileInfo(opts.certProfile))
	}
	msg.Header.GeneralInfo = append(msg.Header.GeneralInfo, opts.generalInfo...)

	if err := creds.Protect(msg); err != nil {
		return nil, &Error{Op: "protect request", Err: err}
	}
	return msg, nil
}

// exchangeFirst sends the first request of an operation and returns its verified response.
func (c *Client) exchangeFirst(ctx context.Context, msg *pkicmp.PKIMessage, creds pkicmp.Credentials) (*cmpHTTPResponse, *pkicmp.VerifyResult, error) {
	reqDER, err := msg.MarshalBinary()
	if err != nil {
		return nil, nil, &Error{Op: "marshal request", Err: err}
	}

	httpResp, err := c.sendHTTP(ctx, reqDER)
	if err != nil {
		return nil, nil, err
	}

	cmpResp, err := httpResp.parse("parse response")
	if err != nil {
		return nil, nil, err
	}
	resp := cmpResp.message

	vr, err := c.verifyResponse(msg, resp, creds, c.trustedCAs, nil)
	if err != nil {
		return nil, nil, cmpResp.wrapError(withUnverifiedStatus(resp, &Error{Op: "verify response", Err: err}))
	}

	if resp.Header.PVNO < pkicmp.PVNO2 || resp.Header.PVNO > pkicmp.PVNO3 {
		return nil, nil, cmpResp.wrapError(&Error{Op: fmt.Sprintf("unsupported protocol version: %d", resp.Header.PVNO)})
	}
	return cmpResp, vr, nil
}

// answeringCertReqIDs returns the certReqId values a CertResponse may carry to answer the request in body.
func answeringCertReqIDs(body *pkicmp.PKIBody) ([]int64, error) {
	if body.Type == pkicmp.BodyTypeP10CR {
		// A p10cr carries no certReqId. RFC 9810 §5.3.4 answers it with -1 and
		// EJBCA answers it with 0. Either can only name the one certificate
		// requested.
		return []int64{-1, 0}, nil
	}
	msgs, err := body.CertReqMessages()
	if err != nil {
		return nil, &Error{Op: "read certReqId from request", Err: err}
	}
	ids := make([]int64, 0, len(*msgs))
	for _, m := range *msgs {
		ids = append(ids, m.CertReq.CertReqID)
	}
	return ids, nil
}

// checkCertReqID verifies that resp carries one of the certReqId values in ids.
func checkCertReqID(resp *pkicmp.CertResponse, ids []int64) error {
	if slices.Contains(ids, resp.CertReqID) {
		return nil
	}
	return &Error{Op: fmt.Sprintf("response certReqId %d does not match the request", resp.CertReqID)}
}

// extractCertRespAndRep returns the single CertResponse of a certificate response together with its message.
func extractCertRespAndRep(resp *pkicmp.PKIMessage, expectedRepType pkicmp.BodyType) (*pkicmp.CertResponse, *pkicmp.CertRepMessage, error) {
	var rep *pkicmp.CertRepMessage
	var err error

	switch expectedRepType {
	case pkicmp.BodyTypeIP:
		rep, err = resp.Body.IP()
	case pkicmp.BodyTypeCP:
		rep, err = resp.Body.CP()
	case pkicmp.BodyTypeKUP:
		rep, err = resp.Body.KUP()
	default:
		return nil, nil, &Error{Op: fmt.Sprintf("unsupported expected response type %d", expectedRepType)}
	}
	if err != nil {
		return nil, nil, err
	}
	if len(rep.Response) == 0 {
		return nil, nil, &Error{Op: "empty response"}
	}
	// The client requests one certificate, so further entries cannot be matched
	// to anything and are refused rather than silently dropped.
	if len(rep.Response) > 1 {
		return nil, nil, &Error{
			Op: fmt.Sprintf("response carries %d CertResponse entries for one request", len(rep.Response)),
		}
	}
	return &rep.Response[0], rep, nil
}

// rawHTTPResponse holds a bounded CMP response body together with its HTTP status.
type rawHTTPResponse struct {
	body       []byte
	statusCode int
}

// cmpHTTPResponse holds a parsed CMP response together with its HTTP status.
type cmpHTTPResponse struct {
	message    *pkicmp.PKIMessage
	statusCode int
}

// parse parses the response body and retains a non-200 status as error context.
func (r *rawHTTPResponse) parse(op string) (*cmpHTTPResponse, error) {
	msg, err := pkicmp.ParsePKIMessage(r.body)
	if err != nil {
		return nil, r.wrapError(&Error{Op: op, Err: err})
	}
	return &cmpHTTPResponse{message: msg, statusCode: r.statusCode}, nil
}

// wrapError adds a non-200 HTTP status without hiding the wrapped CMP error.
func (r *rawHTTPResponse) wrapError(err error) error {
	if r.statusCode == http.StatusOK {
		return err
	}
	return &Error{Op: fmt.Sprintf("HTTP %d: %s", r.statusCode, http.StatusText(r.statusCode)), Err: err}
}

// wrapError adds a non-200 HTTP status without hiding the wrapped CMP error.
func (r *cmpHTTPResponse) wrapError(err error) error {
	if r.statusCode == http.StatusOK {
		return err
	}
	return &Error{Op: fmt.Sprintf("HTTP %d: %s", r.statusCode, http.StatusText(r.statusCode)), Err: err}
}

// supportsCMPResponse reports whether RFC 9811 requires handling CMP content for the HTTP status.
func supportsCMPResponse(statusCode int) bool {
	statusClass := statusCode / 100
	return statusClass == 2 || statusClass == 4 || statusClass == 5
}

// isCMPMediaType reports whether a Content-Type value identifies the CMP media type.
func isCMPMediaType(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && mediaType == "application/pkixcmp"
}

// newHTTPStatusError returns an operational error for an HTTP response without usable CMP content.
func newHTTPStatusError(statusCode int) error {
	return &Error{Op: fmt.Sprintf("HTTP %d: %s", statusCode, http.StatusText(statusCode))}
}

// sendHTTP sends a CMP request and returns bounded response content for supported HTTP status classes.
func (c *Client) sendHTTP(ctx context.Context, reqDER []byte) (*rawHTTPResponse, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(reqDER))
	if err != nil {
		return nil, &Error{Op: "create HTTP request", Err: err}
	}
	httpReq.Header.Set("Content-Type", "application/pkixcmp")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, &Error{Op: "HTTP request", Err: err}
	}
	defer func() { _ = resp.Body.Close() }()

	readBody := io.Reader(resp.Body)
	if c.maxResponseBytes > 0 {
		readBody = io.LimitReader(resp.Body, c.maxResponseBytes+1)
	}

	body, err := io.ReadAll(readBody)
	if err != nil {
		return nil, &Error{Op: "read response", Err: err}
	}
	if c.maxResponseBytes > 0 && int64(len(body)) > c.maxResponseBytes {
		return nil, &Error{Op: fmt.Sprintf("response body too large: limit=%d", c.maxResponseBytes)}
	}

	if !supportsCMPResponse(resp.StatusCode) {
		return nil, newHTTPStatusError(resp.StatusCode)
	}

	// RFC 9811 Section 3.2: Response Content-Type MUST be application/pkixcmp.
	if ct := resp.Header.Get("Content-Type"); !isCMPMediaType(ct) {
		if resp.StatusCode != http.StatusOK {
			return nil, newHTTPStatusError(resp.StatusCode)
		}
		return nil, &Error{Op: fmt.Sprintf("unexpected Content-Type: %s", ct)}
	}

	if len(body) == 0 && resp.StatusCode != http.StatusOK {
		return nil, newHTTPStatusError(resp.StatusCode)
	}

	return &rawHTTPResponse{body: body, statusCode: resp.StatusCode}, nil
}

func parseErrorResponse(msg *pkicmp.PKIMessage) error {
	errContent, err := msg.Body.Error()
	if err != nil {
		return &Error{Op: "error parsing ErrorMsgContent", Err: err}
	}
	return errContent.PKIStatusInfo.AsError()
}

// isEmptyName reports whether a distinguished name carries no attributes at all.
func isEmptyName(name pkix.Name) bool {
	// pkix.Name.Names is populated only when a name is decoded from DER, so a
	// name a caller built in Go has it empty. Testing it to decide whether a
	// name was set silently discards every programmatically built name.
	return len(name.Country) == 0 &&
		len(name.Organization) == 0 &&
		len(name.OrganizationalUnit) == 0 &&
		len(name.Locality) == 0 &&
		len(name.Province) == 0 &&
		len(name.StreetAddress) == 0 &&
		len(name.PostalCode) == 0 &&
		name.SerialNumber == "" &&
		name.CommonName == "" &&
		len(name.Names) == 0 &&
		len(name.ExtraNames) == 0
}

// checkIssuedKey verifies that the issued certificate certifies the public key the client asked for.
func checkIssuedKey(cert *x509.Certificate, requested crypto.PublicKey) error {
	if requested == nil {
		return nil
	}
	// The subject is deliberately not compared: RFC 9810 §5.2.3 lets a CA return
	// grantedWithMods after changing requested fields such as the subject. The
	// public key is different, because a certificate for a key the client does
	// not hold is unusable and the mismatch would only surface later, far from
	// this exchange.
	issuedKey := cert.PublicKey
	if issuedKey == nil {
		// crypto/x509 leaves PublicKey nil for composite ML-DSA, SLH-DSA and ML-KEM keys.
		issuedKey, _ = pkicmp.ParsePublicKey(cert.RawSubjectPublicKeyInfo)
	}
	if issuedKey == nil {
		return &Error{Op: "cannot parse the public key of the issued certificate"}
	}
	if !pkicmp.PublicKeysEqual(issuedKey, requested) {
		return &Error{Op: "issued certificate does not certify the requested public key"}
	}
	return nil
}

// extractCertificate returns the certificate of resp, decrypting an encrypted one with proof.
func extractCertificate(resp *pkicmp.CertResponse, proof *decryptionProof) (*x509.Certificate, error) {
	if resp.CertifiedKeyPair == nil {
		return nil, &Error{Op: "missing certifiedKeyPair in response"}
	}
	certOrEncCert := &resp.CertifiedKeyPair.CertOrEncCert
	if envelope := certOrEncCert.EncryptedCertificate(); envelope != nil {
		return decryptCertificate(envelope, cms.Decrypt, proof)
	}
	// RFC 9810 §5.2.2 keeps EncryptedValue for CMP version 2 CAs, which send it
	// whatever version the request had.
	if value := certOrEncCert.EncryptedValueCertificate(); value != nil {
		return decryptCertificate(value, cms.DecryptEncryptedValue, proof)
	}
	cert := certOrEncCert.Certificate
	if cert == nil {
		return nil, &Error{Op: "unsupported encrypted certificate format"}
	}
	return cert.Parse()
}

// clampCheckAfter converts a server-provided checkAfter, in seconds, into a wait within the configured limits
func (c *Client) clampCheckAfter(seconds int64) time.Duration {
	if seconds <= 0 {
		return c.minCheckAfter
	}
	// The comparison is made in seconds because converting first overflows
	// time.Duration for anything past about 292 years, and a negative duration
	// makes the wait elapse immediately.
	if seconds >= int64(c.maxCheckAfter/time.Second)+1 {
		return c.maxCheckAfter
	}
	wait := time.Duration(seconds) * time.Second
	if wait < c.minCheckAfter {
		return c.minCheckAfter
	}
	if wait > c.maxCheckAfter {
		return c.maxCheckAfter
	}
	return wait
}

// pollState is the state of polling for the final response to a delayed request (RFC 9810 §5.3.22).
type pollState struct {
	// delayed is the header of the delayed request. Every pollReq repeats its
	// names, transaction ID, version and senderKID, and the final response may
	// repeat its senderNonce.
	delayed pkicmp.PKIHeader
	// recipNonce is the senderNonce of the last response, which the next pollReq repeats.
	recipNonce []byte
	certReqID  int64
	// knownSigner is the protection certificate authenticated last in the operation.
	knownSigner *x509.Certificate
	// nextPoll is when the CA asked for the next pollReq. It is zero to poll at once.
	nextPoll time.Time
	// waiting is set when polling stops without a final response while the request still waits.
	waiting bool
}

// poll implements the client-side polling state machine (RFC 9810 §5.3.22).
// It sends pollReq messages and respects the server's checkAfter interval
// until a final response (ip/cp/kup) or error is received, recording each
// pollRep in state. With once set it returns a nil response after the first
// pollRep.
func (c *Client) poll(ctx context.Context, state *pollState, creds pkicmp.Credentials, once bool) (*cmpHTTPResponse, *pkicmp.VerifyResult, error) {
	var waitTime time.Duration

	for i := 0; i < c.maxPolls; i++ {
		wait := waitTime
		if i == 0 {
			wait = c.untilNextPoll(state.nextPoll)
		}
		if wait > 0 {
			select {
			case <-ctx.Done():
				// Naming the wait keeps a deadline that expires between polls
				// distinguishable from one that expires during a request, while
				// the wrapped context error stays available to errors.Is.
				state.waiting = true
				op := fmt.Sprintf("waiting %s before poll %d", wait.Round(time.Millisecond), i+1)
				return nil, nil, &Error{Op: op, Err: ctx.Err()}
			case <-time.After(wait):
			}
		}

		pollReq := pkicmp.PollReqContent{state.certReqID}

		pollMsg := pkicmp.NewPKIMessage(
			pkicmp.NewPollReqBody(&pollReq),
			pkicmp.MessageOptions{
				Sender:     state.delayed.Sender,
				Recipient:  state.delayed.Recipient,
				RecipNonce: state.recipNonce,
			},
		)
		pollMsg.Header.TransactionID = state.delayed.TransactionID
		pollMsg.Header.PVNO = state.delayed.PVNO
		pollMsg.Header.SenderKID = state.delayed.SenderKID

		if err := creds.Protect(pollMsg); err != nil {
			return nil, nil, &Error{Op: "protect poll request", Err: err}
		}

		pollDER, err := pollMsg.MarshalBinary()
		if err != nil {
			return nil, nil, &Error{Op: "marshal poll request", Err: err}
		}

		httpResp, err := c.sendHTTP(ctx, pollDER)
		if err != nil {
			// No response was accepted, so the request is still waiting as far
			// as the client knows.
			state.waiting = true
			return nil, nil, err
		}

		cmpResp, err := httpResp.parse("parse polled response")
		if err != nil {
			return nil, nil, err
		}
		resp := cmpResp.message

		var delayedRequestNonce []byte
		if resp.Body.Type != pkicmp.BodyTypePollRep {
			// RFC 9483 Section 4.4: the final response may refer back to the request
			// whose processing was delayed rather than to the last pollReq.
			delayedRequestNonce = state.delayed.SenderNonce
		}
		vr, err := c.verifyResponse(pollMsg, resp, creds, c.trustedCAs, state.knownSigner, delayedRequestNonce)
		if err != nil {
			return nil, nil, cmpResp.wrapError(withUnverifiedStatus(resp, &Error{Op: "verify polled response", Err: err}))
		}
		if vr != nil && vr.ProtectionCertificate != nil {
			state.knownSigner = vr.ProtectionCertificate
		}

		if resp.Header.PVNO < pkicmp.PVNO2 || resp.Header.PVNO > pkicmp.PVNO3 {
			return nil, nil, cmpResp.wrapError(&Error{Op: fmt.Sprintf("unsupported protocol version: %d", resp.Header.PVNO)})
		}

		if resp.Body.Type == pkicmp.BodyTypeError {
			return nil, nil, cmpResp.wrapError(parseErrorResponse(resp))
		}

		if resp.Body.Type == pkicmp.BodyTypePollRep {
			pollRep, err := resp.Body.PollRep()
			if err != nil {
				return nil, nil, err
			}
			// Clamp unconditionally: an empty pollRep carries no checkAfter, and
			// leaving waitTime at zero would poll as fast as the network allows.
			var checkAfter int64
			if len(*pollRep) > 0 {
				checkAfter = (*pollRep)[0].CheckAfter
			}
			waitTime = c.clampCheckAfter(checkAfter)
			state.recipNonce = resp.Header.SenderNonce
			state.nextPoll = time.Now().Add(waitTime)
			if once {
				state.waiting = true
				return nil, nil, nil
			}
			continue
		}
		return cmpResp, vr, nil
	}

	state.waiting = true
	return nil, nil, &Error{Op: fmt.Sprintf("polling exceeded max retries (%d)", c.maxPolls)}
}

// untilNextPoll returns how long to wait for a pollReq the CA asked for at
// next, at most the maximum of [WithCheckAfterLimits].
func (c *Client) untilNextPoll(next time.Time) time.Duration {
	if next.IsZero() {
		return 0
	}
	return min(max(time.Until(next), 0), c.maxCheckAfter)
}

// verifyResponse checks that a response belongs to the request and that its protection verifies.
//
// knownSigner, when not nil, is a protection certificate already authenticated
// earlier in the same operation. It is offered as an additional candidate
// signer because a server may send extraCerts only on its first message
// (RFC 9810 §5.1), while the candidate still has to satisfy the same chain,
// sender and signature checks as one the server supplied.
func (c *Client) verifyResponse(req *pkicmp.PKIMessage, resp *pkicmp.PKIMessage, creds pkicmp.Credentials, trustedCAs *x509.CertPool, knownSigner *x509.Certificate, alternativeRecipNonce ...[]byte) (*pkicmp.VerifyResult, error) {
	if !bytes.Equal(resp.Header.TransactionID, req.Header.TransactionID) {
		return nil, &Error{Op: "transaction ID mismatch"}
	}

	nonceMatches := bytes.Equal(resp.Header.RecipNonce, req.Header.SenderNonce)
	if !nonceMatches && len(alternativeRecipNonce) > 0 {
		nonceMatches = bytes.Equal(resp.Header.RecipNonce, alternativeRecipNonce[0])
	}
	if !nonceMatches {
		return nil, &Error{Op: "recipient nonce mismatch"}
	}

	// NOTE: Do NOT compare resp.Header.Sender against c.recipient here.
	// RFC 9810 §5.1.1 defines the sender field as a hint to locate the
	// verification key, not as an identity that must match the request's
	// recipient. The response sender is the CA/RA's own name, which may
	// legitimately differ from the recipient the client addressed (e.g.,
	// RA-forwarded requests, or CAs using a separate CMP signing identity).
	// Authenticity is established by verifying the protection: signature
	// chain against trusted CAs (§8.9), or MAC via shared secret.

	if resp.Header.ProtectionAlg == nil {
		return nil, &Error{Op: "missing protection algorithm in response"}
	}

	// The response's own certificates come first, so a configured server
	// certificate is reached only when the response supplies no usable signer.
	candidates := resp.ExtraCerts
	if knownSigner != nil || len(c.serverCerts) > 0 {
		candidates = append([]pkicmp.CMPCertificate(nil), candidates...)
		if knownSigner != nil {
			candidates = append(candidates, pkicmp.CMPCertificate{Raw: knownSigner.Raw})
		}
		for _, cert := range c.serverCerts {
			candidates = append(candidates, pkicmp.CMPCertificate{Raw: cert.Raw})
		}
	}

	vr, err := resp.Verify(pkicmp.VerifyOptions{
		RequiredProtection: c.responseProtection,
		SharedSecret: func() []byte {
			type sharedSecreter interface{ SharedSecret() []byte }
			if ss, ok := creds.(sharedSecreter); ok {
				return ss.SharedSecret()
			}
			return nil
		}(),
		TrustPool:              trustedCAs,
		ExtraCerts:             candidates,
		SenderKID:              resp.Header.SenderKID,
		AllowSenderKIDMismatch: c.allowKIDMismatch,
		AllowSHA1Signatures:    c.allowSHA1Signatures,
		MinMACIterationCount:   c.minMACIterations,
		MaxMACIterationCount:   c.maxMACIterations,
	})
	if err != nil {
		if hint := c.verificationHint(err, trustedCAs); hint != "" {
			err = fmt.Errorf("%w: %s", err, hint)
		}
		return nil, &Error{Op: "verify protection", Err: err}
	}

	return vr, nil
}

// verificationHint names the client configuration that would let a failed response verify, or returns "".
func (c *Client) verificationHint(err error, trustedCAs *x509.CertPool) string {
	var verifyErr *pkicmp.VerificationError
	if !errors.As(err, &verifyErr) {
		return ""
	}
	switch {
	case verifyErr.Reason == pkicmp.ReasonMissingTrustAnchors && trustedCAs == nil:
		// The bare reason reads as an internal detail on a shared-secret client,
		// which is exactly the client that meets a signed error message without a
		// pool to check it against.
		return "the response is signature-protected and no trusted CAs are configured, " +
			"which a shared-secret client also needs because error messages are signed (RFC 9810 §5.3.21)"
	case verifyErr.Reason == pkicmp.ReasonNoCandidateSigner && len(c.serverCerts) == 0:
		return "the response does not carry its protection certificate in extraCerts, " +
			"so configure the certificate the server signs with through WithServerCerts"
	case verifyErr.Reason == pkicmp.ReasonSenderKIDMismatch && len(c.serverCerts) == 0:
		return "configure the certificate the server signs with through WithServerCerts " +
			"or use WithSenderKIDMismatch if the server puts another value in senderKID"
	case verifyErr.Reason == pkicmp.ReasonSenderKIDMismatch:
		return "use WithSenderKIDMismatch if the server puts another value in senderKID"
	default:
		return ""
	}
}
