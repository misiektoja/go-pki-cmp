package pkicmp

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// RFC 9810 §5.1.1 (PKIHeader ASN.1 tests)
func TestPKIHeaderASN1(t *testing.T) {
	t.Run("MarshalAndUnmarshalFull", func(t *testing.T) {
		now := time.Now().Truncate(time.Second).UTC()
		h := &PKIHeader{
			PVNO: PVNO2,
			Sender: GeneralName{DirectoryName: pkix.RDNSequence{{{
				Type:  asn1.ObjectIdentifier{2, 5, 4, 3},
				Value: "Sender",
			}}}},
			Recipient: GeneralName{DirectoryName: pkix.RDNSequence{{{
				Type:  asn1.ObjectIdentifier{2, 5, 4, 3},
				Value: "Recipient",
			}}}},
			MessageTime:   now,
			ProtectionAlg: &AlgorithmIdentifier{Algorithm: oidSHA256},
			SenderKID:     []byte{0x01},
			RecipKID:      []byte{0x02},
			TransactionID: []byte{0x03},
			SenderNonce:   []byte{0x04},
			RecipNonce:    []byte{0x05},
			FreeText:      PKIFreeText{"text"},
			GeneralInfo:   []InfoTypeAndValue{{InfoType: oidSHA256}},
		}

		var b cryptobyte.Builder
		h.marshal(&marshalContext{MinRequiredPVNO: PVNO2}, &b)
		marshaled, err := b.Bytes()
		require.NoError(t, err)

		var unmarshaled PKIHeader
		s := cryptobyte.String(marshaled)
		err = unmarshaled.unmarshal(&s)
		require.NoError(t, err)

		assert.Equal(t, h.PVNO, unmarshaled.PVNO)
		assert.Equal(t, h.MessageTime.Unix(), unmarshaled.MessageTime.Unix())
		assert.Equal(t, h.SenderKID, unmarshaled.SenderKID)
		assert.Equal(t, h.RecipKID, unmarshaled.RecipKID)
		assert.Equal(t, h.TransactionID, unmarshaled.TransactionID)
		assert.Equal(t, h.SenderNonce, unmarshaled.SenderNonce)
		assert.Equal(t, h.RecipNonce, unmarshaled.RecipNonce)
		assert.Equal(t, h.FreeText, unmarshaled.FreeText)
		assert.Equal(t, h.GeneralInfo[0].InfoType, unmarshaled.GeneralInfo[0].InfoType)
	})

	t.Run("UnmarshalCMPv1", func(t *testing.T) {
		var b cryptobyte.Builder
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1Int64(1) // PVNO1
			gn := GeneralName{}
			gn.marshal(&marshalContext{MinRequiredPVNO: PVNO2}, b)
			gn.marshal(&marshalContext{MinRequiredPVNO: PVNO2}, b)
		})
		marshaled, _ := b.Bytes()
		var unmarshaled PKIHeader
		s := cryptobyte.String(marshaled)
		err := unmarshaled.unmarshal(&s)
		assert.NoError(t, err)
		assert.Equal(t, PVNO1, unmarshaled.PVNO)
	})

	t.Run("UnmarshalErrors", func(t *testing.T) {
		t.Run("InvalidSequence", func(t *testing.T) {
			var unmarshaled PKIHeader
			s := cryptobyte.String([]byte{0x00})
			err := unmarshaled.unmarshal(&s)
			assert.Error(t, err)
		})
		t.Run("InvalidPVNO", func(t *testing.T) {
			var b cryptobyte.Builder
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1Int64(2)
				// Missing sender and recipient
			})
			marshaled, _ := b.Bytes()
			var unmarshaled PKIHeader
			s := cryptobyte.String(marshaled)
			err := unmarshaled.unmarshal(&s)

			assert.Error(t, err)
		})
		t.Run("InvalidOptionalFields", func(t *testing.T) {
			marshalBase := func(b *cryptobyte.Builder) {
				b.AddASN1Int64(2)
				gn := GeneralName{}
				gn.marshal(&marshalContext{MinRequiredPVNO: PVNO2}, b)
				gn.marshal(&marshalContext{MinRequiredPVNO: PVNO2}, b)
			}

			t.Run("InvalidMessageTime", func(t *testing.T) {
				var b cryptobyte.Builder
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					marshalBase(b)
					b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
						b.AddUint8(0x01)
					})
				})
				marshaled, _ := b.Bytes()
				var unmarshaled PKIHeader
				s := cryptobyte.String(marshaled)
				err := unmarshaled.unmarshal(&s)
				assert.Error(t, err)
			})

			t.Run("InvalidProtectionAlg", func(t *testing.T) {
				var b cryptobyte.Builder
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					marshalBase(b)
					b.AddASN1(cbasn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
						b.AddUint8(0x01)
					})
				})
				marshaled, _ := b.Bytes()
				var unmarshaled PKIHeader
				s := cryptobyte.String(marshaled)
				err := unmarshaled.unmarshal(&s)
				assert.Error(t, err)
			})

			t.Run("InvalidFreeText", func(t *testing.T) {
				var b cryptobyte.Builder
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					marshalBase(b)
					b.AddASN1(cbasn1.Tag(7).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
						b.AddUint8(0x01)
					})
				})
				marshaled, _ := b.Bytes()
				var unmarshaled PKIHeader
				s := cryptobyte.String(marshaled)
				err := unmarshaled.unmarshal(&s)
				assert.Error(t, err)
			})

			t.Run("InvalidGeneralInfo", func(t *testing.T) {
				var b cryptobyte.Builder
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					marshalBase(b)
					b.AddASN1(cbasn1.Tag(8).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
						b.AddUint8(0x01)
					})
				})
				marshaled, _ := b.Bytes()
				var unmarshaled PKIHeader
				s := cryptobyte.String(marshaled)
				err := unmarshaled.unmarshal(&s)
				assert.Error(t, err)
			})

			t.Run("InvalidRecipNonce", func(t *testing.T) {
				var b cryptobyte.Builder
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					marshalBase(b)
					b.AddASN1(cbasn1.Tag(6).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
						b.AddBytes([]byte{0x04, 0xff})
					})
				})
				marshaled, _ := b.Bytes()
				var unmarshaled PKIHeader
				s := cryptobyte.String(marshaled)
				err := unmarshaled.unmarshal(&s)
				assert.Error(t, err)
			})

			t.Run("InvalidGeneralInfoSequence", func(t *testing.T) {
				var b cryptobyte.Builder
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					marshalBase(b)
					b.AddASN1(cbasn1.Tag(8).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
						b.AddUint8(0x02)
						b.AddUint8(0x00)
					})
				})
				marshaled, _ := b.Bytes()
				var unmarshaled PKIHeader
				s := cryptobyte.String(marshaled)
				err := unmarshaled.unmarshal(&s)
				assert.Error(t, err)
			})

			t.Run("InvalidSenderNonce", func(t *testing.T) {
				var b cryptobyte.Builder
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					marshalBase(b)
					b.AddASN1(cbasn1.Tag(5).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
						b.AddBytes([]byte{0x04, 0xff})
					})
				})
				marshaled, _ := b.Bytes()
				var unmarshaled PKIHeader
				s := cryptobyte.String(marshaled)
				err := unmarshaled.unmarshal(&s)
				assert.Error(t, err)
			})

			t.Run("InvalidFreeTextTag", func(t *testing.T) {
				var b cryptobyte.Builder
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					marshalBase(b)
					b.AddASN1(cbasn1.Tag(7).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
						b.AddUint8(0x02)
						b.AddUint8(0x00)
					})
				})
				marshaled, _ := b.Bytes()
				var unmarshaled PKIHeader
				s := cryptobyte.String(marshaled)
				err := unmarshaled.unmarshal(&s)
				assert.Error(t, err)
			})

			t.Run("InvalidRecipKID", func(t *testing.T) {
				var b cryptobyte.Builder
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					marshalBase(b)
					b.AddASN1(cbasn1.Tag(3).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
						b.AddBytes([]byte{0x04, 0xff})
					})
				})
				marshaled, _ := b.Bytes()
				var unmarshaled PKIHeader
				s := cryptobyte.String(marshaled)
				err := unmarshaled.unmarshal(&s)
				assert.Error(t, err)
			})

			t.Run("InvalidTransactionID", func(t *testing.T) {
				var b cryptobyte.Builder
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					marshalBase(b)
					b.AddASN1(cbasn1.Tag(4).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
						b.AddBytes([]byte{0x04, 0xff})
					})
				})
				marshaled, _ := b.Bytes()
				var unmarshaled PKIHeader
				s := cryptobyte.String(marshaled)
				err := unmarshaled.unmarshal(&s)
				assert.Error(t, err)
			})

			t.Run("InvalidSenderKID", func(t *testing.T) {
				var b cryptobyte.Builder
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					marshalBase(b)
					b.AddASN1(cbasn1.Tag(2).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
						b.AddBytes([]byte{0x04, 0xff})
					})
				})
				marshaled, _ := b.Bytes()
				var unmarshaled PKIHeader
				s := cryptobyte.String(marshaled)
				err := unmarshaled.unmarshal(&s)
				assert.Error(t, err)
			})

			t.Run("InvalidInfoTypeAndValueOID", func(t *testing.T) {
				var b cryptobyte.Builder
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					marshalBase(b)
					b.AddASN1(cbasn1.Tag(8).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
						b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
							b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
								b.AddUint8(0x01)
							})
						})
					})
				})
				marshaled, _ := b.Bytes()
				var unmarshaled PKIHeader
				s := cryptobyte.String(marshaled)
				err := unmarshaled.unmarshal(&s)
				assert.Error(t, err)
			})
		})
	})
}

func TestParsePKIMessage(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		body := NewPKIConfBody()
		msg := &PKIMessage{
			Header: PKIHeader{PVNO: PVNO2},
			Body:   body,
		}
		der, _ := msg.MarshalBinary()
		parsed, err := ParsePKIMessage(der)
		assert.NoError(t, err)
		assert.NotNil(t, parsed)
	})
	t.Run("Invalid", func(t *testing.T) {
		_, err := ParsePKIMessage([]byte{0x00})
		assert.Error(t, err)
	})

	t.Run("RejectsTrailingData", func(t *testing.T) {
		body := NewPKIConfBody()
		msg := &PKIMessage{
			Header: PKIHeader{PVNO: PVNO2},
			Body:   body,
		}
		der, _ := msg.MarshalBinary()
		der = append(der, 0x00)
		_, err := ParsePKIMessage(der)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "trailing data")
	})

	// extraCerts is EXPLICIT, so its [1] wrapper must hold the certificate SEQUENCE and nothing else.
	t.Run("RejectsTrailingDataInExtraCerts", func(t *testing.T) {
		msg := &PKIMessage{
			Header: PKIHeader{PVNO: PVNO2},
			Body:   NewPKIConfBody(),
		}
		der, err := msg.MarshalBinary()
		require.NoError(t, err)
		var content cryptobyte.String
		s := cryptobyte.String(der)
		require.True(t, s.ReadASN1(&content, cbasn1.SEQUENCE))
		// Parsing keeps a CMPCertificate as a raw element, so a short SEQUENCE stands in for one.
		cert := []byte{0x30, 0x03, 0x02, 0x01, 0x01}
		for name, trailing := range map[string][]byte{"Byte": {0x00}, "Element": cert} {
			t.Run(name, func(t *testing.T) {
				b := cryptobyte.NewBuilder(nil)
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddBytes(content)
					b.AddASN1(cbasn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
						b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { b.AddBytes(cert) })
						b.AddBytes(trailing)
					})
				})
				wrapped, err := b.Bytes()
				require.NoError(t, err)
				_, err = ParsePKIMessage(wrapped)
				require.Error(t, err)
				assert.Contains(t, err.Error(), "trailing data inside extraCerts")
			})
		}
	})
}

func TestPKIMessagePVNOTigger(t *testing.T) {
	t.Run("PVNO2", func(t *testing.T) {
		body := NewPKIConfBody()
		msg := &PKIMessage{
			Header: PKIHeader{
				Sender:    GeneralName{},
				Recipient: GeneralName{},
			},
			Body: body,
		}
		der, err := msg.MarshalBinary()
		require.NoError(t, err)
		parsed, err := ParsePKIMessage(der)
		require.NoError(t, err)
		assert.Equal(t, PVNO2, parsed.Header.PVNO)
	})
	t.Run("PVNO3_EnvelopedData", func(t *testing.T) {
		resp := &CertResponse{
			CertReqID: 1,
			Status:    PKIStatusInfo{Status: StatusAccepted},
			CertifiedKeyPair: &CertifiedKeyPair{
				CertOrEncCert: CertOrEncCert{
					EncryptedCert: &encryptedKey{
						envelopedData: &envelopedData{Raw: []byte{0x30, 0x03, 0x02, 0x01, 0x01}},
					},
				},
			},
		}
		body := NewCPBody(&CertRepMessage{
			Response: []CertResponse{*resp},
		})
		msg := &PKIMessage{
			Header: PKIHeader{
				Sender:    GeneralName{},
				Recipient: GeneralName{},
			},
			Body: body,
		}
		der, err := msg.MarshalBinary()
		require.NoError(t, err)
		parsed, err := ParsePKIMessage(der)
		require.NoError(t, err)
		assert.Equal(t, PVNO3, parsed.Header.PVNO)
	})
}

// RFC 9810 §5.1 (PKIMessage ASN.1 tests)
func TestPKIMessageASN1(t *testing.T) {
	t.Run("MarshalAndUnmarshalOptional", func(t *testing.T) {
		body := NewPKIConfBody()
		msg := &PKIMessage{
			Header: PKIHeader{
				Sender:    GeneralName{},
				Recipient: GeneralName{},
			},
			Body:       body,
			Protection: []byte{0xDE, 0xAD},
			ExtraCerts: []CMPCertificate{{Raw: []byte{0x30, 0x03, 0x02, 0x01, 0x01}}},
		}

		marshaled, err := msg.MarshalBinary()
		require.NoError(t, err)

		var unmarshaled PKIMessage
		err = unmarshaled.UnmarshalBinary(marshaled)
		require.NoError(t, err)

		assert.Equal(t, msg.Protection, unmarshaled.Protection)
		assert.Len(t, unmarshaled.ExtraCerts, 1)
	})

	t.Run("UnmarshalErrors", func(t *testing.T) {
		t.Run("NotASequence", func(t *testing.T) {
			var unmarshaled PKIMessage
			err := unmarshaled.UnmarshalBinary([]byte{0x00})
			assert.Error(t, err)
		})
		t.Run("MissingBody", func(t *testing.T) {
			var b cryptobyte.Builder
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				h := &PKIHeader{PVNO: PVNO2}
				h.marshal(&marshalContext{MinRequiredPVNO: PVNO2}, b)
			})
			marshaled, _ := b.Bytes()
			var unmarshaled PKIMessage
			err := unmarshaled.UnmarshalBinary(marshaled)
			assert.Error(t, err)
		})
		t.Run("InvalidProtectionBitString", func(t *testing.T) {
			var b cryptobyte.Builder
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				h := &PKIHeader{PVNO: PVNO2}
				h.marshal(&marshalContext{MinRequiredPVNO: PVNO2}, b)
				body := NewPKIConfBody()
				body.marshal(&marshalContext{MinRequiredPVNO: PVNO2}, b)
				b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
					b.AddUint8(0x02)
					b.AddUint8(0x00)
				})
			})
			marshaled, _ := b.Bytes()
			var unmarshaled PKIMessage
			err := unmarshaled.UnmarshalBinary(marshaled)
			assert.Error(t, err)
		})

		t.Run("InvalidProtectionUnusedBits", func(t *testing.T) {
			var b cryptobyte.Builder
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				h := &PKIHeader{PVNO: PVNO2}
				h.marshal(&marshalContext{MinRequiredPVNO: PVNO2}, b)
				body := NewPKIConfBody()
				body.marshal(&marshalContext{MinRequiredPVNO: PVNO2}, b)
				b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
					b.AddASN1(cbasn1.BIT_STRING, func(b *cryptobyte.Builder) {
					})
				})
			})
			marshaled, _ := b.Bytes()
			var unmarshaled PKIMessage
			err := unmarshaled.UnmarshalBinary(marshaled)
			assert.Error(t, err)
		})
		t.Run("InvalidExtraCertsTag", func(t *testing.T) {
			var b cryptobyte.Builder
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				h := &PKIHeader{PVNO: PVNO2}
				h.marshal(&marshalContext{MinRequiredPVNO: PVNO2}, b)
				body := NewPKIConfBody()
				body.marshal(&marshalContext{MinRequiredPVNO: PVNO2}, b)
				b.AddASN1(cbasn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
					b.AddUint8(0x02)
				})
			})
			marshaled, _ := b.Bytes()
			var unmarshaled PKIMessage
			err := unmarshaled.UnmarshalBinary(marshaled)
			assert.Error(t, err)
		})

		t.Run("InvalidExtraCertsSequence", func(t *testing.T) {
			var b cryptobyte.Builder
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				h := &PKIHeader{PVNO: PVNO2}
				h.marshal(&marshalContext{MinRequiredPVNO: PVNO2}, b)
				body := NewPKIConfBody()
				body.marshal(&marshalContext{MinRequiredPVNO: PVNO2}, b)
				b.AddASN1(cbasn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
					b.AddUint8(0x02)
					b.AddUint8(0x00)
				})
			})
			marshaled, _ := b.Bytes()
			var unmarshaled PKIMessage
			err := unmarshaled.UnmarshalBinary(marshaled)
			assert.Error(t, err)
		})

		t.Run("InvalidExtraCertsElement", func(t *testing.T) {
			var b cryptobyte.Builder
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				h := &PKIHeader{PVNO: PVNO2}
				h.marshal(&marshalContext{MinRequiredPVNO: PVNO2}, b)
				body := NewPKIConfBody()
				body.marshal(&marshalContext{MinRequiredPVNO: PVNO2}, b)
				b.AddASN1(cbasn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
					b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
						b.AddUint8(0x01)
					})
				})
			})
			marshaled, _ := b.Bytes()
			var unmarshaled PKIMessage
			err := unmarshaled.UnmarshalBinary(marshaled)
			assert.Error(t, err)
		})

		t.Run("MissingPKIMessageSequence", func(t *testing.T) {
			var unmarshaled PKIMessage
			err := unmarshaled.UnmarshalBinary([]byte{0x02, 0x01, 0x01})
			assert.Error(t, err)
		})
	})
}
