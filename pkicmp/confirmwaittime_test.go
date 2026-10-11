package pkicmp_test

import (
	"encoding/asn1"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// RFC 9810 §5.1.1.2 defines ConfirmWaitTimeValue as a GeneralizedTime. Encoding
// it as an INTEGER makes the whole header unparsable for a conforming peer.
func TestConfirmWaitTimeIsGeneralizedTime(t *testing.T) {
	itav := pkicmp.ConfirmWaitTimeInfoValue(90 * time.Second)

	var raw asn1.RawValue
	_, err := asn1.Unmarshal(itav.InfoValue, &raw)
	require.NoError(t, err)
	assert.Equal(t, asn1.TagGeneralizedTime, raw.Tag, "confirmWaitTime must be a GeneralizedTime")
	assert.Equal(t, asn1.ClassUniversal, raw.Class)

	deadline, err := pkicmp.ParseConfirmWaitTime(itav)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().Add(90*time.Second), deadline, 5*time.Second)
	assert.Equal(t, time.UTC, deadline.Location(), "DER requires GeneralizedTime in UTC")
}

func TestConfirmWaitTimeRejectsNonGeneralizedTime(t *testing.T) {
	encoded, err := asn1.Marshal(30)
	require.NoError(t, err)
	itav := pkicmp.InfoTypeAndValue{
		InfoType:  asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 4, 14},
		InfoValue: encoded,
	}

	_, err = pkicmp.ParseConfirmWaitTime(itav)
	require.Error(t, err)
}

func TestConfirmWaitTimeRejectsWrongInfoType(t *testing.T) {
	itav := pkicmp.ImplicitConfirmInfoValue()
	_, err := pkicmp.ParseConfirmWaitTime(itav)
	require.Error(t, err)
}
