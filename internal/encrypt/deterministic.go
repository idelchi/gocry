package encrypt

import (
	"bytes"
	"fmt"

	"github.com/tink-crypto/tink-go/v2/daead"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	aes_sivpb "github.com/tink-crypto/tink-go/v2/proto/aes_siv_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"github.com/tink-crypto/tink-go/v2/tink"

	"google.golang.org/protobuf/proto"
)

// newDAEAD creates a deterministic AEAD primitive from a 64-byte key.
//
//nolint:ireturn 		// method must return an interface
func newDAEAD(key []byte) (tink.DeterministicAEAD, error) {
	aesSivKey := &aes_sivpb.AesSivKey{Version: 0, KeyValue: key}

	serializedKey, err := proto.Marshal(aesSivKey)
	if err != nil {
		return nil, fmt.Errorf("marshal aes-siv key: %w", err)
	}

	keyData := &tinkpb.KeyData{
		TypeUrl:         "type.googleapis.com/google.crypto.tink.AesSivKey",
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}

	keySet := &tinkpb.Keyset{
		PrimaryKeyId: 1,
		Key: []*tinkpb.Keyset_Key{{
			KeyData:          keyData,
			Status:           tinkpb.KeyStatusType_ENABLED,
			KeyId:            1,
			OutputPrefixType: tinkpb.OutputPrefixType_RAW,
		}},
	}

	serializedKeyset, err := proto.Marshal(keySet)
	if err != nil {
		return nil, fmt.Errorf("marshal keyset: %w", err)
	}

	handle, err := insecurecleartextkeyset.Read(
		keyset.NewBinaryReader(bytes.NewReader(serializedKeyset)),
	)
	if err != nil {
		return nil, fmt.Errorf("read keyset: %w", err)
	}

	return daead.New(handle) //nolint:wrapcheck	// error does not need wrapping
}
