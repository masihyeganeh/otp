package sekeh

import (
	"otp/internal/sekeh"
	"testing"
)

func TestSekeh(t *testing.T) {
	r, err := sekeh.New("09126175024")
	if err != nil {
		t.Fatal(err)
	}

	err = r.VerifyDevice("123456")
	if err != nil {
		t.Fatal(err)
	}
}
