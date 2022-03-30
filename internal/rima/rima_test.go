package rima

import (
	"testing"
)

func TestRima_GenerateSeed(t *testing.T) {
	r := New("09126175024", "imeiimeiimeiimei")
	uri, err := r.GenerateSeed("OHZmxI8tRlirC4cyujwxhA==", "ZT4QBOXA", "636214-3333-1CSJVSHVLK4FWFCMYFHC2LTT53JPF46FCXN5C3Y3J37RFQ46722R7FPNCYGVRSKG7G2EHWH4V3CR4LC42YM6IHDOAEKJALLY")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf(uri)
}
