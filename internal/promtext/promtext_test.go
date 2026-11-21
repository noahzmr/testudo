package promtext

import (
	"math"
	"strings"
	"testing"
)

func TestWrite(t *testing.T) {
	var b strings.Builder
	err := Write(&b, []Sample{
		Gauge("b_up", "Whether b is up.", 1, "name", `we"ird\name`),
		Counter("a_total", "Packets\nseen.", 42),
		Gauge("b_up", "Whether b is up.", 0, "name", "x", "site", "hq"),
		Gauge("c", "Not a number.", math.NaN()),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `# HELP a_total Packets\nseen.
# TYPE a_total counter
a_total 42
# HELP b_up Whether b is up.
# TYPE b_up gauge
b_up{name="we\"ird\\name"} 1
b_up{name="x",site="hq"} 0
# HELP c Not a number.
# TYPE c gauge
c NaN
`
	if b.String() != want {
		t.Errorf("got\n%s\nwant\n%s", b.String(), want)
	}
}
