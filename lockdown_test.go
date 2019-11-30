package main

import (
	"testing"
)

type tPM struct {
	in       string
	extra    []interface{}
	expected string
}

func TestPaddedMsgs(t *testing.T) {
	pms := NewPaddedMsgs()

	pmList := []tPM{
		{
			"test1:",
			[]interface{}{"some extra", "data", 3},
			"test1: some extra data 3",
		},
		{
			"t1:",
			[]interface{}{"some other", "extra data", 2},
			"   t1: some other extra data 2",
		},
		{
			"test2:",
			[]interface{}{"moar extra data"},
			"test2: moar extra data",
		},
		{
			"this is test 3:",
			[]interface{}{},
			"this is test 3:",
		},
		{
			"test1:",
			[]interface{}{"extra", "data"},
			"         test1: extra data",
		},
		{
			"this is another test 4:",
			[]interface{}{4},
			"this is another test 4: 4",
		},
		{
			"this is another test 5:",
			[]interface{}{"five", 6, []byte{7}},
			"this is another test 5: five 6 [7]",
		},
		{
			"t1:",
			[]interface{}{""},
			"                    t1:",
		},
	}

	for _, pm := range pmList {
		msg := pms.Msg(pm.in, pm.extra...)
		if msg != pm.expected {
			t.Errorf("invalid padded message: expected (%s), got (%s)\n", pm.expected, msg)
		}
	}
}
