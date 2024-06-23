package aes

import (
	"bytes"
	"github.com/twinj/uuid"
	"testing"
)

func TestMarshalAndUnmarshal(t *testing.T) {
	secretKey := uuid.NewV4().Bytes()
	dataset := uuid.NewV4().Bytes()

	res, err := Marshal(dataset, secretKey)
	if err != nil {
		t.Fatal(err)
	}

	if len(res) == 0 || bytes.Compare(dataset, res) == 0 {
		t.Errorf("returned incorrect result")
	}

	tmp, err := Unmarshal(res, secretKey)
	if err != nil {
		t.Fatal(err)
	}

	if len(tmp) == 0 || bytes.Compare(dataset, tmp) != 0 {
		t.Errorf("returned incorrect result")
	}
}

func TestMarshalAndUnmarshalString(t *testing.T) {
	secretKey := uuid.NewV4().Bytes()
	dataset := uuid.NewV4().String()

	res, err := MarshalString(dataset, secretKey)
	if err != nil {
		t.Fatal(err)
	}

	if len(res) == 0 || dataset == res {
		t.Errorf("returned incorrect result")
	}

	tmp, err := UnmarshalString(res, secretKey)
	if err != nil {
		t.Fatal(err)
	}

	if len(tmp) == 0 || dataset != tmp {
		t.Errorf("returned incorrect result")
	}
}
