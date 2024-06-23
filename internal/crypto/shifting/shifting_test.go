package shifting

import (
	"github.com/twinj/uuid"
	"testing"
)

func TestShiftingToLeft(t *testing.T) {
	data := []byte{153} // 10011001

	d := shiftingToLeft(data, 1) // 00110011
	if len(d) != len(data) {
		t.Fatalf("expected %d, got %d", len(data), len(d))
	}
	if d[0] != 51 {
		t.Fatalf("expected %08b, got %08b", 51, d[0])
	}

	d = shiftingToLeft(data, 16) // 00110011
	if len(d) != len(data) {
		t.Fatalf("expected %d, got %d", len(data), len(d))
	}
	if d[0] != 51 {
		t.Errorf("expected %08b, got %08b", 51, d[0])
	}
}

func TestShiftingToRight(t *testing.T) {
	data := []byte{153} // 10011001

	d := shiftingToRight(data, 1) // 11001100
	if len(d) != len(data) {
		t.Fatalf("expected %d, got %d", len(data), len(d))
	}
	if d[0] != 204 {
		t.Fatalf("expected %08b, got %08b", 51, d[0])
	}

	d = shiftingToRight(data, 16) // 00000100
	if len(d) != len(data) {
		t.Fatalf("expected %d, got %d", len(data), len(d))
	}
	if d[0] != 204 {
		t.Errorf("expected %08b, got %08b", 51, d[0])
	}
}

func TestMarshalTo1(t *testing.T) {
	data := []byte{85} // 01010101

	d, err := Marshal(data, 1) // 10101010
	if err != nil {
		t.Fatal(err)
	}

	if len(d) != len(data) {
		t.Fatalf("expected %d, got %d", len(data), len(d))
	}

	if d[0] != 170 {
		t.Fatalf("expected %08b, got %08b", 170, d[0])
	}
}

func TestMarshalTo16(t *testing.T) {
	data := []byte{55, 56, 57} // 00110111,00111000,00111001

	d, err := Marshal(data, 16) // 00111001,00110111,00111000
	if err != nil {
		t.Fatal(err)
	}

	if len(d) != len(data) {
		t.Fatalf("expected %d, got %d", len(data), len(d))
	}

	if d[0] != 57 {
		t.Errorf("expected %08b, got %08b", 57, d[0])
	}
	if d[1] != 55 {
		t.Errorf("expected %08b, got %08b", 55, d[1])
	}
	if d[2] != 56 {
		t.Errorf("expected %08b, got %08b", 56, d[2])
	}
}

func TestMarshalTo20(t *testing.T) {
	data := []byte{60, 61, 62} // 00111100,00111101,00111110

	d, err := Marshal(data, 20) // 11100011,11000011,11010011
	if err != nil {
		t.Fatal(err)
	}

	if len(d) != len(data) {
		t.Fatalf("expected %d, got %d", len(data), len(d))
	}

	if d[0] != 227 { // 11100011
		t.Errorf("expected %08b, got %08b", 227, d[0])
	}
	if d[1] != 195 { // 11000011
		t.Errorf("expected %08b, got %08b", 195, d[1])
	}
	if d[2] != 211 { // 11010011
		t.Errorf("expected %08b, got %08b", 211, d[2])
	}
}

func TestMarshalTo11(t *testing.T) {
	data := []byte{200, 123, 43} // 11001000,01111011,00101011

	d, err := Marshal(data, 11) // 11011001,01011110,01000011
	if err != nil {
		t.Fatal(err)
	}

	if len(d) != len(data) {
		t.Fatalf("expected %d, got %d", len(data), len(d))
	}

	if d[0] != 217 {
		t.Errorf("expected %08b, got %08b", 217, d[0])
	}
	if d[1] != 94 {
		t.Errorf("expected %08b, got %08b", 94, d[1])
	}
	if d[2] != 67 {
		t.Errorf("expected %08b, got %08b", 67, d[2])
	}
}

func TestUnmarshalTo1(t *testing.T) {
	data := []byte{85} // 01010101

	d, err := Unmarshal(data, 1) // 10101010
	if err != nil {
		t.Fatal(err)
	}

	if len(d) != len(data) {
		t.Fatalf("expected %d, got %d", len(data), len(d))
	}

	if d[0] != 170 {
		t.Fatalf("expected %08b, got %08b", 170, d[0])
	}
}

func TestUnmarshalTo16(t *testing.T) {
	data := []byte{55, 56, 57} // 00110111,00111000,00111001

	d, err := Unmarshal(data, 16) // 00111000,00111001,00110111,
	if err != nil {
		t.Fatal(err)
	}

	if len(d) != len(data) {
		t.Fatalf("expected %d, got %d", len(data), len(d))
	}

	if d[0] != 56 {
		t.Errorf("expected %08b, got %08b", 56, d[0])
	}
	if d[1] != 57 {
		t.Errorf("expected %08b, got %08b", 57, d[1])
	}
	if d[2] != 55 {
		t.Errorf("expected %08b, got %08b", 55, d[2])
	}
}

func TestUnmarshalTo20(t *testing.T) {
	data := []byte{60, 61, 62} // 00111100,00111101,00111110

	d, err := Unmarshal(data, 20) // 11000011,11010011,11100011
	if err != nil {
		t.Fatal(err)
	}

	if len(d) != len(data) {
		t.Fatalf("expected %d, got %d", len(data), len(d))
	}

	if d[0] != 195 {
		t.Errorf("expected %08b, got %08b", 195, d[0])
	}
	if d[1] != 211 {
		t.Errorf("expected %08b, got %08b", 211, d[1])
	}
	if d[2] != 227 {
		t.Errorf("expected %08b, got %08b", 227, d[2])
	}
}

func TestUnmarshalTo11(t *testing.T) {
	data := []byte{200, 123, 43} // 11001000,01111011,00101011

	d, err := Unmarshal(data, 11) // 01100101,01111001,00001111
	if err != nil {
		t.Fatal(err)
	}

	if len(d) != len(data) {
		t.Fatalf("expected %d, got %d", len(data), len(d))
	}

	if d[0] != 101 {
		t.Errorf("expected %08b, got %08b", 101, d[0])
	}
	if d[1] != 121 {
		t.Errorf("expected %08b, got %08b", 121, d[1])
	}
	if d[2] != 15 {
		t.Errorf("expected %08b, got %08b", 15, d[2])
	}
}

func TestShifting(t *testing.T) {
	s1 := uuid.NewV4().String()

	b1, err := Marshal([]byte(s1), 11)
	if err != nil {
		t.Fatal(err)
	}

	b2, err := Unmarshal(b1, 11)
	if err != nil {
		t.Fatal(err)
	}

	if s2 := string(b2); s1 != s2 {
		t.Fatalf("expected %s, got %s", s1, s2)
	}
}
