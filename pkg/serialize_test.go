package tokeninjector

import (
	"bytes"
	"github.com/twinj/uuid"
	"math/rand"
	"testing"
	"time"
)

func TestMarshal(t *testing.T) {
	expectedUserID := uuid.NewV4().String()
	expectedUserName := uuid.NewV4().String()
	expectedRoleID := rand.Uint64()
	expectedExpiredAt := time.Unix(time.Now().Unix(), 0).UTC()
	secretKey := uuid.NewV4().Bytes()

	dataset, err := Marshal(expectedUserID, expectedUserName, expectedRoleID, expectedExpiredAt, secretKey)
	if err != nil {
		t.Fatal(err)
	}

	actualUserID, actualUserName, actualRoleID, actualExpiredAt, err := Unmarshal(dataset, secretKey)
	if err != nil {
		t.Fatal(err)
	}

	if expectedUserID != actualUserID {
		t.Errorf("incoorect token userId, got %s, expected %s", actualUserID, expectedUserID)
	}
	if expectedUserName != actualUserName {
		t.Errorf("incoorect token userName, got %s, expected %s", actualUserName, expectedUserName)
	}
	if expectedRoleID != actualRoleID {
		t.Errorf("incoorect token userName, got %d, expected %d", actualRoleID, expectedRoleID)
	}
	if expectedExpiredAt != actualExpiredAt {
		t.Errorf("incoorect token userName, got %s, expected %s", actualExpiredAt.String(), expectedExpiredAt.String())
	}
}

func TestConvert(t *testing.T) {
	expectedUserId := bytes.Repeat([]byte{'I'}, 100)
	expectedUserName := bytes.Repeat([]byte{'N'}, 254)
	expectedRoleId := rand.Uint64()
	expectedExpiredAt := rand.Uint64()

	dataset := convertToByte(expectedUserId, expectedUserName, expectedRoleId, expectedExpiredAt)
	if l := len(expectedUserId) + len(expectedUserName) + 40; len(dataset) != l {
		t.Fatalf("incoorect token dataset, got %d, expected %d", len(dataset), l)
	}

	actualUserId, actualUserName, actualRoleId, actualExpiredAt, err := convertFromByte(dataset)
	if err != nil {
		t.Fatal(err)
	}

	if e, a := string(expectedUserId), string(actualUserId); e != a {
		t.Errorf("incoorect token userId, got %s, expected %s", a, e)
	}

	if e, a := string(expectedUserName), string(actualUserName); e != a {
		t.Errorf("incoorect token userName, got %s, expected %s", a, e)
	}

	if e, a := expectedRoleId, actualRoleId; e != a {
		t.Errorf("incoorect token userRoleId, got %d, expected %d", a, e)
	}

	if e, a := expectedExpiredAt, actualExpiredAt; e != a {
		t.Errorf("incoorect token expiredAt, got %d, expected %d", a, e)
	}
}

func TestCrypt(t *testing.T) {
	expectedDataset := bytes.Repeat([]byte{'x'}, 52)
	secretKey := uuid.NewV4().Bytes()

	d, err := encrypt(expectedDataset, secretKey)
	if err != nil {
		t.Fatal(err)
	}
	if a, e := len(d), len(expectedDataset)+8+16; a == e {
		t.Fatalf("incoorect external token, got %d, expected %d", a, e)
	}
	if bytes.Compare(d, expectedDataset) == 0 {
		t.Fatalf("incoorect external token")
	}

	actualDataset, err := decrypt(d, secretKey)
	if err != nil {
		t.Fatal(err)
	}
	if a, e := len(actualDataset), len(expectedDataset); a != e {
		t.Fatalf("incoorect internal token, got %d, expected %d", a, e)
	}
	if bytes.Compare(actualDataset, expectedDataset) != 0 {
		t.Fatalf("incoorect internal token")
	}
}
