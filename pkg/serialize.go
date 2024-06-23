package tokeninjector

import (
	"encoding/base64"
	"fmt"
	"github.com/prorochestvo/tokeninjector/internal/crypto/aes"
	"github.com/twinj/uuid"
	"hash/crc32"
	"math/bits"
	"math/rand"
	"time"
)

// Marshal creates a token string from the user id, user name, role id, and expiration time.
// The token string is encrypted with the secret key and encoded in base64.
func Marshal(userID string, userName string, roleID uint64, expiredAt time.Time, secretKey []byte) (string, error) {
	dataset := convertToByte(
		[]byte(userID),
		[]byte(userName),
		roleID,
		uint64(expiredAt.UTC().Unix()),
	)

	crypted, err := encrypt(dataset, secretKey)
	if err != nil {
		return "", err
	}

	external := base64.StdEncoding.EncodeToString(crypted)

	return external, nil
}

// Unmarshal extracts the user id, user name, role id, and expiration time from the token string.
// The token string is decoded from base64 and decrypted with the secret key.
func Unmarshal(data string, secretKey []byte) (userID string, userName string, roleID uint64, expiredAt time.Time, err error) {
	dataset, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return
	}

	internal, err := decrypt(dataset, secretKey)
	if err != nil {
		return
	}

	uID, uName, uRole, expired, err := convertFromByte(internal)
	if err != nil {
		return
	}

	userID = string(uID)
	userName = string(uName)
	roleID = uRole
	expiredAt = time.Unix(int64(expired), 0).UTC()

	return
}

// convertToByte creates a byte array from the user id, user name, role id, and expiration time.
func convertToByte(userId []byte, userName []byte, userRoleId uint64, expiredAt uint64) []byte {
	salt := uuid.NewV4().Bytes()

	lUserName := len(userName)
	lUserName = max(lUserName, 0)
	lUserName = min(lUserName, 254)

	lUserID := len(userId)
	lUserID = max(lUserID, 0)
	lUserID = min(lUserID, 100)

	b := make([]byte, lUserName+lUserID+40)
	l := 0

	// salt prefix
	for i := 0; i < 8; i++ {
		b[l+i] = salt[i]
	}
	l += 8

	// user name
	xorUserName := uint8(0)
	b[l+0] = 'N'
	b[l+1] = uint8(lUserName)
	l += 2
	for i := 0; i < lUserName; i++ {
		b[l+i] = userName[i]
		xorUserName = xorUserName ^ userName[i]
	}
	l += lUserName

	// user id
	xorUserID := uint8(0)
	b[l+0] = 'I'
	b[l+1] = uint8(lUserID)
	l += 2
	for i := 0; i < lUserID; i++ {
		b[l+i] = userId[i]
		xorUserID = xorUserID ^ userId[i]
	}
	l += lUserID

	// expired at
	b[l+0] = uint8((expiredAt & 0xFF00000000000000) >> 56)
	b[l+1] = uint8((expiredAt & 0xFF000000000000) >> 48)
	b[l+2] = uint8((expiredAt & 0xFF0000000000) >> 40)
	b[l+3] = uint8((expiredAt & 0xFF00000000) >> 32)
	b[l+4] = uint8((expiredAt & 0xFF000000) >> 24)
	b[l+5] = uint8((expiredAt & 0xFF0000) >> 16)
	b[l+6] = uint8((expiredAt & 0xFF00) >> 8)
	b[l+7] = uint8(expiredAt & 0xFF)
	l += 8

	// role id
	b[l+0] = uint8((userRoleId & 0xFF00000000000000) >> 56)
	b[l+1] = uint8((userRoleId & 0xFF000000000000) >> 48)
	b[l+2] = uint8((userRoleId & 0xFF0000000000) >> 40)
	b[l+3] = uint8((userRoleId & 0xFF00000000) >> 32)
	b[l+4] = uint8((userRoleId & 0xFF000000) >> 24)
	b[l+5] = uint8((userRoleId & 0xFF0000) >> 16)
	b[l+6] = uint8((userRoleId & 0xFF00) >> 8)
	b[l+7] = uint8(userRoleId & 0xFF)
	l += 8

	// salt suffix
	for i := 0; i < 8; i++ {
		b[l+i] = salt[i+8]
	}
	l += 8

	// hash
	b[l+3] = uint8((lUserName ^ lUserID) & 0xFF)
	b[l+2] = xorUserID
	b[l+1] = xorUserName
	b[l+0] = uint8((expiredAt ^ userRoleId) & 0xFF)
	l += 4

	return b
}

// convertFromByte extracts the user id, user name, role id, and expiration time from the byte array.
func convertFromByte(data []byte) (userId []byte, userName []byte, userRoleId uint64, expiredAt uint64, err error) {
	if len(data) <= 40 {
		err = fmt.Errorf("incorrect dataset size")
		return
	}

	l := 0

	// user name
	l += 8
	if data[l] != 'N' {
		err = fmt.Errorf("incorrect dataset")
		return
	}
	l += 2
	lUserName := int(data[l-1])
	lUserName = max(lUserName, 0)
	lUserName = min(lUserName, 254)
	userName = data[l : l+lUserName]
	l += lUserName

	// user id
	if data[l] != 'I' {
		err = fmt.Errorf("incorrect dataset")
		return
	}
	l += 2
	lUserID := int(data[l-1])
	lUserID = max(lUserID, 0)
	lUserID = min(lUserID, 254)
	userId = data[l : l+lUserID]
	l += lUserID

	// expired at
	expiredAt = 0
	expiredAt = expiredAt | ((uint64(data[l+0]) << 56) & 0xFF00000000000000)
	expiredAt = expiredAt | ((uint64(data[l+1]) << 48) & 0x00FF000000000000)
	expiredAt = expiredAt | ((uint64(data[l+2]) << 40) & 0x0000FF0000000000)
	expiredAt = expiredAt | ((uint64(data[l+3]) << 32) & 0x000000FF00000000)
	expiredAt = expiredAt | ((uint64(data[l+4]) << 24) & 0x00000000FF000000)
	expiredAt = expiredAt | ((uint64(data[l+5]) << 16) & 0x0000000000FF0000)
	expiredAt = expiredAt | ((uint64(data[l+6]) << 8) & 0x000000000000FF00)
	expiredAt = expiredAt | (uint64(data[l+7]) & 0x00000000000000FF)
	l += 8

	// role id
	userRoleId = 0
	userRoleId = userRoleId | ((uint64(data[l+0]) << 56) & 0xFF00000000000000)
	userRoleId = userRoleId | ((uint64(data[l+1]) << 48) & 0x00FF000000000000)
	userRoleId = userRoleId | ((uint64(data[l+2]) << 40) & 0x0000FF0000000000)
	userRoleId = userRoleId | ((uint64(data[l+3]) << 32) & 0x000000FF00000000)
	userRoleId = userRoleId | ((uint64(data[l+4]) << 24) & 0x00000000FF000000)
	userRoleId = userRoleId | ((uint64(data[l+5]) << 16) & 0x0000000000FF0000)
	userRoleId = userRoleId | ((uint64(data[l+6]) << 8) & 0x000000000000FF00)
	userRoleId = userRoleId | (uint64(data[l+7]) & 0x00000000000000FF)
	l += 8

	// hash check len user id and name
	if hashLenUserIdAndName, hashCurrent := data[l+8+3], uint8((lUserName^lUserID)&0xFF); hashLenUserIdAndName != hashCurrent {
		err = fmt.Errorf("incorrect dataset hash")
		return
	}

	// hash check of userId
	hashUserID := data[l+8+2]
	xorUserID := uint8(0)
	for i := 0; i < lUserID; i++ {
		xorUserID = xorUserID ^ userId[i]
	}
	if xorUserID != hashUserID {
		err = fmt.Errorf("incorrect dataset hash")
		return
	}

	// hash check of userName
	hashUserName := data[l+8+1]
	xorUserName := uint8(0)
	for i := 0; i < lUserName; i++ {
		xorUserName = xorUserName ^ userName[i]
	}
	if xorUserName != hashUserName {
		err = fmt.Errorf("incorrect dataset hash")
		return
	}

	// hash check role and expired time
	if hashRoleIdAndExpiredAt, hashCurrent := data[l+8+0], uint8((expiredAt^userRoleId)&0xFF); hashRoleIdAndExpiredAt != hashCurrent {
		err = fmt.Errorf("incorrect dataset hash")
		return
	}

	return
}

// encrypt encrypts the data with the secret key.
func encrypt(data, secretKey []byte) ([]byte, error) {
	var err error
	// hash crc32
	hash := crc32.Checksum(data, crc32TableHash)

	var lData = uint64(len(data))

	// combine
	lDataset := 8 + uint64(len(data)) + 4 + (lData+1)%16
	dataset := make([]byte, lDataset)
	var l uint64 = 0
	dataset[l+0] = uint8((lData & 0xFF00000000000000) >> 56)
	dataset[l+1] = uint8((lData & 0x00FF000000000000) >> 48)
	dataset[l+2] = uint8((lData & 0x0000FF0000000000) >> 40)
	dataset[l+3] = uint8((lData & 0x000000FF00000000) >> 32)
	dataset[l+4] = uint8((lData & 0x00000000FF000000) >> 24)
	dataset[l+5] = uint8((lData & 0x0000000000FF0000) >> 16)
	dataset[l+6] = uint8((lData & 0x000000000000FF00) >> 8)
	dataset[l+7] = uint8(lData & 0x00000000000000FF)
	l += 8
	copy(dataset[l:], data)
	l += lData
	dataset[l+3] = uint8((hash & 0xFF000000) >> 24)
	dataset[l+2] = uint8((hash & 0x00FF0000) >> 16)
	dataset[l+1] = uint8((hash & 0x0000FF00) >> 8)
	dataset[l+0] = uint8(hash & 0x000000FF)
	l += 4
	for ; l < lDataset; l++ {
		dataset[l] = uint8(rand.Int31())
	}

	// aes encryption
	externalVersion, err := aes.Marshal(dataset, secretKey)
	if err != nil {
		return nil, err
	}

	return externalVersion, nil
}

// decrypt decrypts the data with the secret key.
func decrypt(data, secretKey []byte) ([]byte, error) {
	var l uint64 = 0

	// aes decryption
	internalVersion, err := aes.Unmarshal(data, secretKey)
	if err != nil {
		return nil, err
	}

	var lData uint64 = 0
	lData = lData | ((uint64(internalVersion[l+0]) << 56) & 0xFF00000000000000)
	lData = lData | ((uint64(internalVersion[l+1]) << 48) & 0x00FF000000000000)
	lData = lData | ((uint64(internalVersion[l+2]) << 40) & 0x0000FF0000000000)
	lData = lData | ((uint64(internalVersion[l+3]) << 32) & 0x000000FF00000000)
	lData = lData | ((uint64(internalVersion[l+4]) << 24) & 0x00000000FF000000)
	lData = lData | ((uint64(internalVersion[l+5]) << 16) & 0x0000000000FF0000)
	lData = lData | ((uint64(internalVersion[l+6]) << 8) & 0x000000000000FF00)
	lData = lData | (uint64(internalVersion[l+7]) & 0x00000000000000FF)
	l += 8

	// dataset
	dataset := internalVersion[l : l+lData]
	l += lData

	// hash crc32
	hash := uint32(0)
	hash = hash | ((uint32(internalVersion[l+3]) << 24) & 0xFF000000)
	hash = hash | ((uint32(internalVersion[l+2]) << 16) & 0x00FF0000)
	hash = hash | ((uint32(internalVersion[l+1]) << 8) & 0x0000FF00)
	hash = hash | (uint32(internalVersion[l+0]) & 0x000000FF)
	l += 4

	if h := crc32.Checksum(dataset, crc32TableHash); hash != h {
		return nil, fmt.Errorf("incorrect hash of data, %X != %X", hash, h)
	}

	return dataset, nil
}

var crc32TableHash = crc32.MakeTable(bits.Reverse32(0xF4ACFB10)) // CRM32 for hash of token data
