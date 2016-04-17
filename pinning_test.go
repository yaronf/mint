package mint

import (
	"testing"
	"time"
)

func initTest() pinningStore {
	config := Config{PinningDB: "testDB.db"}
	ps := pinningStore{}
	ps.initDB(config)
	return ps
}

func finalizeTest(ps pinningStore) {
	ps.deleteDB()
	ps.closeDB()
}

func TestInitDB(t *testing.T) {
	ps := initTest()
	finalizeTest(ps)
}

func TestStoreTicket(t *testing.T) {
	ps := initTest()
	defer finalizeTest(ps)

	origin := "orig1.example.com"
	ticket := []byte("1122334455aabbccdd")
	pinningSecret := []byte("zzxxccvv!!@@##$$")
	lifetime := 99
	ps.storeTicket(origin, ticket, pinningSecret, lifetime)
	tkt, psec, _, found := ps.readTicket(origin)
	assertDeepEquals(t, ticket, tkt)
	assertDeepEquals(t, pinningSecret, psec)
	assertEquals(t, found, true)
	tkt, psec, _, found = ps.readTicket("no such origin")
	assertEquals(t, found, false)

	origin = "orig2.example.com"
	ticket = []byte("1122334455aabbccddee")
	pinningSecret = []byte("zzxxccvv!!@@##$$")
	lifetime = -60 // negative to ensure expiry!
	ps.storeTicket(origin, ticket, pinningSecret, lifetime)
	_, _, _, found = ps.readTicket(origin)
	assertEquals(t, found, false)
}

func TestStoreProtectionKey(t *testing.T) {
	ps := initTest()
	defer finalizeTest(ps)

	keyID := 0x11223344
	key := []byte("this is a key")
	validFrom := time.Now()
	validUntil := time.Now().Add(1 * time.Hour)
	ps.storeProtectionKey(keyID, key, validFrom, validUntil)
	key2, validFrom2, validUntil2, found := ps.readProtectionKey(keyID)
	assertEquals(t, found, true)
	assertDeepEquals(t, key, key2)
	assert(t, validFrom.Equal(validFrom2), "Incorrect validFrom")
	assert(t, validUntil.Equal(validUntil2), "Incorrect validUntil")

	keyID = 0x777777
	key2, validFrom2, validUntil2, found = ps.readProtectionKey(keyID)
	assertEquals(t, found, false)
}

func TestReadCurrentProtectionKey(t *testing.T) {
	ps := initTest()
	defer finalizeTest(ps)

	keyID := 0x112233
	key := []byte("this is a key")
	validFrom := time.Now().Add(-3 * time.Minute)
	validUntil := time.Now().Add(-2 * time.Hour)
	ps.storeProtectionKey(keyID, key, validFrom, validUntil)
	key2, validFrom2, validUntil2, found := ps.readCurrentProtectionKey()
	assertEquals(t, found, false)

	keyID = 0x11223344
	key = []byte("this is another key")
	validFrom = time.Now().Add(-1 * time.Minute)
	validUntil = time.Now().Add(1 * time.Hour)
	ps.storeProtectionKey(keyID, key, validFrom, validUntil)
	key2, validFrom2, validUntil2, found = ps.readCurrentProtectionKey()
	assertEquals(t, found, true)
	assertDeepEquals(t, key, key2)
	assert(t, validFrom.Equal(validFrom2), "Incorrect validFrom")
	assert(t, validUntil.Equal(validUntil2), "Incorrect validUntil")
}

func TestProtectTicket(t *testing.T) {
	pt := pinningTicket{protectionKeyID: 33, ticketSecret: []byte("this is so very secret")}
	protectionKey := []byte("0123456789012345") // 16 bytes, 128 bit
	protectedTicket := pt.Protect(protectionKey)
	// println("protected ticket", string(protectedTicket))
	assertEquals(t, ReadProtectionKeyID(protectedTicket), 33)
	pt2, valid := Validate(protectedTicket, protectionKey)
	assertEquals(t, valid, true)
	assertDeepEquals(t, pt2, pt)

	badTicket := make([]byte, len(protectedTicket))
	copy(badTicket, protectedTicket)
	badTicket[0] = byte(10)
	pt2, valid = Validate(badTicket, protectionKey)
	assertEquals(t, valid, false)
}
