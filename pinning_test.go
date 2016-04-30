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

	// store an expired ticket
	origin = "orig2.example.com"
	ticket = []byte("1122334455aabbccddee")
	pinningSecret = []byte("zzxxccvv!!@@##$$")
	lifetime = -60 // negative to ensure expiry!
	ps.storeTicket(origin, ticket, pinningSecret, lifetime)
	_, _, _, found = ps.readTicket(origin)
	assertEquals(t, found, false)

	// test clientCleanup
	origin = "orig1.example.com"
	tkt, psec, _, found = ps.readTicket(origin)
	assertEquals(t, found, true)
	ps.clientCleanup()
	tkt, psec, _, found = ps.readTicket(origin)
	assertEquals(t, found, false)
}

func TestStoreProtectionKey(t *testing.T) {
	ps := initTest()
	defer finalizeTest(ps)

	key := []byte("this is a key")
	validFrom := time.Now()
	validUntil := time.Now().Add(1 * time.Hour)
	keyID := ps.storeProtectionKey(key, validFrom, validUntil)
	key2, found := ps.readProtectionKey(keyID)
	assertEquals(t, found, true)
	assertDeepEquals(t, key, key2)

	keyID = 0x777777
	key2, found = ps.readProtectionKey(keyID)
	assertEquals(t, found, false)
}

func TestReadCurrentProtectionKey(t *testing.T) {
	ps := initTest()
	defer finalizeTest(ps)

	key := []byte("this is a key")
	validFrom := time.Now().Add(-3 * time.Minute)
	validUntil := time.Now().Add(-2 * time.Hour)
	keyID := ps.storeProtectionKey(key, validFrom, validUntil)
	key2, keyID2, found := ps.readCurrentProtectionKey()
	assertEquals(t, found, false)

	key = []byte("this is another key")
	validFrom = time.Now().Add(-1 * time.Minute)
	validUntil = time.Now().Add(1 * time.Hour)
	keyID = ps.storeProtectionKey(key, validFrom, validUntil)
	key2, keyID2, found = ps.readCurrentProtectionKey()
	assertEquals(t, found, true)
	assertEquals(t, keyID, keyID2)
	assertDeepEquals(t, key, key2)
}

func TestCreateValidProtectionKey(t *testing.T) {
	ps := initTest()
	defer finalizeTest(ps)

	ps.createValidProtectionKey()
	_, _, found := ps.readCurrentProtectionKey()
	assertEquals(t, found, true)
}

func TestProtectTicket(t *testing.T) {
	keyID := uint64(33)
	pt := pinningTicket{protectionKeyID: keyID, ticketSecret: []byte("this is so very secret")}
	protectionKey := []byte("0123456789012345") // 16 bytes, 128 bit
	protectedTicket := pt.protect(protectionKey)
	// println("protected ticket", string(protectedTicket))
	id, err := readProtectionKeyID(protectedTicket)
	assertEquals(t, id, keyID)
	assertNotError(t, err, "read Protection Key?")
	pt2, valid := validate(protectedTicket, protectionKey)
	assertEquals(t, valid, true)
	assertDeepEquals(t, pt2, pt)

	badTicket := make([]byte, len(protectedTicket))
	copy(badTicket, protectedTicket)
	badTicket[0] = byte(10)
	pt2, valid = validate(badTicket, protectionKey)
	assertEquals(t, valid, false)
}
