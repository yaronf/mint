package mint

import "testing"

func initTest() pinningStore {
	config := Config{pinningDB:"testDB.db"}
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
}
