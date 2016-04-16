package mint

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	_ "github.com/mattn/go-sqlite3"
	"io"
	"log"
	"time"
)

type pinningStore struct {
	db sql.DB
}

func (ps *pinningStore) initDB(config Config) {
	if config.pinningDB == "" {
		return
	}

	db, err := sql.Open("sqlite3", config.pinningDB)
	if err != nil {
		log.Fatal(err)
	}
	ps.db = *db

	// Client-side
	sqlStmt := `
	create table if not exists tickets (origin string not null primary key,
		opaque blob not null,
		pinning_secret blob not null,
		valid_until datetime);
	`
	_, err = ps.db.Exec(sqlStmt)
	if err != nil {
		log.Fatalf("%q: %s\n", err, sqlStmt)
	}

	// Server-side
	sqlStmt = `
	create table if not exists protection_keys (keyid integer not null primary key,
		key blob not null,
		valid_from datetime,
		valid_until datetime);
	`
	_, err = ps.db.Exec(sqlStmt)
	if err != nil {
		log.Fatalf("%q: %s\n", err, sqlStmt)
	}
}

func (ps *pinningStore) closeDB() {
	err := ps.db.Close()
	if err != nil {
		log.Fatal(err)
	}
}

func (ps *pinningStore) deleteDB() {
	_, err := ps.db.Exec("delete from tickets")
	if err != nil {
		log.Fatal(err)
	}
	_, err = ps.db.Exec("delete from protection_keys")
	if err != nil {
		log.Fatal(err)
	}
}

func (ps *pinningStore) storeTicket(origin string, ticket []byte, pinningSecret []byte, lifetime int) {
	stmt, err := ps.db.Prepare("insert or replace into tickets values (?, ?, ?, ?)")
	if err != nil {
		log.Fatal(err)
	}
	defer stmt.Close()
	validUntil := time.Now().Add(time.Duration(lifetime)).Unix()
	_, err = stmt.Exec(origin, ticket, pinningSecret, validUntil)
	if err != nil {
		log.Fatal(err)
	}
}

// Client only sends the ticket up to 10s before the nominal expiry
func (ps *pinningStore) expired(validUntil time.Time) bool {
	const validityMargin = 10 * time.Second
	return validUntil.Before(time.Now().Add(-validityMargin))
}

// Read the ticket from the store, indexed by origin
func (ps *pinningStore) readTicket(origin string) (opaque []byte, pinningSecret []byte, validUntil time.Time, found bool) {
	stmt, err := ps.db.Prepare("select opaque, pinning_secret, valid_until from tickets where origin = ?")
	if err != nil {
		log.Fatal(err)
	}
	defer stmt.Close()
	rows, err := stmt.Query(origin)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	if !rows.Next() {
		found = false
		return
	}
	rows.Scan(&opaque, &pinningSecret, &validUntil)
	// validUntil = time.Unix(int64(validUntilUnix), 0)
	found = true
	return
}

func (ps *pinningStore) storeProtectionKey(keyID int, key []byte, validFrom time.Time, validUntil time.Time) {
	stmt, err := ps.db.Prepare("insert or replace into protection_keys values (?, ?, ?, ?)")
	if err != nil {
		log.Fatal(err)
	}
	defer stmt.Close()
	_, err = stmt.Exec(keyID, key, validFrom, validUntil)
	if err != nil {
		log.Fatal(err)
	}
}

func (ps *pinningStore) readProtectionKey(keyID int) (key []byte, validFrom time.Time, validUntil time.Time, found bool) {
	stmt, err := ps.db.Prepare("select key_blob, valid_from, valid_until from protection_keys where key_id = ?")
	if err != nil {
		log.Fatal(err)
	}
	defer stmt.Close()
	rows, err := stmt.Query(keyID)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	if !rows.Next() {
		found = false
		return
	}
	rows.Scan(&key, &validFrom, &validUntil)
	found = true
	return
}

// Delete all tickets from client's store
func (ps *pinningStore) clientCleanup() {
	_, err := ps.db.Exec("delete from tickets")
	if err != nil {
		log.Fatal(err)
	}
}

// TODO Add server-create-first-key, server-rotate, client-cleanup, server-ramp-down ops

type pinningTicket struct {
	protectionKeyID uint32 // integrity protected (AAD)
	ticketSecret    []byte // encrypted
}

func (pt *pinningTicket) Protect(protectionKey []byte) []byte {
	block, err := aes.NewCipher(protectionKey)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, block.BlockSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	var pkIDbytes []byte
	binary.BigEndian.PutUint32(pkIDbytes, pt.protectionKeyID)
	encryptedTicket := aesgcm.Seal(nil, nonce, pt.ticketSecret, pkIDbytes)
	return bytes.Join([][]byte{pkIDbytes, nonce, encryptedTicket}, []byte{})
}

func ReadProtectionKeyID(sealedTicket []byte) int {
	return int(binary.BigEndian.Uint32(sealedTicket[0:3]))
}

func Validate(sealedTicket []byte, protectionKey []byte) (pt pinningTicket, valid bool) {
	pt.protectionKeyID = binary.BigEndian.Uint32(sealedTicket[0:3])
	block, err := aes.NewCipher(protectionKey)
	if err != nil {
		panic(err.Error())
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := sealedTicket[4 : 4+block.BlockSize()]
	cipherText := sealedTicket[4+block.BlockSize():]
	var pkIDbytes []byte
	binary.BigEndian.PutUint32(pkIDbytes, pt.protectionKeyID)
	pt.ticketSecret, err = aesgcm.Open(nil, nonce, cipherText, pkIDbytes)
	valid = (err == nil)
	return
}
