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
	"fmt"
	"crypto"
	"crypto/x509"
	"crypto/hmac"
)

type pinningStore struct {
	db sql.DB
}

var ps pinningStore

const (
	pinningTicketSecretLen = 16 // bytes
	logTypeTicketPinning = "pinning"
)

func InitPinningStore(config *Config) {
	ps = pinningStore{}
	ps.initDB(*config)
}

func (ps *pinningStore) initDB(config Config) {
	db, err := sql.Open("sqlite3", config.PinningDB)
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
	create table if not exists protection_keys (keyid integer primary key autoincrement,
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

// Store ticket in client-side database. Lifetime given in seconds.
func (ps *pinningStore) storeTicket(origin string, ticket []byte, pinningSecret []byte, lifetime int) {
	validUntil := time.Now().Add(time.Duration(lifetime) * time.Second).Unix()
	_, err := ps.db.Exec("insert or replace into tickets values (?, ?, ?, ?)", origin, ticket, pinningSecret, validUntil)
	if err != nil {
		log.Fatal(err)
	}
}

// Client check: is ticket expired? Client only sends the ticket up to 10s before the nominal expiry
func (ps *pinningStore) expired(validUntil time.Time) bool {
	const validityMargin = 10 * time.Second
	return validUntil.Before(time.Now().Add(-validityMargin))
}

// Read the ticket from the store, indexed by origin. Ticket must be unexpired
func (ps *pinningStore) readTicket(origin string) (opaque []byte, pinningSecret []byte, validUntil time.Time, found bool) {
	rows, err := ps.db.Query("select opaque, pinning_secret, valid_until from tickets where origin = ?", origin)
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
	found = !ps.expired(validUntil)
	return
}

func (ps *pinningStore) storeProtectionKey(key []byte, validFrom time.Time, validUntil time.Time) uint64 {
	result, err := ps.db.Exec("insert into protection_keys(key, valid_from, valid_until) values (?, ?, ?)", key, validFrom, validUntil)
	if err != nil {
		log.Fatal(err)
	}
	keyID, err := result.LastInsertId()
	if err != nil {
		log.Fatal(err)
	}
	return uint64(keyID)
}

func (ps *pinningStore) readProtectionKey(keyID uint64) (key []byte, found bool) {
	rows, err := ps.db.Query("select key from protection_keys where keyid = ?", keyID)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	if !rows.Next() {
		found = false
		return
	}
	rows.Scan(&key)
	found = true
	return
}

// Read the current protection key. If there are several that are current, reads an arbitrary one.
func (ps *pinningStore) readCurrentProtectionKey() (key []byte, keyID uint64, found bool) {
	now := time.Now()
	// sqlite: this is string comparison, and it works!
	rows, err := ps.db.Query("select key, keyid from protection_keys where ? between valid_from and valid_until", now)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	if !rows.Next() {
		found = false
		return
	}
	rows.Scan(&key, &keyID)
	found = true
	return
}

// Create a protection key that's immediately valid
func (ps *pinningStore) createValidProtectionKey() {
	key := make([]byte, 16) // AES-256
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err.Error())
	}
	validFrom := time.Now().Add(-1 * time.Minute)
	validUntil := time.Now().Add(1 * time.Hour)
	_ = ps.storeProtectionKey(key, validFrom, validUntil)
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
	protectionKeyID uint64 // integrity protected (AAD)
	ticketSecret    []byte // encrypted
}

func (pt *pinningTicket) protect(protectionKey []byte) []byte {
	block, err := aes.NewCipher(protectionKey)
	if err != nil {
		panic(err.Error())
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	pkIDbytes := make([]byte, 8)
	binary.BigEndian.PutUint64(pkIDbytes, pt.protectionKeyID)
	encryptedTicket := aesgcm.Seal(nil, nonce, pt.ticketSecret, pkIDbytes)
	return bytes.Join([][]byte{pkIDbytes, nonce, encryptedTicket}, []byte{})
}

func readProtectionKeyID(sealedTicket []byte) (pkID uint64, err error) {
	if len(sealedTicket) < 4 {
		return 0, fmt.Errorf("Sealed ticket too short")
	}
	return binary.BigEndian.Uint64(sealedTicket[0:8]), nil
}

func validate(sealedTicket []byte, protectionKey []byte) (pt pinningTicket, err error) {
	if len(sealedTicket) < 8 {
		err = fmt.Errorf("Ticket pinning: sealed ticket too short")
		return
	}
	pt.protectionKeyID = binary.BigEndian.Uint64(sealedTicket[0:8])
	block, err := aes.NewCipher(protectionKey)
	if err != nil {
		panic(err.Error())
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := sealedTicket[8 : 8 + aesgcm.NonceSize()]
	cipherText := sealedTicket[8 + aesgcm.NonceSize():]
	pkIDbytes := make([]byte, 8)
	binary.BigEndian.PutUint64(pkIDbytes, pt.protectionKeyID)
	pt.ticketSecret, err = aesgcm.Open(nil, nonce, cipherText, pkIDbytes)
	if err != nil {
		err = fmt.Errorf("Ticket pinning: failed to decrypt ticket")
		return
	}
	return
}

func newTicketSecret(hash crypto.Hash, xSS []byte, xES []byte) []byte {
	length := pinningTicketSecretLen
	dhSecrets := bytes.Join([][]byte{xSS, xES}, nil)
	ext := hkdfExtract(hash, nil, dhSecrets)
	return hkdfExpandLabel(hash, ext, "pinning secret", nil, length)
}

func newPinningProof(hash crypto.Hash, pinningSecret []byte, cRandom []byte, sRandom []byte, pubKey crypto.PublicKey) (proof []byte, err error) {
	der, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return
	}
	h := hash.New()
	h.Write(der)
	pkeyHash := h.Sum(nil)
	rawProof := bytes.Join([][]byte{[]byte("pinning proof"), []byte{byte(len(cRandom))}, cRandom, []byte{byte(len(sRandom))}, sRandom, pkeyHash}, nil)
	hm := hmac.New(hash.New, pinningSecret)
	hm.Write(rawProof)
	proof = hm.Sum(nil)
	return
}
