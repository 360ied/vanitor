package main

import (
	"bytes"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"flag"
	"log"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"time"
)

var tries uint64

func run(prefix []byte) {
	b32pub := make([]byte, base32.StdEncoding.EncodedLen(32))
	seed := make([]byte, ed25519.SeedSize)
start:
	if _, err := cryptorand.Read(seed); err != nil {
		panic(err)
	}
	key := ed25519.NewKeyFromSeed(seed)
	base32.StdEncoding.Encode(b32pub, key[32:])
	if bytes.HasPrefix(b32pub, prefix) {
		log.Printf("[SUCCESS] FOUND! PUB BASE32: %s", b32pub)
		log.Printf("[SUCCESS] KEY (torev format): %s", base64.StdEncoding.EncodeToString(key))
		os.Exit(0)
	}
	atomic.AddUint64(&tries, 1)
	goto start
}

func main() {
	var prefix string
	var goroutines int
	flag.StringVar(&prefix, "prefix", "tor", "Prefix to search for")
	flag.IntVar(&goroutines, "goroutines", runtime.NumCPU(), "Number of goroutines to spawn")
	flag.Parse()

	prefix = strings.ToUpper(prefix)

	log.Printf("[INFO] Searching for a public key with the prefix of: %s", prefix)
	log.Printf("[INFO] Spawning %d goroutines.", goroutines)

	for i := 0; i < goroutines; i++ {
		go run([]byte(prefix))
	}

	for range time.Tick(1 * time.Second) {
		count := atomic.SwapUint64(&tries, 0)
		log.Printf("[PROGRESS] Generating %d keys per second.", count)
	}
}
