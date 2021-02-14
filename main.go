package main

import (
	"bytes"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"runtime"
	"strings"
	"sync/atomic"
	"time"
)

var (
	tries uint64
	hits  uint64
	enc   = base32.StdEncoding.WithPadding(base32.NoPadding)
)

func run(prefix []byte) {
	b32pub := make([]byte, enc.EncodedLen(32))
	seed := make([]byte, ed25519.SeedSize)
	cutLength := 32 + enc.DecodedLen(len(prefix)) + 1
start:
	if _, err := cryptorand.Read(seed); err != nil {
		panic(err)
	}
	key := ed25519.NewKeyFromSeed(seed)
	enc.Encode(b32pub, key[32:cutLength])
	if bytes.HasPrefix(b32pub, prefix) {
		enc.Encode(b32pub, key[32:])
		b64Key := base64.StdEncoding.EncodeToString(key)
		hitN := atomic.AddUint64(&hits, 1)
		log.Printf("\n[SUCCESS] FOUND! PUB BASE32: %s\n[SUCCESS] Key (torev format): %s\n[SUCCESS] Found %d keys so far.", b32pub, b64Key, hitN)
		fmt.Printf("%s|%s\n", b32pub, b64Key)
	}
	atomic.AddUint64(&tries, 1)
	goto start
}

func main() {
	var (
		prefix     string
		goroutines int
	)
	flag.StringVar(&prefix, "prefix", "tor", "Prefix to search for")
	flag.IntVar(&goroutines, "goroutines", runtime.NumCPU(), "Number of goroutines to spawn")
	flag.Parse()

	prefix = strings.ToUpper(prefix)

	log.Printf("[INFO] Searching for a public key with the prefix of: %s", prefix)
	log.Printf("[INFO] Spawning %d goroutines.", goroutines)

	for i := 0; i < goroutines; i++ {
		go run([]byte(prefix))
	}

	total := uint64(0)
	for range time.Tick(1 * time.Second) {
		count := atomic.SwapUint64(&tries, 0)
		total += count
		log.Printf("[PROGRESS] Generating %d keys per second. Generated %d keys in total.", count, total)
	}
}
