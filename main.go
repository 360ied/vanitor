package main

import (
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"regexp"
	"runtime"
	"sync/atomic"
	"time"
)

var (
	tries uint64
	hits  uint64
	enc   = base32.StdEncoding.WithPadding(base32.NoPadding)
)

func run(prefix []byte, re *regexp.Regexp) {
	b32pub := make([]byte, enc.EncodedLen(32))
	seed := make([]byte, ed25519.SeedSize)
start:
	if _, err := cryptorand.Read(seed); err != nil {
		panic(err)
	}
	key := ed25519.NewKeyFromSeed(seed)
	enc.Encode(b32pub, key[32:])
	if re.Match(b32pub) {
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
		reS        string
		goroutines int
	)
	flag.StringVar(&reS, "re", "tor", "Regex to match")
	flag.IntVar(&goroutines, "goroutines", runtime.NumCPU(), "Number of goroutines to spawn")
	flag.Parse()

	reS = `(?i)` + reS // case insensitive matching
	re := regexp.MustCompile(reS)

	log.Printf("[INFO] Searching for a public key that matches: %s", reS)
	log.Printf("[INFO] Spawning %d goroutines.", goroutines)

	for i := 0; i < goroutines; i++ {
		go run([]byte(reS), re)
	}

	total := uint64(0)
	for range time.Tick(1 * time.Second) {
		count := atomic.SwapUint64(&tries, 0)
		total += count
		log.Printf("[PROGRESS] Generating %d keys per second. Generated %d keys in total.", count, total)
	}
}
