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
	tries     uint64
	hits      uint64
	enc       = base32.StdEncoding.WithPadding(base32.NoPadding)
	startTime = time.Now()
)

func reportHit(b64Buf []byte, key ed25519.PrivateKey, b32pub []byte) {
	base64.StdEncoding.Encode(b64Buf, key)
	hitN := atomic.AddUint64(&hits, 1)
	hitsPerMinute := float64(hitN) / time.Since(startTime).Minutes()
	log.Printf("\n"+
		"[SUCCESS] FOUND! PUB BASE32: %s\n"+
		"[SUCCESS] Key (torev format): %s\n"+
		"[SUCCESS] Found %d keys so far. %.1f/minute %.1f/hour %.1f/day %.1f/week",
		b32pub,
		b64Buf,
		hitN, hitsPerMinute, hitsPerMinute*60, hitsPerMinute*60*24, hitsPerMinute*60*24*7)
	fmt.Printf("%s|%s\n", b32pub, b64Buf)
}

func run(re *regexp.Regexp) {
	b32pub := make([]byte, enc.EncodedLen(32))
	seed := make([]byte, ed25519.SeedSize)
	b64Buf := make([]byte, base64.StdEncoding.EncodedLen(ed25519.PrivateKeySize))
	for {
		if _, err := cryptorand.Read(seed); err != nil {
			panic(err)
		}
		key := ed25519.NewKeyFromSeed(seed)
		enc.Encode(b32pub, key[32:])
		if re.Match(b32pub) {
			reportHit(b64Buf, key, b32pub)
		}
		atomic.AddUint64(&tries, 1)
	}
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
		go run(re)
	}

	total := uint64(0)
	for range time.Tick(1 * time.Second) {
		count := atomic.SwapUint64(&tries, 0)
		total += count
		log.Printf("[PROGRESS] Generating %d keys per second. Generated %d keys in total.", count, total)
	}
}
