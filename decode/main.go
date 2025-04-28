package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"

	// External dependency for UUID parsing
	"github.com/insomniacslk/dhcp/dhcpv6"
)

func main() {
	// --- Argument Parsing ---
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "Usage: decode_duid <DUID_hex_string>")
		fmt.Fprintln(os.Stderr, "Example: decode_duid 00:01:00:01:2c:3d:4e:5f:aa:bb:cc:dd:ee:ff")
		fmt.Fprintln(os.Stderr, "DUID hex string is missing or extra arguments provided. Please try again.")
		os.Exit(1)
	}
	duidHexString := os.Args[1]
	cleanedHexString := strings.ReplaceAll(duidHexString, ":", "")

	duidBytes, err := hex.DecodeString(cleanedHexString)
	if err != nil {
		log.Fatalf("Error: Invalid hex string format provided: '%s'\n%v\nEnsure the string contains only hex characters (0-9, a-f, A-F) and optional colons.", duidHexString, err)
	}

	duid, err := dhcpv6.DUIDFromBytes(duidBytes)

	if err != nil {
		log.Fatalf("error %s decoding as DUID", err)
	}

	println(duid.String())
}
