// Resolve and print secret names (not values) for the token in $SEEKRIT_TOKEN.
//
//	export SEEKRIT_TOKEN=skt_...
//	go run ./example
package main

import (
	"context"
	"fmt"
	"log"
	"sort"

	seekrit "github.com/seekritdev/go-sdk"
)

func main() {
	client, err := seekrit.New()
	if err != nil {
		log.Fatal(err)
	}
	secrets, err := client.Resolve(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	names := make([]string, 0, len(secrets))
	for name := range secrets {
		names = append(names, name)
	}
	sort.Strings(names)
	fmt.Printf("resolved %d secret(s):\n", len(names))
	for _, name := range names {
		fmt.Printf("  - %s\n", name)
	}
}
