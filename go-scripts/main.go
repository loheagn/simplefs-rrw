package main

import (
	"fmt"
	"os"
)

func main() {
	byte, _ := os.ReadFile("/tmp/overlay/merged/helloc")
	for _, b := range byte {
		fmt.Print(int32(b))
	}
}
