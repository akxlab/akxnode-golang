package utils

import (
	"github.com/mazen160/go-random"
)

func GetRandomSeed() ([]byte, error) {
	return random.Bytes(64)
}
