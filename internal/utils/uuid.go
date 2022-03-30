package utils

import (
	"github.com/google/uuid"
	"log"
)

func MustGenerateUUID() string {
	code, err := uuid.NewRandom()
	if err != nil {
		log.Fatal(err)
	}
	return code.String()
}
