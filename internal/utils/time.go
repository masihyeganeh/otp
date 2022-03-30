package utils

import "time"

func TimestampMs() int64 {
	return time.Now().UnixNano() / int64(time.Millisecond)
}
