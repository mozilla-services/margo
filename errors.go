package mar

import (
	"errors"
	"fmt"
)

var (
	limitMinFileSize           = MarIDLen + OffsetToIndexLen + SignaturesHeaderLen + AdditionalSectionsHeaderLen + IndexHeaderLen
	limitMaxFileSize    uint64 = 2147483648
	limitFileNameLength        = 1024
)

var (
	errBadMarID               = errors.New("mar ID must be MAR1")
	errOffsetTooSmall         = errors.New("offset to index is too small to be valid")
	errBadSigAlg              = errors.New("bad signature algorithm")
	errInputTooShort          = errors.New("refusing to read more bytes than present in input")
	errMalformedFileSize      = errors.New("the total file size does not match offset + index size")
	errTooBig                 = errors.New("the total file exceeds the maximum allowed of 2GB")
	errMalformedIndexFileName = errors.New("malformed index is missing null terminator in file name")
	errIndexFileNameTooBig    = errors.New("index file name exceeds the maximum length of 1024 characters")
	errIndexFileNameOverrun   = errors.New("the length of the index file overruns the end of the file")
	errCursorStartAlreadyRead = errors.New("start position has already been read in a previous chunk")
	errCursorEndAlreadyRead   = errors.New("end position has already been read in a previous chunk")
)

const debug = false

func debugPrint(format string, a ...interface{}) {
	if debug {
		fmt.Printf(format, a...)
	}
}
