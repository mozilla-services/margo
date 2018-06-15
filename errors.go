package mar

import (
	"errors"
	"fmt"
)

var (
	limitMinFileSize = MarIDLen + OffsetToIndexLen + SignaturesHeaderLen + AdditionalSectionsHeaderLen + IndexHeaderLen

	// the maximum size we'll agree to parse is 2GB.
	// People From The Future, if this isn't large enough for you, feel
	// free to increase it, and have some self reflection because 640k
	// oughta be enough for everybody!
	limitMaxFileSize uint64 = 2147483648

	// filenames in the index shouldn't be longer than 1024 characters
	limitFileNameLength = 1024
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

// change that at runtime by setting -ldflags "-X go.mozilla.org/mar.debug=true"
const debug = false

func debugPrint(format string, a ...interface{}) {
	if debug {
		fmt.Printf(format, a...)
	}
}
