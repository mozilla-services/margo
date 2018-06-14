package mar

import "errors"

var (
	errBadMarID       = errors.New("mar ID must be MAR1")
	errOffsetTooSmall = errors.New("offset to index is too small to be valid")
	errBadSigAlg      = errors.New("bad signature algorithm")
)
