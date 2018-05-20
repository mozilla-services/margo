package mar // import "go.mozilla.org/mar"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
)

const (
	// MarIDLen is the length of the MAR ID header.
	// A MAR file starts with 4 bytes containing the MAR ID, typically "MAR1"
	MarIDLen = 4

	// OffsetToIndexLen is the length of the offset to index value.
	// The MAR file continues with the position of the index relative
	// to the beginning of the file
	OffsetToIndexLen = 4

	// SignaturesHeaderLen is the length of the signatures header
	// The signature header contains the total size of the MAR file on 8 bytes
	// and the number of signatures in the file on 4 bytes
	SignaturesHeaderLen = 12

	// SignatureEntryHeaderLen is the length of the header of each signature entry
	// Each signature entry contains an algorithm and a size, each on 4 bytes
	SignatureEntryHeaderLen = 8

	// AdditionalSectionsHeaderLen is the length of the additional sections header
	// Optional additional sections can be added, their number is stored on 4 bytes
	AdditionalSectionsHeaderLen = 4

	// AdditionalSectionsEntryHeaderLen is the length of the header of each add. section
	// Each additional section has a block size and block identifier on 4 bytes each
	AdditionalSectionsEntryHeaderLen = 8

	// IndexHeaderLen is the length of the index header
	// The size of the index is stored in a header on 4 bytes
	IndexHeaderLen = 4

	// IndexEntryHeaderLen is the length of the header of each index entry.
	// Each index entry contains a header with an offset to content (relative to
	// the beginning of the file), a content size and permission flags, each on 4 bytes
	IndexEntryHeaderLen = 12

	// SigAlgRsaPkcs1Sha1 is the ID of a signature of type RSA-PKCS1-SHA1
	SigAlgRsaPkcs1Sha1 = 1

	// SigAlgRsaPkcs1Sha384 is the ID of a signature of type RSA-PKCS1-SHA384
	SigAlgRsaPkcs1Sha384 = 2

	// BlockIDProductInfo is the ID of a Product Information Block in additional sections
	BlockIDProductInfo = 1
)

// File is a parsed MAR file.
type File struct {
	MarID                    string                   `json:"mar_id",yaml:"mar_id"`
	OffsetToIndex            uint32                   `json:"offset_to_index",yaml:"offset_to_index"`
	ProductInformation       string                   `json:"product_information,omitempty",yaml:"product_information,omitempty"`
	SignaturesHeader         SignaturesHeader         `json:"signature_header",yaml:"signature_header"`
	Signatures               []Signature              `json:"signatures",yaml:"signatures"`
	AdditionalSectionsHeader AdditionalSectionsHeader `json:"additional_sections_header",yaml:"additional_sections_header"`
	AdditionalSections       []AdditionalSection      `json:"additional_sections",yaml:"additional_sections"`
	IndexHeader              IndexHeader              `json:"index_header",yaml:"index_header"`
	Index                    []IndexEntry             `json:"index",yaml:"index"`
	Content                  map[string]Entry         `json:"content",yaml:"content"`
}

type SignaturesHeader struct {
	FileSize      uint64 `json:"file_size",yaml:"file_size"`
	NumSignatures uint32 `json:"num_signatures",yaml:"num_signatures"`
}

type Signature struct {
	SignatureEntryHeader
	Algorithm string `json:"algorithm",yaml:"algorithm"`
	Data      []byte `json:"data",yaml:"data"`
}

type SignatureEntryHeader struct {
	AlgorithmID uint32 `json:"algorithm_id",yaml:"algorithm_id"`
	Size        uint32 `json:"size",yaml:"size"`
}

type AdditionalSectionsHeader struct {
	NumAdditionalSections uint32 `json:"num_additional_sections",yaml:"num_additional_sections"`
}

type AdditionalSection struct {
	AdditionalSectionEntryHeader
	Data []byte `json:"data",yaml:"data"`
}

type AdditionalSectionEntryHeader struct {
	BlockSize uint32 `json:"block_size",yaml:"block_size"`
	BlockID   uint32 `json:"block_id",yaml:"block_id"`
}

type Entry struct {
	Data         []byte `json:"data",yaml:"data"`
	IsCompressed bool   `json:"is_compressed",yaml:"is_compressed"`
}

type IndexHeader struct {
	Size uint32 `json:"size",yaml:"size"`
}

type IndexEntry struct {
	IndexEntryHeader
	FileName string `json:"file_name",yaml:"file_name"`
}

type IndexEntryHeader struct {
	OffsetToContent uint32 `json:"offset_to_content",yaml:"offset_to_content"`
	Size            uint32 `json:"size",yaml:"size"`
	Flags           uint32 `json:"flags",yaml:"flags"`
}

// Unmarshal takes an unparsed MAR file as input and parses it into a File struct
func Unmarshal(input []byte, file *File) error {
	var (
		// current position of the cursor in the file
		cursor int

		i uint32
	)
	if len(input) < MarIDLen+OffsetToIndexLen+SignaturesHeaderLen+AdditionalSectionsHeaderLen+IndexHeaderLen {
		return fmt.Errorf("input is smaller than minimum MAR size and cannot be parsed")
	}

	// Parse the MAR ID
	marid := make([]byte, MarIDLen, MarIDLen)
	err := parse(input, &marid, cursor, MarIDLen)
	if err != nil {
		return fmt.Errorf("parsing failed at position %d: %v", cursor, err)
	}
	cursor += MarIDLen
	file.MarID = string(marid)

	// Parse the offset to the index
	err = parse(input, &file.OffsetToIndex, cursor, OffsetToIndexLen)
	if err != nil {
		return fmt.Errorf("parsing failed at position %d: %v", cursor, err)
	}
	cursor += OffsetToIndexLen

	fmt.Fprintf(os.Stderr, "Header: MAR ID=%q, Offset to Index=%d\n", file.MarID, file.OffsetToIndex)

	// Parse the Signature header
	err = parse(input, &file.SignaturesHeader, cursor, SignaturesHeaderLen)
	if err != nil {
		return fmt.Errorf("parsing failed at position %d: %v", cursor, err)
	}
	cursor += SignaturesHeaderLen
	fmt.Fprintf(os.Stderr, "\nSignatures Header: FileSize=%d, NumSignatures=%d\n", file.SignaturesHeader.FileSize, file.SignaturesHeader.NumSignatures)

	// Parse each signature and append them to the File
	for i = 0; i < file.SignaturesHeader.NumSignatures; i++ {
		var (
			sigEntryHeader SignatureEntryHeader
			sig            Signature
		)

		err = parse(input, &sigEntryHeader, cursor, SignatureEntryHeaderLen)
		if err != nil {
			return fmt.Errorf("parsing failed at position %d: %v", cursor, err)
		}
		cursor += SignatureEntryHeaderLen

		sig.AlgorithmID = sigEntryHeader.AlgorithmID
		sig.Size = sigEntryHeader.Size
		switch sig.AlgorithmID {
		case SigAlgRsaPkcs1Sha1:
			sig.Algorithm = "RSA-PKCS1-SHA1"
		case SigAlgRsaPkcs1Sha384:
			sig.Algorithm = "RSA-PKCS1-SHA384"
		default:
			sig.Algorithm = fmt.Sprintf("unknown", sig.AlgorithmID)
		}

		fmt.Fprintf(os.Stderr, "* Signature %d Entry Header: Algorithm=%q, Size=%d\n", i, sig.Algorithm, sig.Size)

		sig.Data = make([]byte, sig.Size, sig.Size)
		err = parse(input, &sig.Data, cursor, int(sig.Size))
		if err != nil {
			return fmt.Errorf("parsing failed at position %d: %v", cursor, err)
		}
		cursor += int(sig.Size)
		fmt.Fprintf(os.Stderr, "* Signature %d Data (len=%d): %X\n", i, len(sig.Data), sig.Data)
		file.Signatures = append(file.Signatures, sig)
	}

	// Parse the additional sections header
	err = parse(input, &file.AdditionalSectionsHeader, cursor, AdditionalSectionsHeaderLen)
	if err != nil {
		return fmt.Errorf("parsing failed at position %d: %v", cursor, err)
	}
	cursor += AdditionalSectionsHeaderLen
	fmt.Fprintf(os.Stderr, "\nAdditional Sections: %d\n", file.AdditionalSectionsHeader.NumAdditionalSections)

	// Parse each additional section and append them to the File
	for i = 0; i < file.AdditionalSectionsHeader.NumAdditionalSections; i++ {
		var (
			ash     AdditionalSectionEntryHeader
			as      AdditionalSection
			blockid string
		)

		err = parse(input, &ash, cursor, AdditionalSectionsEntryHeaderLen)
		if err != nil {
			return fmt.Errorf("parsing failed at position %d: %v", cursor, err)
		}
		cursor += AdditionalSectionsEntryHeaderLen

		dataSize := ash.BlockSize - AdditionalSectionsEntryHeaderLen
		as.Data = make([]byte, dataSize, dataSize)

		err = parse(input, &as.Data, cursor, int(dataSize))
		if err != nil {
			return fmt.Errorf("parsing failed at position %d: %v", cursor, err)
		}
		cursor += int(dataSize)

		switch ash.BlockID {
		case BlockIDProductInfo:
			blockid = "Product Information"
			// remove all the null bytes from the product info string
			file.ProductInformation = fmt.Sprintf("%s", strings.Replace(strings.Trim(string(as.Data), "\x00"), "\x00", " ", -1))
		default:
			blockid = fmt.Sprintf("%d (unknown)", ash.BlockID)
		}
		fmt.Fprintf(os.Stderr, "* Additional Section %d: BlockSize=%d, BlockID=%q, Data=%q (len=%d)\n", i, ash.BlockSize, blockid, as.Data, dataSize)
		file.AdditionalSections = append(file.AdditionalSections, as)
	}

	// Parse the index before parsing the content
	cursor = int(file.OffsetToIndex)
	fmt.Fprintf(os.Stderr, "\nJumping to index at offset %d\n", cursor)

	err = parse(input, &file.IndexHeader, cursor, IndexHeaderLen)
	if err != nil {
		return fmt.Errorf("parsing failed at position %d: %v", cursor, err)
	}
	cursor += IndexHeaderLen

	fmt.Fprintf(os.Stderr, "Index Size: %d\n", file.IndexHeader.Size)

	for i = 0; ; i++ {
		var (
			idxEntryHeader IndexEntryHeader
			idxEntry       IndexEntry
		)
		if cursor >= int(file.SignaturesHeader.FileSize) {
			break
		}
		err = parse(input, &idxEntryHeader, cursor, IndexEntryHeaderLen)
		if err != nil {
			return fmt.Errorf("parsing failed at position %d: %v", cursor, err)
		}
		cursor += IndexEntryHeaderLen

		idxEntry.Size = idxEntryHeader.Size
		idxEntry.Flags = idxEntryHeader.Flags
		idxEntry.OffsetToContent = idxEntryHeader.OffsetToContent

		endNamePos := bytes.Index(input[cursor:], []byte("\x00"))
		if endNamePos < 0 {
			return fmt.Errorf("malformed index is missing null terminator in file name")
		}
		idxEntry.FileName = string(input[cursor : cursor+endNamePos])
		cursor += endNamePos + 1

		fmt.Fprintf(os.Stderr, "* Index Entry %3d: Size=%10d Flags=%s Offset=%10d Name=%q\n",
			i, idxEntry.Size, os.FileMode(idxEntry.Flags), idxEntry.OffsetToContent, idxEntry.FileName)
		file.Index = append(file.Index, idxEntry)
	}

	file.Content = make(map[string]Entry)
	for _, idxEntry := range file.Index {
		var entry Entry
		// seek and read content
		entry.Data = append(entry.Data, input[idxEntry.OffsetToContent:idxEntry.OffsetToContent+idxEntry.Size]...)
		// files in MAR archives can be compressed with xz, so we test
		// the first 6 bytes to check for that
		//                                                             /---XZ's magic number--\
		if len(entry.Data) > 6 && bytes.Equal(entry.Data[0:6], []byte("\xFD\x37\x7A\x58\x5A\x00")) {
			entry.IsCompressed = true
		}
		if _, ok := file.Content[idxEntry.FileName]; ok {
			return fmt.Errorf("file named %q already exists in the archive, duplicates are not permitted", idxEntry.FileName)
		}
		file.Content[idxEntry.FileName] = entry
	}
	return nil
}

func parse(input []byte, data interface{}, cursor, readlen int) error {
	if len(input) < cursor+readlen {
		return fmt.Errorf("refused to read more bytes than present in input")
	}
	r := bytes.NewReader(input[cursor : cursor+readlen])
	return binary.Read(r, binary.BigEndian, data)
}

//
// Automatically generated - do not edit!
//
var FirefoxReleasePublicKeys = map[string]string{
	// From https://hg.mozilla.org/mozilla-central/raw-file/92f6879a8f9fc7e727d7c281c9fa9f538cb96cb5/toolkit/mozapps/update/updater/release_primary.der
	"release1_sha384": `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxCHbY+fP3dvaP9XVbmK6
i4rbqo72INEWgDSYbr/DIYfCSzHC9H8pU8dyjt+Nd8OtoUZtBD1N9fP7SlrvPZSI
ZSW4k0e9Ky5aV3Uy+ivamSvYszkhqdeP2y7MBu73XHKYONR9PnKa+ovmREwSEI+h
1e0ebm8zvF7Ndwx0mOeZkDu9SDkDGg4aj2xrJyBBOuGVjuctMZ6l1davANI5xiJ0
GBEU3tR1gJs1T4vLBis5mEFn9y4kgyw/HrxmRYGnZL4fLb2fTI+pNW0Twu3KWwwi
LgLkkVrNWiHSk7YWqxjcg5IA3pQETQ17paTHoB5Mnkvuh6MkDXvRG5VgAHZAigr6
fJMsasOUaBeos/cD1LDQEIObpetlxc0Fiu/lvUts0755otkhI+yv35+wUa6GJrsE
CsT7c/LaFtQXg06aGXbMLDn0bE/e+nw9KWT/rE1iYXMFkzrqoTeYJ+v7/fD/ywU8
m8l4CZmXxzd/RogMrM3xl+j4ucAAltDQyL4yLySaIT05w5U8z2zJDEXFvpFDSRfF
K3kjLwGub7wNwaQDuh/msIUdavu4g+GNikCXAJ8AssLuYatyHoltd2tf+EIIDW3U
zzLpymnLo3cAz3IPfXyqVB+mcLcpqbHjl3hWms6l1wGtz6S4WqdrWs/KfzS5EyDK
r63xn1Rg/XFmR57EsFEXAZ8CAwEAAQ==
-----END PUBLIC KEY-----`,

	// From https://hg.mozilla.org/mozilla-central/raw-file/92f6879a8f9fc7e727d7c281c9fa9f538cb96cb5/toolkit/mozapps/update/updater/release_secondary.der
	"release2_sha384": `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvki6CZE2td7jAtx/+51m
V7w+/xA16HegUXVaesBC/00jG6aAMRo7fczXolCzhMatBeTWrweXsiJ9UhwMhanj
V9uZ1Nj6ITBDtG7WB9ottf+GOpu8/V4PwwFWl4zQ5rjSvnZLGpLPY2KIN0wxArba
Aqz8XsP3WePY7RL+7mG1CX/HEXSDzWMN+OIjZTmd5Z7pkRpUIoRSlGu4bR7J9D31
xCEBnZqP4p8nCqOJZHUk0O5B93z9WprMggQ/BLW4AidAIgBLeSXmGRh4p+kVlYmb
KkMDn+/h/iuP4rhnG1+kk7thnQIGwaqa/MDqijpPtlkQTKPcbrw4MthiWgo2Ag0U
uNS2HqH1TCQMq/lslTgiEaJ1xYTE8xA9lYPS6nFzQpvmDOaaXMg7O6rdnDoCOKMi
pkb27RRlnZe8VV5OTF/e5yw6chEF7dSGfSv4HIMf6wKIWAznacmNCVDbwESrfOdG
VWWjT9Qvv92v/hnoVHdhYJ9sZKI5xVzM0bNZy25cQACFFFMMSfsutM5D8apqmOpm
OZF/aoKQeSAmE+HKAXt785x+buHjlYjqE1SmqG2GUOmvaFV8NeWvUOoeA8jtGEC+
qJ/32l7KXHVoVYje7hncEzxzR1VVURArga5PWIVnSEQoturNKNBPQ3pso6S/YmWO
V64NQxJ6oJ7swf3MkDa1enkCAwEAAQ==
-----END PUBLIC KEY-----`,

	// From https://hg.mozilla.org/mozilla-central/raw-file/58402b43c9e1e22d8a9976ee9a7e4ffeee1bbbf2/toolkit/mozapps/update/updater/release_primary.der
	"release1_sha1": `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvH4r94FpQ0gvr1hhTfV9
NUeWPJ5CN6TZRq7v/Dc4nkJ1J4IP1B3UEii34tcNKpy1nKupiZuTT6T1zQYT+z5x
3UkDF9qQboQ8RNb/BEz/cN3on/LTEnZ7YSraRL11M6cEB8mvmJxddCEquwqccRbs
Usp8WUB7uRv1w6Anley7N9F/LE1iLPwJasZypRnzWb3aYsJy0cMFOYy+OXVdpktn
qYqlNIjnt84u4Nil6UXnBbIJNUVOCY8wOFClNvVpubjPkWK1gtdWy3x/hJU5RpAO
K9cnHxq4M/I4SUWTWO3r7yweQiHG4Jyoc7sP1jkwjBkSG93sDEycfwOdOoZft3wN
sQIDAQAB
-----END PUBLIC KEY-----`,

	// From https://hg.mozilla.org/mozilla-central/raw-file/58402b43c9e1e22d8a9976ee9a7e4ffeee1bbbf2/toolkit/mozapps/update/updater/release_secondary.der
	"release2_sha1": `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq65HLYYaIvB/snHd7Oto
CFGCiV7mx6VMJb+25ZeFIQk7y5fsPDlgLG/V7a84hGVROp8C2gAHxOXXJlk0v/n6
dtruT0GxdLw4mUKB1uiPHLXV46k9ar/6QVgPRMWoJeeh3SVB2JyCtC+uqFca/N4D
VuZjnidGjqrDbQf1gr68cviZSBGzPGirIcYP4CKoNu3vB8BZWyI9NYn0+KfxVn0a
ynUKDd0zshI5FOBRAmmgKRB4tifefe41XQ7G8J62cGUlimH7Rbi1MQ3WFpkVdlh5
fciTekyH9fav66rj7erU/lcnoFJLKrf2Wpu04R0na7q5TACjJx8yYta6fbwCQU01
uwIDAQAB
-----END PUBLIC KEY-----`,

	// From https://hg.mozilla.org/mozilla-central/raw-file/92f6879a8f9fc7e727d7c281c9fa9f538cb96cb5/toolkit/mozapps/update/updater/nightly_aurora_level3_primary.der
	"nightly1_sha384": `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAth151NGY8PBzn0bii9Yc
AjYHZDwP9Lj1c3owG0zLqW2kPcdp86QTAcoYunHGYFFakNG3tooZhzwkMjZ1OrXc
ERjD6AuVSGIBdsKtKP4vLtMjDUteFN4K2+rveozcnYFZuTWEajGu8uoYsv4QgdEA
nTBC39j0J33xlfUR+XKuxzhxNrFX+fRFWuLDJrPziMcVA/mzf0gXlhtEsfV0HYyg
yWpHdIWww+llysD1QOQAHk94Ss8c/4BFXFxlwlLeNlB1ZqLm1LsNy0jUy9EHeO3C
H6eqmiFEbpdjlrkJdgR1NcTzeY/Qf/nhWH6BAZrSapQycF7OSLU+rFWMQUElSPLc
NVl7oNAAfSYLTvRjPGi+mJK3wGFQw1EpwQl+elE1oj4+sHvIVpDrLb6btpxfr1cZ
pR4Di/hkOIymxEDWvtUhOxUXnYbDKQSDcAHKM/xR3sdIAiVtVuL4hyBwlAqkQc2j
H+SmnCbazgnq5+dN4y5DjoOgbZQ/koE3s3bUzzMeIxaul9v4gMtGROw3PQ3OZcP0
lgjPRhY+NeTnWMo2nGb4/eS6Cn2qFLfbEQjsj6pJJBNKfvK/gm1jXb3PgXXdf8+d
2xTPOX8QNpSK7C0w4vYlvSpYZlsx2cznEOV6LDqP0QHUnmd/k1xWRRGiQ7gtT+BV
Fn0h7JyTGmEdFu6l4OhS8hMCAwEAAQ==
-----END PUBLIC KEY-----`,

	// From https://hg.mozilla.org/mozilla-central/raw-file/92f6879a8f9fc7e727d7c281c9fa9f538cb96cb5/toolkit/mozapps/update/updater/nightly_aurora_level3_secondary.der
	"nightly2_sha384": `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAzxgPvz/iBTM1s8pPOYpF
Vfd/B1IGoNOwhh0zezL2QZHDqYZSLG3DMLQIQr3iEGwJq2wwRnOlZm5MqPfVKpif
68iSMwcNW83xgPJLKm2D/8z4RlhM3UUcq0ZOZFARC+mi4OYNmQg8BRRoCORvDpSR
DkZSujbR+nqnYg2bmWidt3KmHEpAne8/2jqNXw34tTERmCaIDU1XD6/M8vhalRXF
9Q4iFWoynoJ88gWdVOu2cfpAsnM/xmD5Zav6RKtGJlJtnpbQUPd5euXdfveT6tsj
kXjsk50L/WbBmr30it7mLwjzxhVlJ+zNWRJMUTipdNL+y+C4QY3e6MDNkIjKXjT7
MkTCHdDeYkFveRJ23eZ3FIcxATHqrUKnVQt3i3801V6zihaL8WmEf+H92K7/pvFV
HopZewG6jBU+AvCg4g/XJEbxYsKnuauL/56vkdsvhYkDKgJunjXA9jiCmNFeeeod
EOE0Ii6f2f3+3Q1quMMz1GnI5tt9qZsFwDfI989v4viWmLfXCCcVmZFnNszUDEHb
7uzbR1dQZtcHFBghsmiEdOS2Lc8jK3EW1liFPb+qq45Xh2vyJ5iLYIJnZqX2wQjq
zQo5Nr4g/hA1Se+bzZNs3JalT0UT1gQ4M71NAIrtjI/+tfnKLb4VJ6yC7GG6PwFI
hd/nHIowE+9e2+ry/tfDpFcCAwEAAQ==
-----END PUBLIC KEY-----`,

	// From https://hg.mozilla.org/mozilla-central/raw-file/58402b43c9e1e22d8a9976ee9a7e4ffeee1bbbf2/toolkit/mozapps/update/updater/nightly_aurora_level3_primary.der
	"nightly1_sha1": `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4j/IS3gWbyVVnWn4ZRnC
Fuzb6VAaHa0I+4E504ekhVAhbKlSfBstkLbXajdjUVAJpn02zWnOaTl5KAdpDpIp
SkdA4mK20ej3/Ij7gIt8IwaX+ArXL8mP84pxDn5BgaNADm3206Z6YQzc/TDYu529
qkDFmLqNUVRJAhPO+qqhKHIcVGh8HUHXN6XV1qOFip+UU0M474jAGgurVmAv8Rh7
VvM0v5KmB6V6WHwM5gwjg2yRY/o+xYIsNeSes9rpp+MOs/RnUA6LI4WZGY4YahvX
VclIXBDgbWPYtojexIJkmYj8JIIRsh3eCsrRRe14fq7cBurp3CxBYMlDHf0RUoaq
hQIDAQAB
-----END PUBLIC KEY-----`,

	// From https://hg.mozilla.org/mozilla-central/raw-file/58402b43c9e1e22d8a9976ee9a7e4ffeee1bbbf2/toolkit/mozapps/update/updater/nightly_aurora_level3_secondary.der
	"nightly2_sha1": `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7jCVFImsVY7ILLBHsqnL
sxkXqkFvT9pnlCKITKL1DuUe1C5dl2wxnUBLngufRNcfiInPSfhl07rEcmMJxsW3
2o7GxR5rqtZfGjBXerIRY36H1igXgODs+MuDuOBVe+ZJOwgGYoQoKP7THrtk/xr6
GKZUI8T4azeOxg60LNXQ1T0kAnrLJ5wZZqT6u8yvQxiCeiCyG6Upfnazb4mgrn0M
uJkvMZOHEuJwWT8ywfaXx/CN/jVt2OF+hCd20RVe08T5V6SjTM/QBgUtlRpQv2+e
4OVz3QsK5cN8ZYWHi/9MxcAkraDI55r67ZDgwmindyPII5VGHuMph6XXhXNFAG8l
MwIDAQAB
-----END PUBLIC KEY-----`,

	// From https://hg.mozilla.org/mozilla-central/raw-file/92f6879a8f9fc7e727d7c281c9fa9f538cb96cb5/toolkit/mozapps/update/updater/dep1.der
	"dep1_sha384": `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA8Y6AS+xwKoXZl0X5qOKr
0I00xC4UN+IMjA1LIQoZ2GBkiqQF3q8v2nWTFE0+47+3NtP0l8tvsQY+LSYR4Fek
v2Vx4m/CAMKmWzW6Vtlj80y6rQ04V19l41bZXvCIBW5fm9sAvPgc7CngkcLySNqk
8vf57cUEpOmbsjSOCmK0j8hh03I1eWogpbAVEchSm1xN2sUJaVTvz5j8BfE6Vm0i
nN7V0zF+AOxzvntZIpfUqMZbHRiMkGn4l9rjia1Rz0qUc9RNCJkNocyKtQ2N2wnN
FjHpmK9x2V71cS1JQGhgLegrswPCAWY1lTmiLk9LweqGoVL0rqR4LCkb0VCaeSRe
6bUEYcU1ZQedE80zGKB3AfoC5br1shYY0xjmyRSCQ8m8WE60HzXhL8wczKrn5yoJ
iF6BxFwcYsvrWBPgIYVZLcqjODfR/M62o8yIfTC7yBcIdycJ0sWhB47dHAFxv1kc
wv8Ik9ftvDyupE8kwcl58fNOXz93j7IxMry/ey27NyYpESPOUNcjT8TP26FdGebg
4iJx0/LaYmaNUdchfBBlaYqGdH6ZGK0OeVxzHstGuG0gebm/igYcpaFxiQzvWijX
MIAU56s4g+yj7pSzT5/s9r8Gv+YhsNHKm4hnwLZaITV0lLMT5h/OZGseQTPMBnAR
hK3CIfcqG0I23hdwI29ZuUMCAwEAAQ==
-----END PUBLIC KEY-----`,

	// From https://hg.mozilla.org/mozilla-central/raw-file/92f6879a8f9fc7e727d7c281c9fa9f538cb96cb5/toolkit/mozapps/update/updater/dep2.der
	"dep2_sha384": `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAzR/PTXo4ZUIV3p2mBwOy
1qEemi4ZW84TqO0W5ws5ENuYvKGusYETvSS/WnUEzI3J7aQOzAtCIuxEsaGZTXdX
Y5/oxcepKGzfSr7T8Wegklr0WIgi0Lili0n0DYRh4Aw7OUJy73N6gBS0QM0GYB0s
cJX/Ofr6nOXSxT5KWJO5joI8a9Fr4kpQK8gj0jiXhtGbZSkaGKoVzdzz7dua/jSj
HXM6EHjAO5PzJh9LDHqM5KiCUAKRVS3mz4jty/Qt1U4+qYmb8mu/ADWtyz/VV3VG
dbffLsSTVz3NSJD5lW8QxwXhFSCP4lHxKwFYl5CjIEhKRwoWV8JG0HjgNivPBYLX
A7m9lEwFden0mXayyHjgn3gBjYBUF7hfBjRi45DrPyayz6/1ZcdQlAuVoGWmPQZ9
gf0xUFnt7JadMdG74K87sPxJSGOtcOCfst9KozGP8451VzkSoOY712GcCfxzsAwP
NveKEfAVG8ayUiRFlFvNSQ13YlRltRwf0Gto2tJcgTWGKQLapi6Z6R55WquQyiaV
UbwNIJmNldl555LFw+dSeCugbFMnE92NWeRdU1iYkGUt8H1llW7R3vt8y4h77eXF
bpjl2nk6199VyCiHf9olnC5rBqLvf+xqduC0UJ+jWgxeFvbBcRJHEF0rA2XNNZPJ
RPlEUn3O+exsA1gHlcddQY0CAwEAAQ==
-----END PUBLIC KEY-----`,

	// From https://hg.mozilla.org/mozilla-central/raw-file/58402b43c9e1e22d8a9976ee9a7e4ffeee1bbbf2/toolkit/mozapps/update/updater/dep1.der
	"dep1_sha1": `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzjHSobdeiQ3JHP/cCIOp
WaX9y12rL5mIo9OR9bpqEZdD0yXJJJeZA887Mv8slqsM+qObMUpKvfEE6zyYPIZJ
ANib31neI5BBYHhfhf2f5EnkilSYlmU3Gx+uRsmsdt58PpYe124tOAGgca/8bUy3
eb6kUUTwvMI0oWQuPkGUaoHVQyj/bBMTrIkyF3UbfFtiX/SfOPvIoabNUe+pQHUe
pqC2+RxzDGj+shTq/hYhtXlptFzsEEb2+0foLy0MY8C30dP2QqbM2iavvr/P8OcS
Gm3H0TQcRzIEBzvPcIjiZi1nQj/r/3TlYRNCjuYT/HsNLXrB/U5Tc990jjAUJxdH
0wIDAQAB
-----END PUBLIC KEY-----`,

	// From https://hg.mozilla.org/mozilla-central/raw-file/58402b43c9e1e22d8a9976ee9a7e4ffeee1bbbf2/toolkit/mozapps/update/updater/dep2.der
	"dep2_sha1": `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1WIFPTzP2Q4c5/8o1w/L
oth5BE6pc7RlqxLC5vDIIoMHyLIYw7FJsaqnYEebBKjm2ZXqV7/94ILJEc+wgwqs
1hKx7qSonAZ1IEiDpaGwvbxIP/gTXKcHX0VOnXImy7vN2r++N0aJhn46gOfZ9cys
bUjMN2R6aSvPNpl1QDFd/3DVefP/7RG9Y0Wg7Tz4U6Ip4wR4MY839dMV1ObX8zQx
ikFkUzNDBbwTp3CLCcvR40GZdkQ2XfjFNZmlhmH6iJYmRwDT4SRnAiicdnDcK+o/
alRnlvBZWbO9ZoiXbyuxXjZRRRx6vO8UTEOQTsKmXBAGZCW6z0+AAlgvPnILgOG+
jQIDAQAB
-----END PUBLIC KEY-----`,
}
