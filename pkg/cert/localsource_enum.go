// Code generated by go-enum DO NOT EDIT.
// Version:
// Revision:
// Build Date:
// Built By:

package cert

import (
	"fmt"
	"strings"
)

const (
	// FileTypePem is a FileType of type Pem.
	FileTypePem FileType = iota
	// FileTypeDer is a FileType of type Der.
	FileTypeDer
)

const _FileTypeName = "pemder"

var _FileTypeMap = map[FileType]string{
	FileTypePem: _FileTypeName[0:3],
	FileTypeDer: _FileTypeName[3:6],
}

// String implements the Stringer interface.
func (x FileType) String() string {
	if str, ok := _FileTypeMap[x]; ok {
		return str
	}
	return fmt.Sprintf("FileType(%d)", x)
}

var _FileTypeValue = map[string]FileType{
	_FileTypeName[0:3]:                  FileTypePem,
	strings.ToLower(_FileTypeName[0:3]): FileTypePem,
	_FileTypeName[3:6]:                  FileTypeDer,
	strings.ToLower(_FileTypeName[3:6]): FileTypeDer,
}

// ParseFileType attempts to convert a string to a FileType.
func ParseFileType(name string) (FileType, error) {
	if x, ok := _FileTypeValue[name]; ok {
		return x, nil
	}
	// Case insensitive parse, do a separate lookup to prevent unnecessary cost of lowercasing a string if we don't need to.
	if x, ok := _FileTypeValue[strings.ToLower(name)]; ok {
		return x, nil
	}
	return FileType(0), fmt.Errorf("%s is not a valid FileType", name)
}

// MarshalText implements the text marshaller method.
func (x FileType) MarshalText() ([]byte, error) {
	return []byte(x.String()), nil
}

// UnmarshalText implements the text unmarshaller method.
func (x *FileType) UnmarshalText(text []byte) error {
	name := string(text)
	tmp, err := ParseFileType(name)
	if err != nil {
		return err
	}
	*x = tmp
	return nil
}