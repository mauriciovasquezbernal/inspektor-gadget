package types

import "unsafe"

type BlobEvent struct {
	// [0] is used for bpf event
	// [1] is used for static members
	// [1+] is used for variable length members
	blob       [][]byte
	lastOffset uintptr
	lastIndex  int
}

func NewBlobEvent() *BlobEvent {
	return &BlobEvent{
		lastIndex: 2,
	}
}

func (e *BlobEvent) Allocate() {
	e.blob = make([][]byte, e.lastIndex)
	e.blob[1] = make([]byte, e.lastOffset)
}

func (e *BlobEvent) AddInt32(name string) (ColumnDesc, func(ev *BlobEvent, v int32)) {
	offset := e.lastOffset

	col := ColumnDesc{
		Name: name,
		Type: Type{
			Name: "int32",
		},
		Offset: offset,
		Index:  1,
	}

	e.lastOffset += 4

	setter := func(ev *BlobEvent, v int32) {
		*(*int32)(unsafe.Pointer(&ev.blob[1][offset])) = v
	}

	return col, setter
}

func (e *BlobEvent) AddString(name string) (ColumnDesc, func(ev *BlobEvent, v string)) {
	index := e.lastIndex

	col := ColumnDesc{
		Name: name,
		Type: Type{
			Name: "string",
		},
		Index: index,
	}

	e.lastIndex++

	setter := func(ev *BlobEvent, v string) {
		e.blob[index] = []byte(v)
	}

	return col, setter
}

func (e *BlobEvent) Blob() [][]byte {
	return e.blob
}
