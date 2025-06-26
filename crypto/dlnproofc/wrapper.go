package dlnproofc

/*
#cgo CFLAGS: -I.
#cgo LDFLAGS: -lgmp
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "proof.h"
*/
import "C"
import (
	"errors"
	"unsafe"
)

const (
	ITERATIONS = 128
)

// convert Go byte slice to C pointer
func cBytes(buf []byte) (*C.uint8_t, C.size_t) {
	if len(buf) == 0 {
		return nil, 0
	}
	return (*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(len(buf))
}

// convert slice of byte slices to **C.uint8_t with proper C memory allocation
func c2DBytes(data [][]byte) (**C.uint8_t, []*C.uint8_t, error) {
	if len(data) == 0 {
		return nil, nil, errors.New("input data is empty")
	}

	// Allocate C memory for the pointer array to avoid Go pointer to Go pointer
	ptrArrayC := (**C.uint8_t)(C.malloc(C.size_t(len(data)) * C.size_t(unsafe.Sizeof(uintptr(0)))))
	if ptrArrayC == nil {
		return nil, nil, errors.New("failed to allocate C memory for pointer array")
	}

	// Keep track of individual pointers for cleanup
	ptrArray := make([]*C.uint8_t, len(data))
	ptrArraySlice := (*[1 << 30]*C.uint8_t)(unsafe.Pointer(ptrArrayC))[:len(data):len(data)]

	for i := range data {
		if len(data[i]) == 0 {
			// Clean up previously allocated memory
			for j := 0; j < i; j++ {
				C.free(unsafe.Pointer(ptrArray[j]))
			}
			C.free(unsafe.Pointer(ptrArrayC))
			return nil, nil, errors.New("input sub-slice is empty")
		}
		// Allocate C memory and copy data
		ptrArray[i] = (*C.uint8_t)(C.malloc(C.size_t(len(data[i]))))
		if ptrArray[i] == nil {
			// Clean up previously allocated memory
			for j := 0; j < i; j++ {
				C.free(unsafe.Pointer(ptrArray[j]))
			}
			C.free(unsafe.Pointer(ptrArrayC))
			return nil, nil, errors.New("C memory allocation failed")
		}
		C.memcpy(unsafe.Pointer(ptrArray[i]), unsafe.Pointer(&data[i][0]), C.size_t(len(data[i])))
		ptrArraySlice[i] = ptrArray[i]
	}
	return ptrArrayC, ptrArray, nil
}

// Free C-allocated memory for 2D arrays
func freeCPtrArray(ptrs []*C.uint8_t) {
	for _, ptr := range ptrs {
		if ptr != nil {
			C.free(unsafe.Pointer(ptr))
		}
	}
}

// DLNVerify verifies the DLN proof
func DLNVerify(
	h1, h2, N []byte,
	alphaList, tList [][]byte,
	hash []byte,
) (bool, error) {
	if len(alphaList) != ITERATIONS || len(tList) != ITERATIONS {
		return false, errors.New("alpha/t list must have 128 elements")
	}

	if len(hash) == 0 {
		return false, errors.New("hash cannot be empty")
	}

	// Validate that all alpha and t elements have the same length
	if len(alphaList) > 0 && len(tList) > 0 {
		expectedLen := len(alphaList[0])
		for i, alpha := range alphaList {
			if len(alpha) != expectedLen {
				return false, errors.New("all alpha elements must have the same length")
			}
			if len(tList[i]) != expectedLen {
				return false, errors.New("all t elements must have the same length")
			}
		}
	}

	h1Ptr, h1Len := cBytes(h1)
	h2Ptr, h2Len := cBytes(h2)
	nPtr, nLen := cBytes(N)

	alphaPtrs, alphaCPtrs, err := c2DBytes(alphaList)
	if err != nil {
		return false, err
	}
	defer func() {
		freeCPtrArray(alphaCPtrs)
		C.free(unsafe.Pointer(alphaPtrs))
	}()

	tPtrs, tCPtrs, err := c2DBytes(tList)
	if err != nil {
		return false, err
	}
	defer func() {
		freeCPtrArray(tCPtrs)
		C.free(unsafe.Pointer(tPtrs))
	}()

	hashPtr := (*C.uint8_t)(unsafe.Pointer(&hash[0]))

	res := C.dln_verify(
		h1Ptr, h1Len,
		h2Ptr, h2Len,
		nPtr, nLen,
		alphaPtrs,
		tPtrs,
		C.size_t(len(alphaList[0])),
		hashPtr,
	)

	return res == 1, nil
}

// DLNProve generates a DLN proof
func DLNProve(
	h1, x, p, q, N []byte,
	hash []byte,
	outLen int,
) ([][]byte, [][]byte, error) {
	if outLen <= 0 {
		return nil, nil, errors.New("outLen must be positive")
	}

	if len(hash) == 0 {
		return nil, nil, errors.New("hash cannot be empty")
	}

	// Validate input parameters
	if len(h1) == 0 || len(x) == 0 || len(p) == 0 || len(q) == 0 || len(N) == 0 {
		return nil, nil, errors.New("input parameters cannot be empty")
	}

	alphaOut := make([][]byte, ITERATIONS)
	tOut := make([][]byte, ITERATIONS)

	// Allocate C memory for pointer arrays to avoid Go pointer to Go pointer issue
	alphaPtrsC := (**C.uint8_t)(C.malloc(C.size_t(ITERATIONS) * C.size_t(unsafe.Sizeof(uintptr(0)))))
	if alphaPtrsC == nil {
		return nil, nil, errors.New("failed to allocate C memory for alpha pointers")
	}
	defer C.free(unsafe.Pointer(alphaPtrsC))

	tPtrsC := (**C.uint8_t)(C.malloc(C.size_t(ITERATIONS) * C.size_t(unsafe.Sizeof(uintptr(0)))))
	if tPtrsC == nil {
		return nil, nil, errors.New("failed to allocate C memory for t pointers")
	}
	defer C.free(unsafe.Pointer(tPtrsC))

	// Create pointer arrays in C memory, allocate each output buffer in C
	alphaPtrsSlice := (*[ITERATIONS]*C.uint8_t)(unsafe.Pointer(alphaPtrsC))
	tPtrsSlice := (*[ITERATIONS]*C.uint8_t)(unsafe.Pointer(tPtrsC))

	for i := 0; i < ITERATIONS; i++ {
		alphaPtrsSlice[i] = (*C.uint8_t)(C.malloc(C.size_t(outLen)))
		if alphaPtrsSlice[i] == nil {
			for j := 0; j < i; j++ {
				C.free(unsafe.Pointer(alphaPtrsSlice[j]))
			}
			return nil, nil, errors.New("failed to allocate C memory for alphaOut element")
		}
		tPtrsSlice[i] = (*C.uint8_t)(C.malloc(C.size_t(outLen)))
		if tPtrsSlice[i] == nil {
			for j := 0; j <= i; j++ {
				C.free(unsafe.Pointer(alphaPtrsSlice[j]))
			}
			for j := 0; j < i; j++ {
				C.free(unsafe.Pointer(tPtrsSlice[j]))
			}
			return nil, nil, errors.New("failed to allocate C memory for tOut element")
		}
	}
	defer func() {
		for i := 0; i < ITERATIONS; i++ {
			C.free(unsafe.Pointer(alphaPtrsSlice[i]))
			C.free(unsafe.Pointer(tPtrsSlice[i]))
		}
	}()

	h1Ptr, h1Len := cBytes(h1)
	xPtr, xLen := cBytes(x)
	pPtr, pLen := cBytes(p)
	qPtr, qLen := cBytes(q)
	nPtr, nLen := cBytes(N)
	hashPtr := (*C.uint8_t)(unsafe.Pointer(&hash[0]))

	success := C.dln_prove(
		h1Ptr, h1Len,
		xPtr, xLen,
		pPtr, pLen,
		qPtr, qLen,
		nPtr, nLen,
		hashPtr,
		alphaPtrsC,
		tPtrsC,
		C.size_t(outLen),
	)

	if success != 1 {
		return nil, nil, errors.New("dln_prove failed")
	}

	// Copy data from C memory to Go slices
	for i := 0; i < ITERATIONS; i++ {
		alphaOut[i] = goBytes(unsafe.Pointer(alphaPtrsSlice[i]), outLen)
		tOut[i] = goBytes(unsafe.Pointer(tPtrsSlice[i]), outLen)
	}

	return alphaOut, tOut, nil
}

func goBytes(ptr unsafe.Pointer, length int) []byte {
	if ptr == nil || length == 0 {
		return nil
	}
	b := make([]byte, length)
	copy(b, (*[1 << 30]byte)(ptr)[:length:length])
	return b
}
