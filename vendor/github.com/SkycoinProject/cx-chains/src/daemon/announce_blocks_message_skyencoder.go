// Code generated by github.com/SkycoinProject/skyencoder. DO NOT EDIT.
package daemon

import "github.com/SkycoinProject/cx-chains/src/cipher/encoder"

// encodeSizeAnnounceBlocksMessage computes the size of an encoded object of type AnnounceBlocksMessage
func encodeSizeAnnounceBlocksMessage(obj *AnnounceBlocksMessage) uint64 {
	i0 := uint64(0)

	// obj.MaxBkSeq
	i0 += 8

	return i0
}

// encodeAnnounceBlocksMessage encodes an object of type AnnounceBlocksMessage to a buffer allocated to the exact size
// required to encode the object.
func encodeAnnounceBlocksMessage(obj *AnnounceBlocksMessage) ([]byte, error) {
	n := encodeSizeAnnounceBlocksMessage(obj)
	buf := make([]byte, n)

	if err := encodeAnnounceBlocksMessageToBuffer(buf, obj); err != nil {
		return nil, err
	}

	return buf, nil
}

// encodeAnnounceBlocksMessageToBuffer encodes an object of type AnnounceBlocksMessage to a []byte buffer.
// The buffer must be large enough to encode the object, otherwise an error is returned.
func encodeAnnounceBlocksMessageToBuffer(buf []byte, obj *AnnounceBlocksMessage) error {
	if uint64(len(buf)) < encodeSizeAnnounceBlocksMessage(obj) {
		return encoder.ErrBufferUnderflow
	}

	e := &encoder.Encoder{
		Buffer: buf[:],
	}

	// obj.MaxBkSeq
	e.Uint64(obj.MaxBkSeq)

	return nil
}

// decodeAnnounceBlocksMessage decodes an object of type AnnounceBlocksMessage from a buffer.
// Returns the number of bytes used from the buffer to decode the object.
// If the buffer not long enough to decode the object, returns encoder.ErrBufferUnderflow.
func decodeAnnounceBlocksMessage(buf []byte, obj *AnnounceBlocksMessage) (uint64, error) {
	d := &encoder.Decoder{
		Buffer: buf[:],
	}

	{
		// obj.MaxBkSeq
		i, err := d.Uint64()
		if err != nil {
			return 0, err
		}
		obj.MaxBkSeq = i
	}

	return uint64(len(buf) - len(d.Buffer)), nil
}

// decodeAnnounceBlocksMessageExact decodes an object of type AnnounceBlocksMessage from a buffer.
// If the buffer not long enough to decode the object, returns encoder.ErrBufferUnderflow.
// If the buffer is longer than required to decode the object, returns encoder.ErrRemainingBytes.
func decodeAnnounceBlocksMessageExact(buf []byte, obj *AnnounceBlocksMessage) error {
	if n, err := decodeAnnounceBlocksMessage(buf, obj); err != nil {
		return err
	} else if n != uint64(len(buf)) {
		return encoder.ErrRemainingBytes
	}

	return nil
}
