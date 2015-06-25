package lea

import "fmt"

const (
	ENCRYPT_MODE = iota
	DECRYPT_MODE
)

// LEA uses a 128-bit block
type word uint32

func (w word) String() string {
	return fmt.Sprintf("%08x", uint32(w))
}

// converts a byte array [B1 B2 B3 B4] to a word B4B3B2B1
func ba2w(ba [4]byte) word {
	return word(uint32(ba[3])<<24 |
		uint32(ba[2])<<16 |
		uint32(ba[1])<<8 |
		uint32(ba[0]))
}

// converts a word B1B2B3B4 to a byte array [B4 B3 B2 B1]
func w2ba(w word) (ba [4]byte) {
	ba[0] = byte(w)
	ba[1] = byte(w >> 8)
	ba[2] = byte(w >> 16)
	ba[3] = byte(w >> 24)
	return
}

// 2 circular shift functions below
// [be careful] # of shift could be larger than 32

// circular left shift
func rol(w word, r uint) word {
	return (w << (r % 32)) | (w >> (32 - (r % 32)))
}

// circular right shift
func ror(w word, r uint) word {
	return (w >> (r % 32)) | (w << (32 - (r % 32)))
}

// returns round keys for encryption or decryption
// param K is a key (128-bit, 192-bit, or 256-bit)
// # of rows of return value (RK) will be different by the given key size
// mode: ENCRYPT_MODE or DECRYPT_MODE
func RoundKey(K []byte, mode int) (RK [][6]word) {
	delta := [8]word{0xc3efe9db, 0x44626b02, 0x79e27c8a, 0x78df30ec, 0x715ea49e, 0xc785da0a, 0xe04ef22a, 0xe5c40957}
	var Nr uint
	switch len(K) {
	case 16:
		Nr = 24
	case 24:
		Nr = 28
	case 32:
		Nr = 32
	}
	T := make([]word, len(K)/4)
	RK = make([][6]word, Nr)
	for i := 0; i < len(K)/4; i++ {
		var buf [4]byte
		copy(buf[:], K[i*4:(i+1)*4])
		T[i] = ba2w(buf)
	}
	for i := uint(0); i < Nr; i++ {
		var rki uint
		// procedures for generating round keys for encryption and decryption are the same
		// when decrypting mode, save them in reverse
		switch mode {
		case ENCRYPT_MODE:
			rki = i
		case DECRYPT_MODE:
			rki = Nr - i - 1
		}
		switch len(K) {
		case 16:
			T[0] = rol(T[0]+rol(delta[i%4], i), 1)
			T[1] = rol(T[1]+rol(delta[i%4], i+1), 3)
			T[2] = rol(T[2]+rol(delta[i%4], i+2), 6)
			T[3] = rol(T[3]+rol(delta[i%4], i+3), 11)
			RK[rki] = [6]word{T[0], T[1], T[2], T[1], T[3], T[1]}
		case 24:
			T[0] = rol(T[0]+rol(delta[i%6], i), 1)
			T[1] = rol(T[1]+rol(delta[i%6], i+1), 3)
			T[2] = rol(T[2]+rol(delta[i%6], i+2), 6)
			T[3] = rol(T[3]+rol(delta[i%6], i+3), 11)
			T[4] = rol(T[4]+rol(delta[i%6], i+4), 13)
			T[5] = rol(T[5]+rol(delta[i%6], i+5), 17)
			RK[rki] = [6]word{T[0], T[1], T[2], T[3], T[4], T[5]}
		case 32:
			T[(6*i)%8] = rol(T[(6*i)%8]+rol(delta[i%8], i), 1)
			T[(6*i+1)%8] = rol(T[(6*i+1)%8]+rol(delta[i%8], i+1), 3)
			T[(6*i+2)%8] = rol(T[(6*i+2)%8]+rol(delta[i%8], i+2), 6)
			T[(6*i+3)%8] = rol(T[(6*i+3)%8]+rol(delta[i%8], i+3), 11)
			T[(6*i+4)%8] = rol(T[(6*i+4)%8]+rol(delta[i%8], i+4), 13)
			T[(6*i+5)%8] = rol(T[(6*i+5)%8]+rol(delta[i%8], i+5), 17)
			RK[rki] = [6]word{T[(6*i)%8], T[(6*i+1)%8], T[(6*i+2)%8], T[(6*i+3)%8], T[(6*i+4)%8], T[(6*i+5)%8]}
		}
	}
	return
}

// one round for encryption
func EncRound(x [4]word, rk [6]word) (t [4]word) {
	t[0] = rol((x[0]^rk[0])+(x[1]^rk[1]), 9)
	t[1] = ror((x[1]^rk[2])+(x[2]^rk[3]), 5)
	t[2] = ror((x[2]^rk[4])+(x[3]^rk[5]), 3)
	t[3] = x[0]
	return
}

// one round for decryption
func DecRound(x [4]word, rk [6]word) (t [4]word) {
	t[0] = x[3]
	t[1] = (ror(x[0], 9) - (t[0] ^ rk[0])) ^ rk[1]
	t[2] = (rol(x[1], 5) - (t[1] ^ rk[2])) ^ rk[3]
	t[3] = (rol(x[2], 3) - (t[2] ^ rk[4])) ^ rk[5]
	return
}

// helper function for encryption and decryption
// LEA uses 4 words (4 bytes * 4 = 16 bytes = 128 bits) for encryption or decryption
// 1. breaks the given 16 bytes into 4 words
// 2. encrypts or decrypts them
// 3. reconstructs 4 words to 16 bytes
func encdec(from [16]byte, RK [][6]word, mode int) (to [16]byte) {
	var X [4]word
	for i := 0; i < 4; i++ {
		var buf [4]byte
		copy(buf[:], from[i*4:(i+1)*4])
		X[i] = ba2w(buf)
	}
	Nr := len(RK)
	for i := 0; i < Nr; i++ {
		switch mode {
		case ENCRYPT_MODE:
			X = EncRound(X, RK[i])
		case DECRYPT_MODE:
			X = DecRound(X, RK[i])
		}
	}
	for i := 0; i < 4; i++ {
		buf := w2ba(X[i])
		copy(to[i*4:(i+1)*4], buf[:])
	}
	return
}

func Encrypt(P [16]byte, RK [][6]word) [16]byte {
	return encdec(P, RK, ENCRYPT_MODE)
}

func Decrypt(C [16]byte, RK [][6]word) [16]byte {
	return encdec(C, RK, DECRYPT_MODE)
}
