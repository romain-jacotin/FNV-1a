package main

import "fmt"

// To know more about the FNV-1a hash algorithm, you can visit this:
// http://www.isthe.com/chongo/tech/comp/fnv/index.html
//
// The FNV-1a hash algorithm is very easy, but Golang do not support uint128, uint256, uint512 and
// uint1024 numeric types ... :-D
//
// ------------------------------------------------------------------------------------------------
// FNV-1a algorithm for 128 bits (it is exactly the same for others hash size):
// ------------------------------------------------------------------------------------------------
// offset_basis = 144066263297769815596495629667062367629 	= 0x6C62272E07BB014262B821756295C58D
// fnv_prime =    309485009821345068724781371 				= 0x0000000001000000000000000000013B
//
// hash = offset_basis
// for each octet_of_data to be hashed
//   hash = hash xor octet_of_data
//   hash = hash * fnv_prime
// ------------------------------------------------------------------------------------------------
// IMPORTANT NOTE: FNV1a hash binary exchange between hosts/programs MUST be in little endian !!!
// ------------------------------------------------------------------------------------------------
//
// Now come the Golang implementation that is using multiple uint64 to simulate big numbers
// "multiplication" and "xor" operations (128, 256, 512 and 1024 bits). The trick is that you need
// to propagate carries between the multiple uint64 variables that simulate a big unsigned int ;-)

func FNV1a_32(inputdata *[]byte) [4]byte {
	var val uint32 = 2166136261 // offset_basis = 2166136261
	var hash [4]byte            // Little Endian Hash value
	var i uint

	for _, v := range *inputdata {
		// xor the bottom with the current octet
		val ^= uint32(v)
		// multiply by the 32 bit FNV magic prime mod 2^32
		// fnv_prime = 224 + 28 + 0x93 = 16777619
		val *= 16777619
	}

	// Writing in Little Endian mode the 32 bits hash value (=4 bytes)
	for ; i < 4; i++ {
		hash[i] = byte(val >> (i * 8))
	}
	return hash
	// Some FNV-1a 32 bits test vectors in Big Endian:
	//
	//   "hello world!goodbye!"	--> 113baa28
	//
	//   "I am a gopher!" 		--> 7b0b53e9
	//
	// Others FNV test vectors from various sizes (32,64,128,256,512 or 1024 bits)
	// can be created here: http://find.fnvhash.com/
}

func FNV1a_64(inputdata *[]byte) [8]byte {
	var val uint64 = 14695981039346656037 // offset_basis = 14695981039346656037
	var hash [8]byte                      // Little Endian Hash value
	var i uint

	for _, v := range *inputdata {
		// xor the bottom with the current octet
		val ^= uint64(v)

		// multiply by the 64 bit FNV magic prime mod 2^64
		// fnv_prime = 1099511628211
		val *= 1099511628211
	}

	// Writing in Little Endian mode the 64 bits hash value (=8 bytes)
	for ; i < 8; i++ {
		hash[i] = byte(val >> (i * 8))
	}
	return hash
	// Some FNV-1a 64 bits test vectors in Big Endian:
	//
	//   "hello world!goodbye!"	--> 50015c195ee3d588
	//
	//   "I am a gopher!" 		--> 9fb4685c5284a9a9
	//
	// Others FNV test vectors from various sizes (32,64,128,256,512 or 1024 bits)
	// can be created here: http://find.fnvhash.com/
}

func FNV1a_128(inputdata *[]byte) [16]byte {
	// offset_basis = 144066263297769815596495629667062367629
	// 				= 0x6C62272E 07BB0142 62B82175 6295C58D
	// Convert offset_basis into a base 2^32 array
	var val = [4]uint64{0x6295C58D, 0x62B82175, 0x07BB0142, 0x6C62272E}
	var tmp [4]uint64 // tmp 128 bit value
	var hash [16]byte // Little Endian Hash value

	const FNV_128_PRIME_LOW = 0x0000013B
	const FNV_128_PRIME_SHIFT = 24

	for _, v := range *inputdata {
		// xor the bottom with the current octet
		val[0] ^= uint64(v)

		// multiply by the 128 bit FNV magic prime mod 2^128
		// fnv_prime	= 309485009821345068724781371 (decimal)
		// 				= 0x0000000001000000000000000000013B (hexadecimal)
		// 				= 0x00000000 	0x01000000 				0x00000000	0x0000013B (in 4*32 words)
		//				= 0x0			1<<FNV_128_PRIME_SHIFT	0x0			FNV_128_PRIME_LOW
		//
		// FNV_128_PRIME_LOW = 0x0000013B
		// FNV_128_PRIME_SHIFT = 24

		// multiply by the lowest order digit base 2^32 and by the other non-zero digit
		tmp[0] = val[0] * FNV_128_PRIME_LOW
		tmp[1] = val[1] * FNV_128_PRIME_LOW
		tmp[2] = val[2]*FNV_128_PRIME_LOW + val[0]<<FNV_128_PRIME_SHIFT
		tmp[3] = val[3]*FNV_128_PRIME_LOW + val[1]<<FNV_128_PRIME_SHIFT

		// propagate carries
		tmp[1] += (tmp[0] >> 32)
		tmp[2] += (tmp[1] >> 32)
		tmp[3] += (tmp[2] >> 32)

		val[0] = tmp[0] & 0xffffffff
		val[1] = tmp[1] & 0xffffffff
		val[2] = tmp[2] & 0xffffffff
		val[3] = tmp[3] // & 0xffffffff
		// Doing a val[3] &= 0xffffffff is not really needed since it simply
		// removes multiples of 2^128.  We can discard these excess bits
		// outside of the loop when writing the hash in Little Endian.
	}

	// Writing in Little Endian mode the 128 bits hash value (=16 bytes)
	for i := 0; i < 16; i += 4 {
		hash[i] = byte(val[i>>2])
		hash[i+1] = byte(val[i>>2] >> 8)
		hash[i+2] = byte(val[i>>2] >> 16)
		hash[i+3] = byte(val[i>>2] >> 24)
	}
	return hash
	// Some FNV-1a 128 bits test vectors in Big Endian:
	//
	//   "hello world!goodbye!"	--> aebb096b13b291473b18f8448a446fa0
	//
	//   "I am a gopher!" 		--> 2b178bc6a6071ec752fa46a01e21fb29
	//
	// Others FNV test vectors from various sizes (32,64,128,256,512 or 1024 bits)
	// can be created here: http://find.fnvhash.com/
}

func FNV1a_256(inputdata *[]byte) [32]byte {
	// offset_basis = 100029257958052580907070968620625704837092796014241193945225284501741471925557
	// 				= 0xDD268DBC AAC55036 2D98C384 C4E576CC C8B15368 47B6BBB3 1023B4C8 CAEE0535
	// Convert offset_basis into a base 2^32 array
	var val = [8]uint64{0xCAEE0535, 0x1023B4C8, 0x47B6BBB3, 0xC8B15368,
		0xC4E576CC, 0x2D98C384, 0xAAC55036, 0xDD268DBC}
	var tmp [8]uint64 // tmp 256 bit value
	var hash [32]byte // Little Endian Hash value

	const FNV_256_PRIME_LOW = 0x00000163
	const FNV_256_PRIME_SHIFT = 8

	for _, v := range *inputdata {
		// xor the bottom with the current octet
		val[0] ^= uint64(v)
		// multiply by the lowest order digit base 2^32 and by the other non-zero digit
		// fnv_prime 	= 374144419156711147060143317175368453031918731002211 (decimal)
		//           	= 0x00000000 00000000 00000100 00000000 00000000 00000000 00000000 00000163 (in 8*32 words)
		//				= 0x0 0x0 1<<FNV_256_PRIME_SHIFT 0x0 0x0 0x0 0x0 FNV_256_PRIME_LOW
		for i := 0; i < 5; i++ {
			tmp[i] = val[i] * FNV_256_PRIME_LOW
		}
		for i := 5; i < 8; i++ {
			tmp[i] = val[i]*FNV_256_PRIME_LOW + val[i-5]<<FNV_256_PRIME_SHIFT
		}

		// propagate carries
		for i := 1; i < 8; i++ {
			tmp[i] += (tmp[i-1] >> 32)
		}
		for i := 0; i < 8; i++ {
			val[i] = tmp[i] & 0xffffffff
		}
	}

	// Writing in Little Endian mode the 256 bits hash value (=32 bytes)
	for i := 0; i < 32; i += 4 {
		hash[i] = byte(val[i>>2])
		hash[i+1] = byte(val[i>>2] >> 8)
		hash[i+2] = byte(val[i>>2] >> 16)
		hash[i+3] = byte(val[i>>2] >> 24)
	}
	return hash
	// Some FNV-1a 256 bits test vectors in Big Endian:
	//
	//   "hello world!goodbye!"	--> a3846d0515e77985b8e15916d15c1ffd2ead3cf20a78e15a4ab0c023728fc0f8
	//
	//   "I am a gopher!" 		--> fc677e8e771c54ff23ae33c9fd2f06c84705a4bedbb9b6c7cdb2950cedaec1e9
	//
	// Others FNV test vectors from various sizes (32,64,128,256,512 or 1024 bits)
	// can be created here: http://find.fnvhash.com/
}

func FNV1a_512(inputdata *[]byte) [64]byte {
	// offset_basis = 9659303129496669498009435400716310466090418745672637896108374329434462657994582932197716438449813051892206539805784495328239340083876191928701583869517785 (decimal)
	// 				= 0xB86DB0B1 171F4416 DCA1E50F 309990AC AC87D059 C9000000 00000000 00000D21
	// 				    E948F68A 34C192F6 2EA79BC9 42DBE7CE 18203641 5F56E34B AC982AAC 4AFE9FD9
	// Convert offset_basis into a base 2^32 array
	var val = [16]uint64{0x4AFE9FD9, 0xAC982AAC, 0x5F56E34B, 0x18203641,
		0x42DBE7CE, 0x2EA79BC9, 0x34C192F6, 0xE948F68A,
		0x00000D21, 0x00000000, 0xC9000000, 0xAC87D059,
		0x309990AC, 0xDCA1E50F, 0x171F4416, 0xB86DB0B1}
	var tmp [16]uint64 // tmp 512 bit value
	var hash [64]byte  // Little Endian Hash value

	const FNV_512_PRIME_LOW = 0x0000000000000157
	const FNV_512_PRIME_SHIFT = 24

	for _, v := range *inputdata {
		// xor the bottom hash with the current octet
		val[0] ^= uint64(v)

		// multiply by the lowest order digit base 2^32 and by the other non-zero digit
		// fnv_prime 	= 35835915874844867368919076489095108449946327955754392558399825615420669938882575126094039892345713852759 (decimal)
		//           	= 0x00000000 00000000 00000000 00000000 00000000 01000000 00000000 00000000
		// 			      00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000157 (in 16*32 words)
		//				= 0x0 0x0 0x0 0x0 0x0 1<<FNV_512_PRIME_SHIFT 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 FNV_512_PRIME_LOW
		for i := 0; i < 10; i++ {
			tmp[i] = val[i] * FNV_512_PRIME_LOW
		}
		for i := 10; i < 16; i++ {
			tmp[i] = val[i]*FNV_512_PRIME_LOW + val[i-10]<<FNV_512_PRIME_SHIFT
		}

		// propagate carries
		for i := 1; i < 16; i++ {
			tmp[i] += (tmp[i-1] >> 32)
		}
		for i := 0; i < 16; i++ {
			val[i] = tmp[i] & 0xffffffff
		}
	}

	// Writing in Little Endian mode the 512 bits hash value (=64 bytes)
	for i := 0; i < 64; i += 4 {
		hash[i] = byte(val[i>>2])
		hash[i+1] = byte(val[i>>2] >> 8)
		hash[i+2] = byte(val[i>>2] >> 16)
		hash[i+3] = byte(val[i>>2] >> 24)
	}
	return hash
	// Some FNV-1a 512 bits test vectors in Big Endian:
	//
	//   "hello world!goodbye!"	--> c80e61d5ce3ae0d34e0b0f185f8a7415ef835a36b01988b4d6e4efc77313664f
	// 								3729c4451f1a07bd424528a7e61e7c1d4ae33c3c8cc14732f25f367983920b84
	//
	//   "I am a gopher!" 		-->	da97ee2f631f3dde7d55d98e724023423b4baa8aea15371cfa15ca2f33fc042c
	// 								8f61f8cfa1b2b3b79939f7347fce32311e7e2da79a5dca99ea495284cd738669
	//
	// Others FNV test vectors from various sizes (32,64,128,256,512 or 1024 bits)
	// can be created here: http://find.fnvhash.com/
}

func FNV1a_1024(inputdata *[]byte) [128]byte {
	// offset_basis = 14197795064947621068722070641403218320880622795441933960878474914617582723252296
	// 				  73230371772215086409652120235554936562817466910857181476047101507614802975596980
	// 				  40773201576924585630032153049571501574036444603635505054127112859663616102678680
	// 				  82893823963790439336411086884584107735010676915 (decimal)
	// 				= 0x00000000 00000000 005F7A76 758ECC4D 32E56D5A 591028B7 4B29FC42 23FDADA1
	//					6C3BF34E DA3674DA 9A21D900 00000000 00000000 00000000 00000000 00000000
	// 					00000000 00000000 00000000 00000000 00000000 00000000 00000000 0004C6D7
	// 					EB6E7380 2734510A 555F256C C005AE55 6BDE8CC9 C6A93B21 AFF4B16C 71EE90B3
	// Convert offset_basis into a base 2^32 array
	var val = [32]uint64{0x71EE90B3, 0xAFF4B16C, 0xC6A93B21, 0x6BDE8CC9,
		0xC005AE55, 0x555F256C, 0x2734510A, 0xEB6E7380,
		0x0004C6D7, 0x00000000, 0x00000000, 0x00000000,
		0x00000000, 0x00000000, 0x00000000, 0x00000000,
		0x00000000, 0x00000000, 0x00000000, 0x00000000,
		0x00000000, 0x9A21D900, 0xDA3674DA, 0x6C3BF34E,
		0x23FDADA1, 0x4B29FC42, 0x591028B7, 0x32E56D5A,
		0x758ECC4D, 0x005F7A76, 0x00000000, 0x00000000}
	var tmp [32]uint64 // tmp 1024 bit value
	var hash [128]byte // Little Endian Hash value

	const FNV_1024_PRIME_LOW = 0x0000018D
	const FNV_1024_PRIME_SHIFT = 8

	for _, v := range *inputdata {
		// xor the bottom hash with the current octet
		val[0] ^= uint64(v)

		// multiply by the lowest order digit base 2^32 and by the other non-zero digit
		// fnv_prime 	= 50164565101131186554345988110352789550307653454047907443030175238311120551081474
		// 				  51509157692220295382716162651878526895249385292291816524375083746691371804094271
		// 				  873160484737966720260389217684476157468082573 (decimal)
		//           	= 0x00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
		// 					00000000 00000000 00000100 00000000 00000000 00000000 00000000 00000000
		// 					00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
		// 					00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000018D (in 32*32 words)
		//				= 	0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0
		// 					0x0 0x0 1<<FNV_1024_PRIME_SHIFT 0x0 0x0 0x0 0x0 0x0
		// 					0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0
		//					0x0 0x0 0x0 0x0 0x0 0x0 0x0 FNV_1024_PRIME_LOW
		for i := 0; i < 21; i++ {
			tmp[i] = val[i] * FNV_1024_PRIME_LOW
		}
		for i := 21; i < 32; i++ {
			tmp[i] = val[i]*FNV_1024_PRIME_LOW + val[i-21]<<FNV_1024_PRIME_SHIFT
		}

		// propagate carries
		for i := 1; i < 32; i++ {
			tmp[i] += (tmp[i-1] >> 32)
		}
		for i := 0; i < 32; i++ {
			val[i] = tmp[i] & 0xffffffff
		}
	}

	// Writing in Little Endian mode the 1024 bits hash value (=128 bytes)
	for i := 0; i < 128; i += 4 {
		hash[i] = byte(val[i>>2])
		hash[i+1] = byte(val[i>>2] >> 8)
		hash[i+2] = byte(val[i>>2] >> 16)
		hash[i+3] = byte(val[i>>2] >> 24)
	}
	return hash
	// Here some FNV-1a 1024 bits test vectors in Big Endian:
	//
	//   "hello world!goodbye!"	--> b897b5105c6e6e597783b1cee11c5a1efe09d71e8277697a9f0cdef458b193f2
	// 								4fbd9a715d5667f5d7c891000000000000000000000000000000000000000000
	// 								000000000000000078c10a52e7afdaf167e608756cd3d3145361343de4d43872
	// 								c6d1c526c07e9b4250b8cae0a961eebbcb5073c67bdb76f6f4d2b60ba30564ce
	//
	//   "I am a gopher!" 		-->	85f2d26936ded8f66cc5835aed0b37dc11e51448a21279a31fded0a051fe5508
	// 								e8a3928f03df0faedddf72000000000000000000000000000000000000000000
	// 								000000000000000000000000000008ae7badf407f5732a48d3f14e1ba8722279
	// 								5202b88ad18d7790957105101fe5b99dff40def61e106358cea348f2d6a64da5
	//
	// Others FNV test vectors from various sizes (32,64,128,256,512 or 1024 bits)
	// can be created here: http://find.fnvhash.com/
}

func main() {
	data1 := []byte{'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '!', 'g', 'o', 'o', 'd', 'b', 'y', 'e', '!'}
	data2 := []byte{'I', ' ', 'a', 'm', ' ', 'a', ' ', 'g', 'o', 'p', 'h', 'e', 'r', '!'}

	fmt.Printf("\ndata[%v bytes] = \"hello world!goodbye!\"\n\n", len(data1))
	fmt.Printf("FNV1a_32   = %x\n\n", FNV1a_32(&data1))
	fmt.Printf("FNV1a_64   = %x\n\n", FNV1a_64(&data1))
	fmt.Printf("FNV1a_128  = %x\n\n", FNV1a_128(&data1))
	fmt.Printf("FNV1a_256  = %x\n\n", FNV1a_256(&data1))
	fmt.Printf("FNV1a_512  = %x\n\n", FNV1a_512(&data1))
	fmt.Printf("FNV1a_1024 = %x\n\n", FNV1a_1024(&data1))

	fmt.Printf("data[%v bytes] = \"I am a gopher!\"\n\n", len(data2))
	fmt.Printf("FNV1a_32   = %x\n\n", FNV1a_32(&data2))
	fmt.Printf("FNV1a_64   = %x\n\n", FNV1a_64(&data2))
	fmt.Printf("FNV1a_128  = %x\n\n", FNV1a_128(&data2))
	fmt.Printf("FNV1a_256  = %x\n\n", FNV1a_256(&data2))
	fmt.Printf("FNV1a_512  = %x\n\n", FNV1a_512(&data2))
	fmt.Printf("FNV1a_1024 = %x\n\n", FNV1a_1024(&data2))
}
