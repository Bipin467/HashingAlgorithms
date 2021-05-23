#include "../public/BitManipulation.h"

union forendian {
	uint16_t bit_16;
	uint8_t bit_8[2];
};

forendian x = {0x0001 };

inline uint32_t ROTL32(uint32_t val, uint8_t rotationBit) {
	return val << rotationBit | val >> (32 - rotationBit);
}


inline uint32_t ROTR32(uint32_t val, uint8_t rotationBit) {
	return val >> rotationBit | val << (32 - rotationBit);
}


inline uint64_t ROTL64(uint64_t val, uint8_t rotationBit) {
	return val << rotationBit | val >> (64 - rotationBit);
}


inline uint64_t ROTR64(uint64_t val, uint8_t rotationBit) {
	return val >> rotationBit | val << (64 - rotationBit);
}

inline bool IsBigEndian() {
	return x.bit_8[1];
}


inline uint32_t SwapEndianess32(uint32_t val) {
	return (val >> 24) | ((val >> 8) & 0x0000ff00) | ((val << 8) & 0x00ff0000) | (val << 24);
}


inline uint64_t SwapEndianess64(uint64_t val) {
	return (val >> 56) | ((val >> 40) & 0x000000000000ff00) | ((val >> 24) & 0x0000000000ff0000) | ((val >> 8) & 0x00000000ff000000) | ((val << 8) & 0x000000ff00000000) | ((val << 24) & 0x0000ff0000000000) | ((val << 40) & 0x00ff000000000000) | (val << 56);
}