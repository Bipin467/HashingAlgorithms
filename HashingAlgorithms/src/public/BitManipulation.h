#pragma once
#include <stdint.h>
extern inline uint32_t ROTR32(uint32_t val, uint8_t rotationBit);    //Rotate 32 bit integer right by rotationBIt Value
extern inline uint32_t ROTL32(uint32_t val, uint8_t rotationBit);    //Rotate 32bit integer left by rotationBit Value
extern inline uint64_t ROTR64(uint64_t val, uint8_t rotationBit);    //Rotate 64 bit integer right by rotationbit value
extern inline uint64_t ROTL64(uint64_t val, uint8_t rotationBit);    //Rotate 64 bit integer left by rotationbit value
extern inline bool IsBigEndian();									 //Check if the system is is bigendian
extern inline uint32_t SwapEndianess32(uint32_t val);				 //swap endianness of 32 bit integer
extern inline uint64_t SwapEndianess64(uint64_t val);				 //swap endianess of 64 bit integer
