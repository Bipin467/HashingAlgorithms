#pragma once
#include "SHAConstants.h"
#include <string>
#include "BitManipulation.h"
namespace HashingAlgorithm {
	class SHA224 {
	private:
		SHA224();
		uint16_t CalculateK(uint32_t bitLength);
		uint16_t CalculateK(uint64_t bitLength);
		void Transform();
		uint32_t CH(uint32_t x, uint32_t y, uint32_t z);
		uint32_t Maj(uint32_t x, uint32_t y, uint32_t z);
		uint32_t BSIG0(uint32_t x);
		uint32_t BSIG1(uint32_t x);
		uint32_t SSIG0(uint32_t x);
		uint32_t SSIG1(uint32_t x);
	private:
		bool m_IsBigEndian;
		char m_finalStringMessage[57];
		Block m_computeData;
		int32_t m_tempHash[8];
	public:
		static SHA224& GetInstance();
		static void Convert32BitHexBigEndian(uint32_t val, char* data);  //Converts the value to hex value in bigendian

	public:
		char* ComputeHash(const std::string& data);
	};
}