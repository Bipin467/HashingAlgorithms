#pragma once
#include "SHAConstants.h"
#include <string>
#include "BitManipulation.h"
namespace HashingAlgorithm {
	class SHA256 {
	private:
		SHA256();
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
		char m_finalStringMessage[65];
		Block32 m_computeData;
		uint32_t m_tempHash[8];
	public:
		static SHA256& GetInstance();
		static void Convert32BitHexToStr(uint32_t val, char* data);  //Converts the value to hex value in bigendian

	public:
		char* ComputeHash(const std::string& data);
	};
}