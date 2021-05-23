#pragma once
#include "SHAConstants.h"
#include <string>
#include "BitManipulation.h"
namespace HashingAlgorithm {
	class SHA512 {
	private:
		SHA512();
		//uint16_t CalculateK(uint bitLength);
		uint16_t CalculateK(uint64_t bitLength);    //data length of 64 bit is supported since i am using msvc compiler which doesn't support __int128,and also for the amount of computing power it takes to hash that much data is enormus and it is very less likely to happen so i am ignoring it for msvc build.
		void Transform();
		uint64_t CH(uint64_t x, uint64_t y, uint64_t z);
		uint64_t Maj(uint64_t x, uint64_t y, uint64_t z);
		uint64_t BSIG0(uint64_t x);
		uint64_t BSIG1(uint64_t x);
		uint64_t SSIG0(uint64_t x);
		uint64_t SSIG1(uint64_t x);
	private:
		bool m_IsBigEndian;
		char m_finalStringMessage[129];
		Block64 m_computeData;
		uint64_t m_tempHash[8];
	public:
		static SHA512& GetInstance();
		static void Convert64BitHexToStr(uint64_t val, char* data);  //Converts the value to hex value in bigendian

	public:
		char* ComputeHash(const std::string& data);
	};
}