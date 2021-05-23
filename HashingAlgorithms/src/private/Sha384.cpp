#include "../public/Sha384.h"

HashingAlgorithm::SHA384::SHA384() {
	this->m_IsBigEndian = IsBigEndian();
	memset(m_tempHash, 0, sizeof(m_tempHash));
}

uint16_t HashingAlgorithm::SHA384::CalculateK(uint64_t bitLength)
{
	return (1024 - ((bitLength + 1 + 128) % 1024)) % 1024;
}

void HashingAlgorithm::SHA384::Transform()
{
	uint64_t w[80];
	for (int i = 0; i < 16; i++) {
		w[i] = SwapEndianess64((this->m_computeData.BlockData[i]));    //as all x86 and x64 processor works on little endian i assume this is going to work on al machins;
	}
	for (int i = 16; i < 80; i++) {
		w[i] = this->SSIG1(w[i - 2]) + w[i - 7] + this->SSIG0(w[i - 15]) + w[i - 16];
	}
	uint64_t a, b, c, d, e, f, g, h, T1, T2;
	a = m_tempHash[0];
	b = m_tempHash[1];
	c = m_tempHash[2];
	d = m_tempHash[3];
	e = m_tempHash[4];
	f = m_tempHash[5];
	g = m_tempHash[6];
	h = m_tempHash[7];
	for (int i = 0; i < 80; i++) {
		T1 = h + this->BSIG1(e) + this->CH(e, f, g) + SHA384CONSTS::K[i] + w[i];
		T2 = this->BSIG0(a) + this->Maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
	}
	this->m_tempHash[0] += a;
	this->m_tempHash[1] += b;
	this->m_tempHash[2] += c;
	this->m_tempHash[3] += d;
	this->m_tempHash[4] += e;
	this->m_tempHash[5] += f;
	this->m_tempHash[6] += g;
	this->m_tempHash[7] += h;
}

uint64_t HashingAlgorithm::SHA384::CH(uint64_t x, uint64_t y, uint64_t z)
{
	return (x&y) ^ ((~x)&z);
}

uint64_t HashingAlgorithm::SHA384::Maj(uint64_t x, uint64_t y, uint64_t z)
{
	return (x&y) ^ (x&z) ^ (y&z);
}

uint64_t HashingAlgorithm::SHA384::BSIG0(uint64_t x)
{
	return ROTR64(x, 28) ^ ROTR64(x, 34) ^ ROTR64(x, 39);
}

uint64_t HashingAlgorithm::SHA384::BSIG1(uint64_t x)
{
	return ROTR64(x, 14) ^ ROTR64(x, 18) ^ ROTR64(x, 41);
}

uint64_t HashingAlgorithm::SHA384::SSIG0(uint64_t x)
{
	return ROTR64(x, 1) ^ ROTR64(x, 8) ^ (x >> 7);
}

uint64_t HashingAlgorithm::SHA384::SSIG1(uint64_t x)
{
	return ROTR64(x, 19) ^ ROTR64(x, 61) ^ (x >> 6);
}

HashingAlgorithm::SHA384 & HashingAlgorithm::SHA384::GetInstance()
{
	static SHA384 instance;
	return instance;
}

void HashingAlgorithm::SHA384::Convert64BitHexToStr(uint64_t val, char * data)
{
	char hexData[16] = { '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f' };
	data[1] = hexData[((val >> 56) & 0x000000000000000f)];
	data[2] = hexData[((val >> 52) & 0x000000000000000f)];
	data[3] = hexData[((val >> 48) & 0x000000000000000f)];
	data[0] = hexData[((val >> 60) & 0x000000000000000f)];
	data[4] = hexData[((val >> 44) & 0x000000000000000f)];
	data[5] = hexData[((val >> 40) & 0x000000000000000f)];
	data[6] = hexData[((val >> 36) & 0x000000000000000f)];
	data[7] = hexData[((val >> 32) & 0x000000000000000f)];
	data[8] = hexData[((val >> 28) & 0x000000000000000f)];
	data[9] = hexData[((val >> 24) & 0x000000000000000f)];
	data[10] = hexData[((val >> 20) & 0x000000000000000f)];
	data[11] = hexData[((val >> 16) & 0x000000000000000f)];
	data[12] = hexData[((val >> 12) & 0x000000000000000f)];
	data[13] = hexData[((val >> 8) & 0x000000000000000f)];
	data[14] = hexData[((val >> 4) & 0x000000000000000f)];
	data[15] = hexData[((val >> 0) & 0x000000000000000f)];
}

char * HashingAlgorithm::SHA384::ComputeHash(const std::string & data)
{
	uint64_t dataLength = data.length() * BYTE_SIZE;
	uint16_t k = this->CalculateK(dataLength);
	int paddedMessageLength = ((dataLength + 1 + 128) / 1024) + 1 - !k;
	memcpy(this->m_tempHash, SHA384CONSTS::H, sizeof(m_tempHash));
	for (int i = 0; i < paddedMessageLength - 2; i++) {
		memcpy(this->m_computeData.BlockData, data.c_str() + i * sizeof(Block64), sizeof(Block64));
		this->Transform();
	}
	uint64_t offset = (paddedMessageLength - 1) * sizeof(Block64);
	if (paddedMessageLength > 1) {
		memset(this->m_computeData.BlockData, 0, sizeof(Block64));
		uint64_t temp = data.length() - (paddedMessageLength - 2) * sizeof(Block64);
		uint8_t  greater = temp > sizeof(Block64);     //checking if temp size is greater than block size
		uint32_t val = (paddedMessageLength - 2) * sizeof(Block64);
		memcpy(this->m_computeData.BlockData, data.c_str() + val, (greater * sizeof(Block64) + (!greater) * temp));
		if (!greater) {
			this->m_computeData.ByteData[temp] = 0b10000000;
		}
		this->Transform();
		memset(this->m_computeData.BlockData, 0, sizeof(Block64));
		memcpy(this->m_computeData.BlockData, data.c_str() + val + sizeof(Block64), (greater* (temp - sizeof(Block64))));
		if (greater) {
			this->m_computeData.ByteData[temp - sizeof(Block64)] = 0b10000000;
		}
	}
	else {

		memset(this->m_computeData.BlockData, 0, sizeof(Block64));
		memcpy(this->m_computeData.BlockData, data.c_str() + offset, data.length());
		this->m_computeData.ByteData[data.length() - offset] = 0b10000000;
	}

	if (!IsBigEndian()) dataLength = SwapEndianess64(dataLength);
	memcpy(&this->m_computeData.ByteData[128 - 8], &dataLength, 8);
	//this->m_computeData.ByteData[64 - 1] = ((char*)&dataLength)[0];
	//this->m_computeData.ByteData[64 - 2] = ((char*)&dataLength)[1];
	//this->m_computeData.ByteData[64 - 3] = ((char*)&dataLength)[2];
	//this->m_computeData.ByteData[64 - 4] = ((char*)&dataLength)[3];
	//this->m_computeData.ByteData[64 - 5] = ((char*)&dataLength)[4];
	//this->m_computeData.ByteData[64 - 6] = ((char*)&dataLength)[5];
	//this->m_computeData.ByteData[64 - 7] = ((char*)&dataLength)[6];
	//this->m_computeData.ByteData[64 - 8] = ((char*)&dataLength)[7];
	this->Transform();
	char tempData[16];
	for (int i = 0; i < 6; i++) {
		Convert64BitHexToStr(this->m_tempHash[i], tempData);
		memcpy(this->m_finalStringMessage + i * 16, tempData, 16);
	}
	this->m_finalStringMessage[112] = 0x00;
	return m_finalStringMessage;
}
