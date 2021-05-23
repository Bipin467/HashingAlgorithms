#include "../public/Sha224.h"

HashingAlgorithm::SHA224::SHA224() {
	this->m_IsBigEndian = IsBigEndian();
	memset(m_tempHash, 0, sizeof(m_tempHash));
}
uint16_t HashingAlgorithm::SHA224::CalculateK(uint32_t bitLength)
{
	return 512-(bitLength + 1 + 64) % 512;
}

uint16_t HashingAlgorithm::SHA224::CalculateK(uint64_t bitLength)
{
	return 512 - (bitLength + 1 + 64) % 512;
}

HashingAlgorithm::SHA224& HashingAlgorithm::SHA224::GetInstance() {
	static SHA224 instance;
	return instance;
}

void HashingAlgorithm::SHA224::Convert32BitHexToStr(uint32_t val, char * data)
{
	char hexData[16] = { '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f' };
	data[0] = hexData[val >> 28];
	data[1] = hexData[((val >> 24) & 0x0000000f)];
	data[2] = hexData[((val >> 20) & 0x0000000f)];
	data[3] = hexData[((val >> 16) & 0x0000000f)];
	data[4] = hexData[((val >> 12) & 0x0000000f)];
	data[5] = hexData[((val >> 8) & 0x0000000f)];
	data[6] = hexData[((val >> 4) & 0x0000000f)];
	data[7] = hexData[(val & 0x0000000f)];
	//data[8] = 0x00;
}


char* HashingAlgorithm::SHA224::ComputeHash(const std::string& data) {
	uint64_t dataLength = data.length() * BYTE_SIZE;
	uint16_t k = this->CalculateK(dataLength);
	int64_t paddedMessageLength = ((dataLength + 1 + 64) / 512) + 1 - !k;
	memcpy(this->m_tempHash, SHA224CONSTS::H, sizeof(m_tempHash));
	for (int i = 0; i < paddedMessageLength - 2; i++) {
		memcpy(this->m_computeData.BlockData, data.c_str() + i * sizeof(Block32), sizeof(Block32));
		this->Transform();
	}
	uint64_t offset = (paddedMessageLength - 1) * sizeof(Block32);
	if (paddedMessageLength > 1) {
		memset(this->m_computeData.BlockData, 0, sizeof(Block32));
		uint64_t temp = data.length() - (paddedMessageLength - 2) * sizeof(Block32);
		uint8_t  greater = temp > sizeof(Block32);
		uint32_t val = (paddedMessageLength - 2) * sizeof(Block32);
		memcpy(this->m_computeData.BlockData, data.c_str() + val, (greater * sizeof(Block32) + (!greater) * temp));
		if (!greater) {
			this->m_computeData.ByteData[temp] = 0b10000000;
		}
		this->Transform();
		memset(this->m_computeData.BlockData, 0, sizeof(Block32));
		memcpy(this->m_computeData.BlockData, data.c_str() + val + sizeof(Block32), (greater* (temp - sizeof(Block32))));
		if (greater) {
			this->m_computeData.ByteData[temp - sizeof(Block32)] = 0b10000000;
		}
	}
	else {

		memset(this->m_computeData.BlockData, 0, sizeof(Block32));
		memcpy(this->m_computeData.BlockData, data.c_str() + offset, data.length());
		this->m_computeData.ByteData[data.length() - offset] = 0b10000000;
	}
	if (!IsBigEndian())	dataLength = SwapEndianess64(dataLength);    //swapping endianness because sha uses bigendian type
	memcpy(&this->m_computeData.ByteData[64 - 8], &dataLength, 8);
	//this->m_computeData.ByteData[64 - 1] = ((char*)&dataLength)[0];
	//this->m_computeData.ByteData[64 - 2] = ((char*)&dataLength)[1];
	//this->m_computeData.ByteData[64 - 3] = ((char*)&dataLength)[2];
	//this->m_computeData.ByteData[64 - 4] = ((char*)&dataLength)[3];
	//this->m_computeData.ByteData[64 - 5] = ((char*)&dataLength)[4];
	//this->m_computeData.ByteData[64 - 6] = ((char*)&dataLength)[5];
	//this->m_computeData.ByteData[64 - 7] = ((char*)&dataLength)[6];
	//this->m_computeData.ByteData[64 - 8] = ((char*)&dataLength)[7];
	this->Transform();
	char tempData[8];
	for (int i = 0; i < 7; i++) {
		Convert32BitHexToStr(this->m_tempHash[i], tempData);
		memcpy(this->m_finalStringMessage + i * 8, tempData, 8);
	}
	this->m_finalStringMessage[56] = 0x00;
	return m_finalStringMessage;
}


void HashingAlgorithm::SHA224::Transform() {
	uint32_t w[64];
	for (int i = 0; i < 16; i++) {
		w[i] = SwapEndianess32(this->m_computeData.BlockData[i]);
	}
	for (int i = 16; i < 64; i++) {
		w[i] = this->SSIG1(w[i - 2]) + w[i - 7] + this->SSIG0(w[i - 15]) + w[i - 16];
	}
	uint32_t a, b, c, d, e, f, g, h, T1, T2;
	a = m_tempHash[0];
	b = m_tempHash[1];
	c = m_tempHash[2];
	d = m_tempHash[3];
	e = m_tempHash[4];
	f = m_tempHash[5];
	g = m_tempHash[6];
	h = m_tempHash[7];
	for (int i = 0; i < 64; i++) {
		T1 = h + this->BSIG1(e) + this->CH(e, f, g) + SHA224CONSTS::K[i] + w[i];
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

uint32_t HashingAlgorithm::SHA224::Maj(uint32_t x, uint32_t y, uint32_t z)
{
	return (x&y) ^ (x&z) ^ (y&z);
}

uint32_t HashingAlgorithm::SHA224::CH(uint32_t x, uint32_t y, uint32_t z)
{
	return (x&y) ^ ((~x) &z);
}

uint32_t HashingAlgorithm::SHA224::BSIG0(uint32_t x) {
	return ROTR32(x, 2) ^ ROTR32(x, 13) ^ ROTR32(x, 22);
}

uint32_t HashingAlgorithm::SHA224::BSIG1(uint32_t x) {
	return ROTR32(x, 6) ^ ROTR32(x, 11) ^ ROTR32(x, 25);
}


uint32_t HashingAlgorithm::SHA224::SSIG0(uint32_t x) {
	return ROTR32(x, 7) ^ ROTR32(x, 18) ^ (x >> 3);
}


uint32_t HashingAlgorithm::SHA224::SSIG1(uint32_t x) {
	return ROTR32(x, 17) ^ ROTR32(x, 19) ^ (x >> 10);
}
