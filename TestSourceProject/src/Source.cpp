#include "public/HashingAlgo.h"
#include<iostream>
#include<chrono>
#include<string>

enum SHAType {
	SHA224 = 0, SHA256, SHA384, SHA512, Exit, Error
};
struct CommandExecuteData {
	SHAType Type;
	std::string Data;
};
class CommandBuffer {
private:
	CommandBuffer() {};
public:
	static CommandBuffer& GetInstance() {
		static CommandBuffer _instance;
		return _instance;
	}
	CommandExecuteData ExecuteCommand(const std::string& data) {
		CommandExecuteData cexData;
		if (data == ".exit") {
			cexData.Type = Exit;
			return cexData;
		}
		if (data.length() < 6) {
			cexData.Type = Error;
			return cexData;
		}
		std::string temp = data.substr(0, 6);
		for (int i = 0; i < temp.length(); i++) {          //converting to uppercase
			temp[i] = toupper(temp[i]);
		}
		if (temp == "SHA256") {
			cexData.Type = SHA256;
		}
		else if (temp == "SHA224") {
			cexData.Type = SHA224;
		}
		else if (temp == "SHA384") {
			cexData.Type = SHA384;
		}
		else if (temp == "SHA512") {
			cexData.Type = SHA512;
		}
		else {
			cexData.Type = Error;
		}

		if (cexData.Type != Error) {
			if (data.length() < 7) {
				cexData.Type = Error;
			}
			if (data[6] == ' ') {
				if (data.length() < 8) {
					cexData.Type = Error;
				}
				else {
					cexData.Data = data.substr(7, data.length() - 7);
				}
			}
		}
		return cexData;
	}
};
int main() {
	std::string hashVal;
	std::cout << "Hash>> ";
	std::getline(std::cin, hashVal);
	CommandExecuteData data = CommandBuffer::GetInstance().ExecuteCommand(hashVal);
	while (data.Type != Exit) {
		if (data.Type == Error) {
			std::cout << "No such command found" << '\n';
			std::cout << "Type SHA224 or SHA256 or SHA384 or SHA512  to select specific hashing algorithm" << '\n';
			std::cout << "Give a space and write the key you want to hash after one space" << '\n';
			std::cout << "Type .exit to exit the program" << '\n';
		}
		else {
			switch (data.Type) {
			case SHA224:
				std::cout << HashingAlgorithm::SHA224::GetInstance().ComputeHash(data.Data) << std::endl;
				break;
			case SHA256:
				std::cout << HashingAlgorithm::SHA256::GetInstance().ComputeHash(data.Data) << std::endl;
				break;
			case SHA384:
				std::cout << HashingAlgorithm::SHA384::GetInstance().ComputeHash(data.Data) << std::endl;
				break;
			case SHA512:
				std::cout << HashingAlgorithm::SHA512::GetInstance().ComputeHash(data.Data) << std::endl;
				break;
			}
		}
		std::cout << std::endl;
		std::cout << "Hash>> ";
		std::getline(std::cin, hashVal);
		data = CommandBuffer::GetInstance().ExecuteCommand(hashVal);
	}

#ifdef TEST_HASH_TIME       //define TEST_HASH_TIME on the top to test the hash computation performance.
	std::chrono::system_clock::time_point time = std::chrono::system_clock::now();
	for (int i = 0; i < 10000000; i++) {
		HashingAlgorithm::SHA512::GetInstance().ComputeHash("acd");
	}
	std::chrono::duration<float> timeSpent = std::chrono::system_clock::now() - time;
	std::cout << "Time ellapsed: " << timeSpent.count() << "\n";
#endif
}
