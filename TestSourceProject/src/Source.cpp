#include "HashingAlgo.h"
#include<iostream>
#include<chrono>
int main() {
	std::cout << HashingAlgorithm::SHA256::GetInstance().ComputeHash("abc") << std::endl;
	std::chrono::system_clock::time_point time = std::chrono::system_clock::now();
	for (int i = 0; i < 10000000; i++) {
		HashingAlgorithm::SHA256::GetInstance().ComputeHash("abc");
	}
	std::cout << SwapEndianess32(SwapEndianess32(50)) << std::endl;
	std::cout << ROTR32(ROTL32(5, 2), 2) << std::endl;
	std::chrono::duration<float> timeSpent = std::chrono::system_clock::now()-time;
	std::cout << "Time ellapsed: " << timeSpent.count() << "\n";
	std::cout << HashingAlgorithm::SHA224::GetInstance().ComputeHash("abc") << std::endl;
	std::cin.get();
}