#include "kernel.h"

template< class type >
class TArray {
public:
	TArray() : data(), count(), max_count() {}
	TArray(type* data, std::uint32_t count, std::uint32_t max_count) :
		data(data), count(count), max_count(max_count) {
	}

	type get(std::uintptr_t idx) {
		return Kernel->read< type >(
			std::bit_cast<std::uintptr_t>(this->data) + (idx * sizeof(type))
		);
	}


	std::vector<type> get_itter() {
		if (this->count > this->max_count)
			return {};

		std::vector<type> buffer(this->count);

		Kernel->read_physical((PVOID)
			std::bit_cast<std::uintptr_t>(this->data),
			buffer.data(),
			sizeof(type) * this->count
		);

		return buffer;
	}

	std::uintptr_t get_addr() {
		return reinterpret_cast<std::uintptr_t>(this->data);
	}

	std::uint32_t size() const {
		return this->count;
	};

	std::uint32_t max_size() const {
		return this->max_count;
	};



	bool is_valid() const {
		return this->data != nullptr;
	};

	type* data;
	std::uint32_t count;
	std::uint32_t max_count;

};
int main()
{
	if (!Kernel->connect_driver())
	{
		std::cout << "[-] Failed To Connect To Kernel Mode" << std::endl;
	}
	else
	{
		std::cout << "[+] Connected To Kernel Mode" << std::endl;
	}

	//Kernel->clean(nullptr, false);

	Kernel->g_process_id = Kernel->get_process_id(L"RainbowSix.exe");

	if (!Kernel->g_process_id)
	{
		std::cout << "[-] Failed To Retrieve Process ID" << std::endl;
	}
	else
	{
		std::cout << "[+] Retrieved Process ID -> " << Kernel->g_process_id << std::endl;
	}

	Kernel->g_process_base = Kernel->get_base_address(); //winver.exe

	if (!Kernel->g_process_base)
	{
		std::cout << "[-] Failed To Retrieve Process Base" << std::endl;
	}
	else
	{
		std::cout << "[+] Retrieved Process Base -> " << Kernel->g_process_base << std::endl;
	}

	//Kernel->g_process_cr3 = Kernel->get_cr3();

	if (!Kernel->g_process_cr3)
	{
		std::cout << "[-] Failed To Retrieve Process CR3" << std::endl;
	}
	else
	{
		std::cout << "[+] Retrieved Process CR3 -> " << Kernel->g_process_cr3 << std::endl;
	}
	
	auto current_addres = Kernel->read<uintptr_t>(Kernel->g_process_base + 0x1456EAF8);
	std::cout <<  "main address -> " << current_addres << std::endl;
	for (uintptr_t offset = 0; offset <= 0x100; offset += sizeof(float)) {
		float value = Kernel->read<float>(current_addres + offset);
		std::cout << "Values -> " << value << std::endl;

	//	printf("Address 0x%p: %f\n", (void*)offset, value);
	}
	
	Sleep(10000);

}