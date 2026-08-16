#include <algorithm>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

/*informational links
https://skr1x.github.io/portable-executable-format/
https://wiki.osdev.org/PE
https://wiki.osdev.org/PE
*/
#pragma pack(push, 1)

struct DOSHeader
{
    std::uint16_t e_magic;
    std::uint16_t pad[29];
    std::int32_t e_lfanew;
};

struct COFFFileHeader
{
    std::uint16_t machine;
    std::uint16_t numberOfSections;
    std::uint32_t timeDateStamp;
    std::uint32_t pointerToSymbolTable;
    std::uint32_t numberOfSymbols;
    std::uint16_t sizeOfOptionalHeader;
    std::uint16_t characteristics;
};

struct PE32OptionalHeader
{
    std::uint16_t magic;
    std::uint8_t majorLinkerVersion;
    std::uint8_t minorLinkerVersion;
    std::uint32_t sizeOfCode;
    std::uint32_t sizeOfInitializedData;
    std::uint32_t sizeOfUninitializedData;
    std::uint32_t addressOfEntryPoint;
    std::uint32_t baseOfCode;
    std::uint32_t baseOfData;
    std::uint32_t imageBase;
};

struct PE32PlusOptionalHeader
{
    std::uint16_t magic;
    std::uint8_t majorLinkerVersion;
    std::uint8_t minorLinkerVersion;
    std::uint32_t sizeOfCode;
    std::uint32_t sizeOfInitializedData;
    std::uint32_t sizeOfUninitializedData;
    std::uint32_t addressOfEntryPoint;
    std::uint32_t baseOfCode;
    std::uint64_t imageBase;
};

struct SectionHeader
{
    char name[8];
    std::uint32_t virtualSize;
    std::uint32_t virtualAddress;
    std::uint32_t sizeOfRawData;
    std::uint32_t pointerToRawData;
    std::uint32_t pointerToRelocations;
    std::uint32_t pointerToLinenumbers;
    std::uint16_t numberOfRelocations;
    std::uint16_t numberOfLinenumbers;
    std::uint32_t characteristics;
};

#pragma pack(pop)

constexpr std::uint16_t DOS_SIGNATURE = 0x5A4D;
constexpr std::uint32_t PE_SIGNATURE = 0x00004550;

constexpr std::uint16_t PE32_MAGIC = 0x010B;
constexpr std::uint16_t PE32_PLUS_MAGIC = 0x020B;

constexpr std::uint16_t MACHINE_I386 = 0x014C;
constexpr std::uint16_t MACHINE_X86_64 = 0x8664;
constexpr std::uint16_t MACHINE_ARM64 = 0xAA64;

constexpr int MAX_BYTES_TO_PRINT = 32;
constexpr int BYTES_PER_LINE = 16;

template <typename T>
bool readStruct(std::ifstream& file, T& value)
{
    file.read(reinterpret_cast<char*>(&value), sizeof(T));
    return file.good();
}

std::string getArchitecture(std::uint16_t machine)
{
    switch (machine)
    {
        case MACHINE_X86_64:
            return "x86-64";

        case MACHINE_I386:
            return "i386";

        case MACHINE_ARM64:
            return "ARM64";

        default:
            return "Unknown";
    }
}

std::string getSectionName(const SectionHeader& section)
{
    char name[9] = {};
    std::memcpy(name, section.name, sizeof(section.name));
    return name;
}

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << " <path_to_exe>\n";
        return 1;
    }

    std::ifstream file(argv[1], std::ios::binary);

    if (!file)
    {
        std::cerr << "Error: Could not open file.\n";
        return 1;
    }

    DOSHeader dosHeader;

    if (!readStruct(file, dosHeader))
    {
        std::cerr << "Error: Could not read DOS header.\n";
        return 1;
    }

    if (dosHeader.e_magic != DOS_SIGNATURE)
    {
        std::cout << "Not an EXE file\n";
        return 1;
    }

    file.seekg(dosHeader.e_lfanew, std::ios::beg);

    if (!file)
    {
        std::cerr << "Error: Invalid PE header offset.\n";
        return 1;
    }

    std::uint32_t peSignature = 0;

    if (!readStruct(file, peSignature))
    {
        std::cerr << "Error: Could not read PE signature.\n";
        return 1;
    }

    if (peSignature != PE_SIGNATURE)
    {
        std::cout << "Not an EXE file\n";
        return 1;
    }

    COFFFileHeader coffHeader;

    if (!readStruct(file, coffHeader))
    {
        std::cerr << "Error: Could not read COFF header.\n";
        return 1;
    }

    const std::string architecture = getArchitecture(coffHeader.machine);

    std::uint16_t optionalHeaderMagic = 0;

    if (!readStruct(file, optionalHeaderMagic))
    {
        std::cerr << "Error: Could not read Optional Header magic.\n";
        return 1;
    }

    file.seekg(-static_cast<std::streamoff>(sizeof(optionalHeaderMagic)), std::ios::cur);

    std::uint64_t imageBase = 0;
    std::uint32_t entryPointRVA = 0;

    switch (optionalHeaderMagic)
    {
        case PE32_MAGIC:
        {
            PE32OptionalHeader optionalHeader;

            if (!readStruct(file, optionalHeader))
            {
                std::cerr << "Error: Could not read PE32 Optional Header.\n";
                return 1;
            }

            imageBase = optionalHeader.imageBase;
            entryPointRVA = optionalHeader.addressOfEntryPoint;

            break;
        }

        case PE32_PLUS_MAGIC:
        {
            PE32PlusOptionalHeader optionalHeader;

            if (!readStruct(file, optionalHeader))
            {
                std::cerr << "Error: Could not read PE32+ Optional Header.\n";
                return 1;
            }

            imageBase = optionalHeader.imageBase;
            entryPointRVA = optionalHeader.addressOfEntryPoint;

            break;
        }

        default:
        {
            std::cout << "Not an EXE file\n";
            return 1;
        }
    }

    const std::uint64_t absoluteEntryPoint = imageBase + entryPointRVA;

    std::cout << "PE file: " << argv[1] << '\n';
    std::cout << "Architecture: " << architecture << '\n';
    std::cout << "Entry point: 0x" << std::hex << absoluteEntryPoint << "\n\n";

    const std::streamoff sectionHeadersOffset = static_cast<std::streamoff>(dosHeader.e_lfanew) + sizeof(peSignature) + sizeof(COFFFileHeader) + coffHeader.sizeOfOptionalHeader;

    file.seekg(sectionHeadersOffset, std::ios::beg);

    if (!file)
    {
        std::cerr << "Error: Could not seek to section headers.\n";
        return 1;
    }

    std::cout << "Sections:\n";

    SectionHeader textSection {};
    bool foundTextSection = false;

    for (std::uint16_t i = 0; i < coffHeader.numberOfSections; ++i)
    {
        SectionHeader section {};

        if (!readStruct(file, section))
        {
            std::cerr << "Error: Could not read section header.\n";
            return 1;
        }

        const std::string sectionName = getSectionName(section);
        const std::uint64_t sectionAddress = imageBase + section.virtualAddress;

        std::cout << "  [" << std::dec << i << "] " << std::left << std::setw(8) << sectionName << " offset=0x" << std::hex << section.pointerToRawData << " size=0x" << section.sizeOfRawData << " addr=0x" << sectionAddress << '\n';

        if (std::strncmp(section.name, ".text", sizeof(section.name)) == 0) //check if this is the .text section
        {
            textSection = section;
            foundTextSection = true;
        }
    }

    std::cout << '\n';

    if (!foundTextSection)
    {
        std::cerr << ".text section not found!\n";
        return 1;
    }

    const std::uint64_t textAddress = imageBase + textSection.virtualAddress;

    std::cout << ".text section found!\n";
    std::cout << "  File offset : 0x" << std::hex << textSection.pointerToRawData << '\n';
    std::cout << "  Virtual addr: 0x" << textAddress << '\n';
    std::cout << "  Size        : 0x" << std::hex << textSection.sizeOfRawData << " (" << std::dec << textSection.sizeOfRawData << " bytes)\n\n";

    std::vector<std::uint8_t> machineCode(textSection.sizeOfRawData);

    file.seekg(textSection.pointerToRawData, std::ios::beg);

    if (!file)
    {
        std::cerr << "Error: Could not seek to .text section.\n";
        return 1;
    }

    file.read(reinterpret_cast<char*>(machineCode.data()), static_cast<std::streamsize>(machineCode.size()));

    if (!file)
    {
        std::cerr << "Error: Could not read .text section.\n";
        return 1;
    }

    std::cout << "First bytes of .text:\n";

    const std::size_t bytesToPrint = std::min(machineCode.size(), static_cast<std::size_t>(MAX_BYTES_TO_PRINT));

    for (std::size_t i = 0; i < bytesToPrint; ++i)
    {
        std::cout << std::dec << static_cast<unsigned int>(machineCode[i]) << ' ';

        if ((i + 1) % BYTES_PER_LINE == 0)
        {
            std::cout << '\n';
        }
    }

    std::cout << '\n';

    return 0;
}
