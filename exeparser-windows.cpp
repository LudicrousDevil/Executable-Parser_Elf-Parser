#include <Windows.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

constexpr int MAX_BYTES_TO_PRINT = 32;
constexpr int BYTES_PER_LINE = 16;

template <typename T>
bool readStruct(std::ifstream& file, T& value)
{
    file.read(reinterpret_cast<char*>(&value), sizeof(T));
    return file.good();
}

std::string getArchitecture(WORD machine)
{
    switch (machine)
    {
        case IMAGE_FILE_MACHINE_AMD64:
            return "x86-64";

        case IMAGE_FILE_MACHINE_I386:
            return "i386";

        case IMAGE_FILE_MACHINE_ARM64:
            return "ARM64";

        default:
            return "Unknown";
    }
}

std::string getSectionName(const IMAGE_SECTION_HEADER& section)
{
    char name[IMAGE_SIZEOF_SHORT_NAME + 1] = {};

    std::memcpy(name, section.Name, IMAGE_SIZEOF_SHORT_NAME);

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

    // DOS HEADER

    IMAGE_DOS_HEADER dosHeader{};

    if (!readStruct(file, dosHeader))
    {
        std::cerr << "Error: Could not read DOS header.\n";
        return 1;
    }

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
    {
        std::cout << "Not an EXE file\n";
        return 1;
    }

    // e_lfanew contains the file offset of the PE header.
    file.seekg(dosHeader.e_lfanew, std::ios::beg);

    if (!file)
    {
        std::cerr << "Error: Invalid PE header offset.\n";
        return 1;
    }

    // PE SIGNATURE

    DWORD peSignature = 0;

    if (!readStruct(file, peSignature))
    {
        std::cerr << "Error: Could not read PE signature.\n";
        return 1;
    }

    if (peSignature != IMAGE_NT_SIGNATURE)
    {
        std::cout << "Not an EXE file\n";
        return 1;
    }

    // COFF / FILE HEADER

    IMAGE_FILE_HEADER fileHeader{};

    if (!readStruct(file, fileHeader))
    {
        std::cerr << "Error: Could not read COFF header.\n";
        return 1;
    }

    const std::string architecture = getArchitecture(fileHeader.Machine);

    // OPTIONAL HEADER

    WORD optionalHeaderMagic = 0;

    if (!readStruct(file, optionalHeaderMagic))
    {
        std::cerr << "Error: Could not read Optional Header magic.\n";
        return 1;
    }

    // Move back so we can read the complete optional header.
    file.seekg(-static_cast<std::streamoff>(sizeof(optionalHeaderMagic)), std::ios::cur);

    if (!file)
    {
        std::cerr << "Error: Could not seek within Optional Header.\n";
        return 1;
    }

    std::uint64_t imageBase = 0;
    std::uint32_t entryPointRVA = 0;

    switch (optionalHeaderMagic)
    {
        case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
        {
            IMAGE_OPTIONAL_HEADER32 optionalHeader{};

            if (!readStruct(file, optionalHeader))
            {
                std::cerr << "Error: Could not read PE32 Optional Header.\n";
                return 1;
            }

            imageBase = optionalHeader.ImageBase;
            entryPointRVA = optionalHeader.AddressOfEntryPoint;

            break;
        }

        case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
        {
            IMAGE_OPTIONAL_HEADER64 optionalHeader{};

            if (!readStruct(file, optionalHeader))
            {
                std::cerr << "Error: Could not read PE32+ Optional Header.\n";
                return 1;
            }

            imageBase = optionalHeader.ImageBase;
            entryPointRVA = optionalHeader.AddressOfEntryPoint;

            break;
        }

        default:
        {
            std::cout << "Not an EXE file\n";
            return 1;
        }
    }

    // ENTRY POINT

    const std::uint64_t absoluteEntryPoint = imageBase + entryPointRVA;

    std::cout << "PE file: " << argv[1] << '\n';
    std::cout << "Architecture: " << architecture << '\n';
    std::cout << "Entry point: 0x" << std::hex << absoluteEntryPoint << "\n\n";

    // SECTION HEADERS

    const std::streamoff sectionHeadersOffset = static_cast<std::streamoff>(dosHeader.e_lfanew) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + fileHeader.SizeOfOptionalHeader;

    file.seekg(sectionHeadersOffset, std::ios::beg);

    if (!file)
    {
        std::cerr << "Error: Could not seek to section headers.\n";
        return 1;
    }

    std::cout << "Sections:\n";

    IMAGE_SECTION_HEADER textSection{};
    bool foundTextSection = false;

    for (WORD i = 0; i < fileHeader.NumberOfSections; ++i)
    {
        IMAGE_SECTION_HEADER section{};

        if (!readStruct(file, section))
        {
            std::cerr << "Error: Could not read section header.\n";
            return 1;
        }

        const std::string sectionName = getSectionName(section);
        const std::uint64_t sectionAddress = imageBase + section.VirtualAddress;

        std::cout << "  [" << std::dec << i << "] " << std::left << std::setw(8) << sectionName << " offset=0x" << std::hex << section.PointerToRawData << " size=0x" << section.SizeOfRawData << " addr=0x" << sectionAddress << '\n';

        if (sectionName == ".text")
        {
            textSection = section;
            foundTextSection = true;
        }
    }

    std::cout << '\n';

    // .TEXT SECTION

    if (!foundTextSection)
    {
        std::cerr << ".text section not found!\n";
        return 1;
    }

    const std::uint64_t textAddress = imageBase + textSection.VirtualAddress;

    std::cout << ".text section found!\n";
    std::cout << "  File offset : 0x" << std::hex << textSection.PointerToRawData << '\n';
    std::cout << "  Virtual addr: 0x" << textAddress << '\n';
    std::cout << "  Size        : 0x" << std::hex << textSection.SizeOfRawData << " (" << std::dec << textSection.SizeOfRawData << " bytes)\n\n";

    // READ .TEXT

    std::vector<std::uint8_t> machineCode(textSection.SizeOfRawData);

    file.seekg(textSection.PointerToRawData, std::ios::beg);

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

    // PRINT FIRST BYTES

    std::cout << "First bytes of .text:\n";

    const std::size_t bytesToPrint = std::min(machineCode.size(), static_cast<std::size_t>(MAX_BYTES_TO_PRINT));

    for (std::size_t i = 0; i < bytesToPrint; ++i)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(machineCode[i]) << ' ';

        if ((i + 1) % BYTES_PER_LINE == 0)
        {
            std::cout << '\n';
        }
    }

    std::cout << '\n';

    return 0;
}
