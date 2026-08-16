#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include <cstring>

#include <elf.h>

int main(int argc, char* argv[])
{
    if (argc != 2)
    {
        std::cout << "Usage: " << argv[0] << " <elf-file>\n";
        return 1;
    }

    const char* filename = argv[1];

    //open file
    std::ifstream file(filename, std::ios::binary);

    if (!file)
    {
        std::cerr << "Failed to open file: " << filename << "\n";
        return 1;
    }

    // read ELF64 header

    Elf64_Ehdr elfHeader{};

    file.read(reinterpret_cast<char*>(&elfHeader), sizeof(elfHeader));

    if (!file)
    {
        std::cerr << "Failed to read ELF header\n";
        return 1;
    }

    // Check elf magic  (if the file is a valid elf format)

    if (elfHeader.e_ident[EI_MAG0] != ELFMAG0 ||
        elfHeader.e_ident[EI_MAG1] != ELFMAG1 ||
        elfHeader.e_ident[EI_MAG2] != ELFMAG2 ||
        elfHeader.e_ident[EI_MAG3] != ELFMAG3)
    {
        std::cerr << "Not an ELF file\n";
        return 1;
    }

    //Check ELF64

    if (elfHeader.e_ident[EI_CLASS] != ELFCLASS64)
    {
        std::cerr << "This program only supports ELF64\n";
        return 1;
    }

    // Check x86-64

    if (elfHeader.e_machine != EM_X86_64)
    {
        std::cerr << "This program only supports x86-64\n";
        return 1;
    }

    std::cout << "ELF file: " << filename << "\n";
    std::cout << "Architecture: x86-64\n";

    std::cout << std::hex << "Entry point: 0x" << elfHeader.e_entry << "\n";

    // Locate section-name string table

    if (elfHeader.e_shstrndx == SHN_UNDEF)
    {
        std::cerr << "No section-name string table\n";
        return 1;
    }

    Elf64_Shdr stringTableHeader{}; //just struct used to store data

    /*
     https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html

    ALERT elfHeader.e_shoff = This member holds the section header table's file offset in bytes. If the file has no section header table, this member holds zero.

    ALERT elfHeader.e_shstrndx = This member holds the section header table index of the entry associated with the section name string table. If the file has no section name string table, this member holds the value SHN_UNDEF.

    ^^^  See ``Sections'' and ``String Table'' below for more information.      (https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html)



    ALERT elfHeader.e_shentsize = This member holds a section header's size in bytes. A section header is one entry in the section header table; all entries are the same size.

    below is elfHeader.e_shoff   +   (   elfHeader.e_shstrndx * elfHeader.e_shentsize  )

    (file offset in bytes)   +   (     Header table index    *    Header size in bytes    )

    THIS CODE (next two lines) MOVED THE FILE POINTER OR READ POSITION TO THE BYTES OFFSET OF THE ELF STRING TABLE IN THE FILE
    */
    const auto sectionIndex = static_cast<std::streamoff>(elfHeader.e_shstrndx);
    const auto sectionSize  = static_cast<std::streamoff>(elfHeader.e_shentsize);
    std::streamoff stringTableHeaderOffset = elfHeader.e_shoff + (sectionIndex * sectionSize);

    file.seekg(stringTableHeaderOffset);

    if (!file)
    {
        std::cerr << "Failed to seek to section-name string table\n";
        return 1;
    }

    file.read(reinterpret_cast<char*>(&stringTableHeader), sizeof(stringTableHeader));//writing to the stringTableHeader struct

    if (!file)
    {
        std::cerr << "Failed to read string table header\n";
        return 1;
    }

    // Read section-name string table

    std::vector<char> stringTable(static_cast<size_t>(stringTableHeader.sh_size));

    file.seekg(static_cast<std::streamoff>(stringTableHeader.sh_offset));

    if (!file)
    {
        std::cerr << "Failed to seek to string table\n";
        return 1;
    }

            //&stringTable[0]     static_cast<std::streamsize>(stringTable.size())     old code, replaced with std::size() from c++20 (im using c++23) using kate had to make a .clangd file in project directory
    file.read(stringTable.data(), std::ssize(stringTable) );

    if (!file)
    {
        std::cerr << "Failed to read string table\n";
        return 1;
    }

    // Find .text

    Elf64_Shdr textSection{};
    bool foundText = false;

    std::cout << "\nSections:\n";

    //                  e_shnum holds the number of entries in the section header table
    for (int i = 0; i < elfHeader.e_shnum; ++i)
    {
        Elf64_Shdr section{};

        std::streamoff sectionOffset = static_cast<std::streamoff>(elfHeader.e_shoff) + static_cast<std::streamoff>( i * elfHeader.e_shentsize);

        file.seekg(sectionOffset);

        if (!file)
        {
            std::cerr << "Failed to seek to section " << i << "\n";
            return 1;
        }

        //read file section data into section struct
        file.read(reinterpret_cast<char*>(&section), sizeof(section) );

        if (!file)
        {
            std::cerr << "Failed to read section " << i << "\n";
            return 1;
        }

        // Get section name         &stringTable[0]
        const char* sectionName = stringTable.data() + section.sh_name;

        std::cout << "  [" << std::dec << i << "] " << std::left << std::string(sectionName) << std::right << " offset=0x" << std::hex << section.sh_offset << " size=0x" << section.sh_size << " addr=0x" << section.sh_addr << "\n";

        // Check for .text
        if (std::strcmp(sectionName, ".text") == 0)
        {
            textSection = section;
            foundText = true;
        }
    }

    // Make sure .text was found

    if (!foundText)
    {
        std::cerr << "\n.text section not found\n";
        return 1;
    }

    // Print .text information

    std::cout << "\n.text section found!\n";

    std::cout << "  File offset : 0x" << std::hex << textSection.sh_offset << "\n";

    std::cout << "  Virtual addr: 0x" << textSection.sh_addr << "\n";

    std::cout << "  Size        : 0x" << textSection.sh_size << " (" << std::dec << textSection.sh_size << " bytes)\n";

    // Read .text

    std::vector<uint8_t> text(static_cast<size_t>(textSection.sh_size));

    file.seekg(static_cast<std::streamoff>(textSection.sh_offset));

    if (!file)
    {
        std::cerr << "Failed to seek to .text\n";
        return 1;
    }

    file.read(reinterpret_cast<char*>(text.data()),static_cast<std::streamsize>(text.size()));

    if (!file)
    {
        std::cerr << "Failed to read .text\n";
        return 1;
    }

    // Print first 32 bytes
    std::cout << "\nFirst bytes of .text:\n";

    size_t bytesToPrint = text.size();

    if (bytesToPrint > 32)
    {
        bytesToPrint = 32;
    }

    for (size_t i = 0; i < bytesToPrint; ++i)
    {

        if (text[i] < 0x10)
        {
            std::cout << std::hex << '0';
        }

        std::cout << static_cast<int>(text[i]) << ' ';

        if ((i + 1) % 16 == 0)  //print 16 bytes before new line to format hex  (i + 1) if remainder / 16 = 0 new line
        {
            std::cout << '\n';
        }
    }

    std::cout << '\n';
    return 0;
}
