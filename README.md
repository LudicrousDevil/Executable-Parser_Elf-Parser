# Executable-Parser_Elf-Parser
AI generated code to get data from the .text sections from ELF or EXE files so begin working on a disassembler project

elfparser.cpp: ELF parser can parse linux "executable" or binary files from linux.
exeparser.cpp: EXE parser can parse exe files and has the structs needed defined in the .cpp file so we can compile and run on linux
exeparser-windows.cpp: EXE parser using Windows.h if someone is on windows they can use this file to test on windows, since using windows.h the structs don't have to be defined in the cpp file

I have went through and studied the elf parser and cleaned it up
I have not went through, studied, or cleaned up the EXE parser, although I do plan to study and clean up the exeparser.cpp and then begin work on a disassembler.
