#include <iostream>
#include <fstream>
#include "PEFILE.h"

int main(int argc, char* argv[])
{
	if (argc != 2) {
		printf("Usage: %s [path to executable]\n", argv[0]);
		return 1;
	}

	FILE* PpeFile;
	fopen_s(&PpeFile, argv[1], "rb");

	if (PpeFile == NULL) {
		printf("Can't open file.\n");
		return 1;
	}

	if (INITPARSE(PpeFile) == 1) {
		exit(1);
	}
	else if (INITPARSE(PpeFile) == 32) {
		PE32FILE PeFile_1(argv[1], PpeFile);
		PeFile_1.PrintInfo();
		fclose(PpeFile);
		exit(0);
	}
	else if (INITPARSE(PpeFile) == 64) {
		PE64FILE PeFile_1(argv[1], PpeFile);
		PeFile_1.PrintInfo();
		fclose(PpeFile);
		exit(0);
	}

	return 0;
}