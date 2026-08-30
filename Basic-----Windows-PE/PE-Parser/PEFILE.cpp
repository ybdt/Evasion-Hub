#include "PEFILE.h"

// INITIAL PARSE //

int INITPARSE(FILE* PpeFile) {
	___IMAGE_DOS_HEADER TMP_DOS_HEADER;
	WORD PEFILE_TYPE;

	fseek(PpeFile, 0, SEEK_SET);
	fread(&TMP_DOS_HEADER, sizeof(___IMAGE_DOS_HEADER), 1, PpeFile);

	if (TMP_DOS_HEADER.e_magic != ___IMAGE_DOS_SIGNATURE) {
		printf("Error. Not a PE file.\n");
		return 1;
	}

	fseek(PpeFile, (TMP_DOS_HEADER.e_lfanew + sizeof(DWORD) + sizeof(___IMAGE_FILE_HEADER)), SEEK_SET);
	fread(&PEFILE_TYPE, sizeof(WORD), 1, PpeFile);

	if (PEFILE_TYPE == ___IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		return 32;
	}
	else if (PEFILE_TYPE == ___IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		return 64;
	}
	else {
		printf("Error while parsing IMAGE_OPTIONAL_HEADER.Magic. Unknown Type.\n");
		return 1;
	}

}