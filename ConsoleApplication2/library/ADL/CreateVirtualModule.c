MODULE_INFO CreateVirtualModule(const char *DllName)
{
	//get module address of the kernel32.dll
	ADDRESS *CopySource = (ADDRESS *)GetModuleAddress(DllName);

	IMAGE_DOS_HEADER DosHeader;
	MEMCOPY(&DosHeader, CopySource, sizeof(IMAGE_DOS_HEADER));

	IMAGE_NT_HEADERS NtHeader;
	MEMCOPY(&NtHeader, CopySource + DosHeader.e_lfanew, sizeof(NtHeader));

	MODULE_INFO info;
	MEMCOPY(&info.NtHeader, &NtHeader, sizeof(NtHeader));

	int distance = DosHeader.e_lfanew + sizeof(NtHeader);

	//create virtual DLL
	LPBYTE CopyCat = (LPBYTE)VirtualAlloc(NULL, NtHeader.OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	info.DllBase = CopyCat;

	//add PE FILE default information
	MEMCOPY(CopyCat, &DosHeader, sizeof(DosHeader));
	MEMCOPY(CopyCat + DosHeader.e_lfanew, &NtHeader, sizeof(NtHeader));

	for(int i = 0; i != NtHeader.FileHeader.NumberOfSections; i++)
	{
		IMAGE_SECTION_HEADER SectionHeader;
		MEMCOPY(&SectionHeader, CopySource + distance, sizeof(SectionHeader));
		
		//add section header information
		MEMCOPY(CopyCat + distance, &SectionHeader, sizeof(SectionHeader));

		//add section information
		MEMCOPY(CopyCat + SectionHeader.VirtualAddress, CopySource + SectionHeader.VirtualAddress, SectionHeader.SizeOfRawData);

		distance += sizeof(SectionHeader);
	}

	return info;
}

void FreeVirtualModule(MODULE_INFO info)
{
	VirtualFree(info.DllBase, 0, MEM_RELEASE);	
	VirtualFree(info.DllBase, info.NtHeader.OptionalHeader.SizeOfImage, MEM_DECOMMIT);
} 

MODULE_INFO CreateVirtualModuleEx(const char *DllName)
{
	HANDLE hFile = LPFN(CreateFileA)(
		DllName,
		GENERIC_READ, 
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	DWORD FileSize = GetFileSize(hFile, NULL);
	LPBYTE FileBuffer = (LPBYTE)LocalAlloc(LPTR, FileSize);
	DWORD Readed;

	BOOL ret = LPFN(ReadFile)(
		hFile, 
		FileBuffer, 
		FileSize, 
		&Readed,
		NULL);

	LPFN(CloseHandle)(hFile);


	ADDRESS *CopySource = (ADDRESS *)FileBuffer;

	IMAGE_DOS_HEADER DosHeader;
	MEMCOPY(&DosHeader, CopySource, sizeof(IMAGE_DOS_HEADER));

	IMAGE_NT_HEADERS NtHeader;
	MEMCOPY(&NtHeader, CopySource + DosHeader.e_lfanew, sizeof(NtHeader));

	MODULE_INFO info;
	MEMCOPY(&info.NtHeader, &NtHeader, sizeof(NtHeader));

	int distance = DosHeader.e_lfanew + sizeof(NtHeader);

	//create virtual DLL
	LPBYTE CopyCat = (LPBYTE)LPFN(VirtualAlloc)(
		NULL, 
		NtHeader.OptionalHeader.SizeOfImage, 
		MEM_RESERVE | MEM_COMMIT, 
		PAGE_EXECUTE_READWRITE
		);

	info.DllBase = CopyCat;

	//add PE FILE default information
	MEMCOPY(CopyCat, &DosHeader, sizeof(DosHeader));
	MEMCOPY(CopyCat + DosHeader.e_lfanew, &NtHeader, sizeof(NtHeader));

	/*
typedef struct _IMAGE_SECTION_HEADER {
    BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
            DWORD   PhysicalAddress;
            DWORD   VirtualSize;
    } Misc;
    DWORD   VirtualAddress;
    DWORD   SizeOfRawData;
    DWORD   PointerToRawData;
    DWORD   PointerToRelocations;
    DWORD   PointerToLinenumbers;
    WORD    NumberOfRelocations;
    WORD    NumberOfLinenumbers;
    DWORD   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
	*/

	for(int i = 0; i != NtHeader.FileHeader.NumberOfSections; i++)
	{
		IMAGE_SECTION_HEADER SectionHeader;
		MEMCOPY(
			&SectionHeader, 
			CopySource + distance, 
			sizeof(SectionHeader)
			);
		
		//add section header information
		MEMCOPY(
			CopyCat + distance, 
			&SectionHeader, 
			sizeof(SectionHeader)
			);
		
		//add section information
		MEMCOPY(
			CopyCat + SectionHeader.VirtualAddress, 
			CopySource + SectionHeader.PointerToRawData, 
			SectionHeader.SizeOfRawData
			);

		distance += sizeof(SectionHeader);
	}

	LocalFree(FileBuffer);

	return info;
}