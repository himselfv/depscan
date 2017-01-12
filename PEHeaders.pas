unit PEHeaders;

interface
uses Windows;

const
  IMAGE_DOS_SIGNATURE    = $5A4D; // MZ
  {$EXTERNALSYM IMAGE_DOS_SIGNATURE}
  IMAGE_OS2_SIGNATURE    = $454E; // NE
  {$EXTERNALSYM IMAGE_OS2_SIGNATURE}
  IMAGE_OS2_SIGNATURE_LE = $454C; // LE
  {$EXTERNALSYM IMAGE_OS2_SIGNATURE_LE}
  IMAGE_VXD_SIGNATURE    = $454C; // LE
  {$EXTERNALSYM IMAGE_VXD_SIGNATURE}
  IMAGE_NT_SIGNATURE     = $00004550; // PE00
  {$EXTERNALSYM IMAGE_NT_SIGNATURE}

// #include "pshpack2.h"                   // 16 bit headers are 2 byte packed

type

  // DOS .EXE header

  PIMAGE_DOS_HEADER = ^IMAGE_DOS_HEADER;
  {$EXTERNALSYM PIMAGE_DOS_HEADER}
  _IMAGE_DOS_HEADER = record
    e_magic: Word;     // Magic number
    e_cblp: Word;      // Bytes on last page of file
    e_cp: Word;        // Pages in file
    e_crlc: Word;      // Relocations
    e_cparhdr: Word;   // Size of header in paragraphs
    e_minalloc: Word;  // Minimum extra paragraphs needed
    e_maxalloc: Word;  // Maximum extra paragraphs needed
    e_ss: Word;        // Initial (relative) SS value
    e_sp: Word;        // Initial SP value
    e_csum: Word;      // Checksum
    e_ip: Word;        // Initial IP value
    e_cs: Word;        // Initial (relative) CS value
    e_lfarlc: Word;    // File address of relocation table
    e_ovno: Word;      // Overlay number
    e_res: array [0..3] of Word;    // Reserved words
    e_oemid: Word;     // OEM identifier (for e_oeminfo)
    e_oeminfo: Word;   // OEM information; e_oemid specific
    e_res2: array [0..9] of Word;  // Reserved words
    e_lfanew: Longint; // File address of new exe header
  end;
  {$EXTERNALSYM _IMAGE_DOS_HEADER}
  IMAGE_DOS_HEADER = _IMAGE_DOS_HEADER;
  {$EXTERNALSYM IMAGE_DOS_HEADER}
  TImageDosHeader = IMAGE_DOS_HEADER;
  PImageDosHeader = PIMAGE_DOS_HEADER;

  // OS/2 .EXE header

  PIMAGE_OS2_HEADER = ^IMAGE_OS2_HEADER;
  {$EXTERNALSYM PIMAGE_OS2_HEADER}
  _IMAGE_OS2_HEADER = record
    ne_magic: Word;        // Magic number
    ne_ver: CHAR;          // Version number
    ne_rev: CHAR;          // Revision number
    ne_enttab: Word;       // Offset of Entry Table
    ne_cbenttab: Word;     // Number of bytes in Entry Table
    ne_crc: Longint;       // Checksum of whole file
    ne_flags: Word;        // Flag word
    ne_autodata: Word;     // Automatic data segment number
    ne_heap: Word;         // Initial heap allocation
    ne_stack: Word;        // Initial stack allocation
    ne_csip: Longint;      // Initial CS:IP setting
    ne_sssp: Longint;      // Initial SS:SP setting
    ne_cseg: Word;         // Count of file segments
    ne_cmod: Word;         // Entries in Module Reference Table
    ne_cbnrestab: Word;    // Size of non-resident name table
    ne_segtab: Word;       // Offset of Segment Table
    ne_rsrctab: Word;      // Offset of Resource Table
    ne_restab: Word;       // Offset of resident name table
    ne_modtab: Word;       // Offset of Module Reference Table
    ne_imptab: Word;       // Offset of Imported Names Table
    ne_nrestab: Longint;   // Offset of Non-resident Names Table
    ne_cmovent: Word;      // Count of movable entries
    ne_align: Word;        // Segment alignment shift count
    ne_cres: Word;         // Count of resource segments
    ne_exetyp: Byte;       // Target Operating system
    ne_flagsothers: Byte;  // Other .EXE flags
    ne_pretthunks: Word;   // offset to return thunks
    ne_psegrefbytes: Word; // offset to segment ref. bytes
    ne_swaparea: Word;     // Minimum code swap area size
    ne_expver: Word;       // Expected Windows version number
  end;
  {$EXTERNALSYM _IMAGE_OS2_HEADER}
  IMAGE_OS2_HEADER = _IMAGE_OS2_HEADER;
  {$EXTERNALSYM IMAGE_OS2_HEADER}
  TImageOs2Header = IMAGE_OS2_HEADER;
  PImageOs2Header = PIMAGE_OS2_HEADER;

  // Windows VXD header

  PIMAGE_VXD_HEADER = ^IMAGE_VXD_HEADER;
  {$EXTERNALSYM PIMAGE_VXD_HEADER}
  _IMAGE_VXD_HEADER = record
    e32_magic: Word;         // Magic number
    e32_border: Byte;        // The byte ordering for the VXD
    e32_worder: Byte;        // The word ordering for the VXD
    e32_level: DWORD;        // The EXE format level for now = 0
    e32_cpu: Word;           // The CPU type
    e32_os: Word;            // The OS type
    e32_ver: DWORD;          // Module version
    e32_mflags: DWORD;       // Module flags
    e32_mpages: DWORD;       // Module # pages
    e32_startobj: DWORD;     // Object # for instruction pointer
    e32_eip: DWORD;          // Extended instruction pointer
    e32_stackobj: DWORD;     // Object # for stack pointer
    e32_esp: DWORD;          // Extended stack pointer
    e32_pagesize: DWORD;     // VXD page size
    e32_lastpagesize: DWORD; // Last page size in VXD
    e32_fixupsize: DWORD;    // Fixup section size
    e32_fixupsum: DWORD;     // Fixup section checksum
    e32_ldrsize: DWORD;      // Loader section size
    e32_ldrsum: DWORD;       // Loader section checksum
    e32_objtab: DWORD;       // Object table offset
    e32_objcnt: DWORD;       // Number of objects in module
    e32_objmap: DWORD;       // Object page map offset
    e32_itermap: DWORD;      // Object iterated data map offset
    e32_rsrctab: DWORD;      // Offset of Resource Table
    e32_rsrccnt: DWORD;      // Number of resource entries
    e32_restab: DWORD;       // Offset of resident name table
    e32_enttab: DWORD;       // Offset of Entry Table
    e32_dirtab: DWORD;       // Offset of Module Directive Table
    e32_dircnt: DWORD;       // Number of module directives
    e32_fpagetab: DWORD;     // Offset of Fixup Page Table
    e32_frectab: DWORD;      // Offset of Fixup Record Table
    e32_impmod: DWORD;       // Offset of Import Module Name Table
    e32_impmodcnt: DWORD;    // Number of entries in Import Module Name Table
    e32_impproc: DWORD;      // Offset of Import Procedure Name Table
    e32_pagesum: DWORD;      // Offset of Per-Page Checksum Table
    e32_datapage: DWORD;     // Offset of Enumerated Data Pages
    e32_preload: DWORD;      // Number of preload pages
    e32_nrestab: DWORD;      // Offset of Non-resident Names Table
    e32_cbnrestab: DWORD;    // Size of Non-resident Name Table
    e32_nressum: DWORD;      // Non-resident Name Table Checksum
    e32_autodata: DWORD;     // Object # for automatic data object
    e32_debuginfo: DWORD;    // Offset of the debugging information
    e32_debuglen: DWORD;     // The length of the debugging info. in bytes
    e32_instpreload: DWORD;  // Number of instance pages in preload section of VXD file
    e32_instdemand: DWORD;   // Number of instance pages in demand load section of VXD file
    e32_heapsize: DWORD;     // Size of heap - for 16-bit apps
    e32_res3: array [0..11] of Byte;      // Reserved words
    e32_winresoff: DWORD;
    e32_winreslen: DWORD;
    e32_devid: Word;         // Device ID for VxD
    e32_ddkver: Word;        // DDK version for VxD
  end;
  {$EXTERNALSYM _IMAGE_VXD_HEADER}
  IMAGE_VXD_HEADER = _IMAGE_VXD_HEADER;
  {$EXTERNALSYM IMAGE_VXD_HEADER}
  TImageVxdHeader = IMAGE_VXD_HEADER;
  PImageVxdHeader = PIMAGE_VXD_HEADER;

// #include "poppack.h"                    // Back to 4 byte packing

//
// File header format.
//

  PIMAGE_FILE_HEADER = ^IMAGE_FILE_HEADER;
  {$EXTERNALSYM PIMAGE_FILE_HEADER}
  _IMAGE_FILE_HEADER = record
    Machine: WORD;
    NumberOfSections: WORD;
    TimeDateStamp: DWORD;
    PointerToSymbolTable: DWORD;
    NumberOfSymbols: DWORD;
    SizeOfOptionalHeader: WORD;
    Characteristics: WORD;
  end;
  {$EXTERNALSYM _IMAGE_FILE_HEADER}
  IMAGE_FILE_HEADER = _IMAGE_FILE_HEADER;
  {$EXTERNALSYM IMAGE_FILE_HEADER}
  TImageFileHeader = IMAGE_FILE_HEADER;
  PImageFileHeader = PIMAGE_FILE_HEADER;

const
  IMAGE_SIZEOF_FILE_HEADER = 20;
  {$EXTERNALSYM IMAGE_SIZEOF_FILE_HEADER}

  IMAGE_FILE_RELOCS_STRIPPED         = $0001; // Relocation info stripped from file.
  {$EXTERNALSYM IMAGE_FILE_RELOCS_STRIPPED}
  IMAGE_FILE_EXECUTABLE_IMAGE        = $0002; // File is executable  (i.e. no unresolved externel references).
  {$EXTERNALSYM IMAGE_FILE_EXECUTABLE_IMAGE}
  IMAGE_FILE_LINE_NUMS_STRIPPED      = $0004; // Line nunbers stripped from file.
  {$EXTERNALSYM IMAGE_FILE_LINE_NUMS_STRIPPED}
  IMAGE_FILE_LOCAL_SYMS_STRIPPED     = $0008; // Local symbols stripped from file.
  {$EXTERNALSYM IMAGE_FILE_LOCAL_SYMS_STRIPPED}
  IMAGE_FILE_AGGRESIVE_WS_TRIM       = $0010; // Agressively trim working set
  {$EXTERNALSYM IMAGE_FILE_AGGRESIVE_WS_TRIM}
  IMAGE_FILE_LARGE_ADDRESS_AWARE     = $0020; // App can handle >2gb addresses
  {$EXTERNALSYM IMAGE_FILE_LARGE_ADDRESS_AWARE}
  IMAGE_FILE_BYTES_REVERSED_LO       = $0080; // Bytes of machine word are reversed.
  {$EXTERNALSYM IMAGE_FILE_BYTES_REVERSED_LO}
  IMAGE_FILE_32BIT_MACHINE           = $0100; // 32 bit word machine.
  {$EXTERNALSYM IMAGE_FILE_32BIT_MACHINE}
  IMAGE_FILE_DEBUG_STRIPPED          = $0200; // Debugging info stripped from file in .DBG file
  {$EXTERNALSYM IMAGE_FILE_DEBUG_STRIPPED}
  IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = $0400; // If Image is on removable media, copy and run from the swap file.
  {$EXTERNALSYM IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP}
  IMAGE_FILE_NET_RUN_FROM_SWAP       = $0800; // If Image is on Net, copy and run from the swap file.
  {$EXTERNALSYM IMAGE_FILE_NET_RUN_FROM_SWAP}
  IMAGE_FILE_SYSTEM                  = $1000; // System File.
  {$EXTERNALSYM IMAGE_FILE_SYSTEM}
  IMAGE_FILE_DLL                     = $2000; // File is a DLL.
  {$EXTERNALSYM IMAGE_FILE_DLL}
  IMAGE_FILE_UP_SYSTEM_ONLY          = $4000; // File should only be run on a UP machine
  {$EXTERNALSYM IMAGE_FILE_UP_SYSTEM_ONLY}
  IMAGE_FILE_BYTES_REVERSED_HI       = $8000; // Bytes of machine word are reversed.
  {$EXTERNALSYM IMAGE_FILE_BYTES_REVERSED_HI}

  IMAGE_FILE_MACHINE_UNKNOWN   = 0;
  {$EXTERNALSYM IMAGE_FILE_MACHINE_UNKNOWN}
  IMAGE_FILE_MACHINE_I386      = $014c; // Intel 386.
  {$EXTERNALSYM IMAGE_FILE_MACHINE_I386}
  IMAGE_FILE_MACHINE_R3000     = $0162; // MIPS little-endian, 0x160 big-endian
  {$EXTERNALSYM IMAGE_FILE_MACHINE_R3000}
  IMAGE_FILE_MACHINE_R4000     = $0166; // MIPS little-endian
  {$EXTERNALSYM IMAGE_FILE_MACHINE_R4000}
  IMAGE_FILE_MACHINE_R10000    = $0168; // MIPS little-endian
  {$EXTERNALSYM IMAGE_FILE_MACHINE_R10000}
  IMAGE_FILE_MACHINE_WCEMIPSV2 = $0169; // MIPS little-endian WCE v2
  {$EXTERNALSYM IMAGE_FILE_MACHINE_WCEMIPSV2}
  IMAGE_FILE_MACHINE_ALPHA     = $0184; // Alpha_AXP
  {$EXTERNALSYM IMAGE_FILE_MACHINE_ALPHA}
  IMAGE_FILE_MACHINE_SH3       = $01a2; // SH3 little-endian
  {$EXTERNALSYM IMAGE_FILE_MACHINE_SH3}
  IMAGE_FILE_MACHINE_SH3DSP    = $01a3;
  {$EXTERNALSYM IMAGE_FILE_MACHINE_SH3DSP}
  IMAGE_FILE_MACHINE_SH3E      = $01a4; // SH3E little-endian
  {$EXTERNALSYM IMAGE_FILE_MACHINE_SH3E}
  IMAGE_FILE_MACHINE_SH4       = $01a6; // SH4 little-endian
  {$EXTERNALSYM IMAGE_FILE_MACHINE_SH4}
  IMAGE_FILE_MACHINE_SH5       = $01a8; // SH5
  {$EXTERNALSYM IMAGE_FILE_MACHINE_SH5}
  IMAGE_FILE_MACHINE_ARM       = $01c0; // ARM Little-Endian
  {$EXTERNALSYM IMAGE_FILE_MACHINE_ARM}
  IMAGE_FILE_MACHINE_THUMB     = $01c2;
  {$EXTERNALSYM IMAGE_FILE_MACHINE_THUMB}
  IMAGE_FILE_MACHINE_AM33      = $01d3;
  {$EXTERNALSYM IMAGE_FILE_MACHINE_AM33}
  IMAGE_FILE_MACHINE_POWERPC   = $01F0; // IBM PowerPC Little-Endian
  {$EXTERNALSYM IMAGE_FILE_MACHINE_POWERPC}
  IMAGE_FILE_MACHINE_POWERPCFP = $01f1;
  {$EXTERNALSYM IMAGE_FILE_MACHINE_POWERPCFP}
  IMAGE_FILE_MACHINE_IA64      = $0200; // Intel 64
  {$EXTERNALSYM IMAGE_FILE_MACHINE_IA64}
  IMAGE_FILE_MACHINE_MIPS16    = $0266; // MIPS
  {$EXTERNALSYM IMAGE_FILE_MACHINE_MIPS16}
  IMAGE_FILE_MACHINE_ALPHA64   = $0284; // ALPHA64
  {$EXTERNALSYM IMAGE_FILE_MACHINE_ALPHA64}
  IMAGE_FILE_MACHINE_MIPSFPU   = $0366; // MIPS
  {$EXTERNALSYM IMAGE_FILE_MACHINE_MIPSFPU}
  IMAGE_FILE_MACHINE_MIPSFPU16 = $0466; // MIPS
  {$EXTERNALSYM IMAGE_FILE_MACHINE_MIPSFPU16}
  IMAGE_FILE_MACHINE_AXP64     = IMAGE_FILE_MACHINE_ALPHA64;
  {$EXTERNALSYM IMAGE_FILE_MACHINE_AXP64}
  IMAGE_FILE_MACHINE_TRICORE   = $0520; // Infineon
  {$EXTERNALSYM IMAGE_FILE_MACHINE_TRICORE}
  IMAGE_FILE_MACHINE_CEF       = $0CEF;
  {$EXTERNALSYM IMAGE_FILE_MACHINE_CEF}
  IMAGE_FILE_MACHINE_EBC       = $0EBC; // EFI Byte Code
  {$EXTERNALSYM IMAGE_FILE_MACHINE_EBC}
  IMAGE_FILE_MACHINE_AMD64     = $8664; // AMD64 (K8)
  {$EXTERNALSYM IMAGE_FILE_MACHINE_AMD64}
  IMAGE_FILE_MACHINE_M32R      = $9041; // M32R little-endian
  {$EXTERNALSYM IMAGE_FILE_MACHINE_M32R}
  IMAGE_FILE_MACHINE_CEE       = $C0EE;
  {$EXTERNALSYM IMAGE_FILE_MACHINE_CEE}

//
// Directory format.
//

type
  PIMAGE_DATA_DIRECTORY = ^IMAGE_DATA_DIRECTORY;
  {$EXTERNALSYM PIMAGE_DATA_DIRECTORY}
  _IMAGE_DATA_DIRECTORY = record
    VirtualAddress: DWORD;
    Size: DWORD;
  end;
  {$EXTERNALSYM _IMAGE_DATA_DIRECTORY}
  IMAGE_DATA_DIRECTORY = _IMAGE_DATA_DIRECTORY;
  {$EXTERNALSYM IMAGE_DATA_DIRECTORY}
  TImageDataDirectory = IMAGE_DATA_DIRECTORY;
  PImageDataDirectory = PIMAGE_DATA_DIRECTORY;

const
  IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16;
  {$EXTERNALSYM IMAGE_NUMBEROF_DIRECTORY_ENTRIES}

//
// Optional header format.
//

type
  PIMAGE_OPTIONAL_HEADER32 = ^IMAGE_OPTIONAL_HEADER32;
  {$EXTERNALSYM PIMAGE_OPTIONAL_HEADER32}
  _IMAGE_OPTIONAL_HEADER = record
    //
    // Standard fields.
    //
    Magic: Word;
    MajorLinkerVersion: Byte;
    MinorLinkerVersion: Byte;
    SizeOfCode: DWORD;
    SizeOfInitializedData: DWORD;
    SizeOfUninitializedData: DWORD;
    AddressOfEntryPoint: DWORD;
    BaseOfCode: DWORD;
    BaseOfData: DWORD;
    //
    // NT additional fields.
    //
    ImageBase: DWORD;
    SectionAlignment: DWORD;
    FileAlignment: DWORD;
    MajorOperatingSystemVersion: Word;
    MinorOperatingSystemVersion: Word;
    MajorImageVersion: Word;
    MinorImageVersion: Word;
    MajorSubsystemVersion: Word;
    MinorSubsystemVersion: Word;
    Win32VersionValue: DWORD;
    SizeOfImage: DWORD;
    SizeOfHeaders: DWORD;
    CheckSum: DWORD;
    Subsystem: Word;
    DllCharacteristics: Word;
    SizeOfStackReserve: DWORD;
    SizeOfStackCommit: DWORD;
    SizeOfHeapReserve: DWORD;
    SizeOfHeapCommit: DWORD;
    LoaderFlags: DWORD;
    NumberOfRvaAndSizes: DWORD;
    DataDirectory: array [0..IMAGE_NUMBEROF_DIRECTORY_ENTRIES - 1] of IMAGE_DATA_DIRECTORY;
  end;
  {$EXTERNALSYM _IMAGE_OPTIONAL_HEADER}
  IMAGE_OPTIONAL_HEADER32 = _IMAGE_OPTIONAL_HEADER;
  {$EXTERNALSYM IMAGE_OPTIONAL_HEADER32}
  TImageOptionalHeader32 = IMAGE_OPTIONAL_HEADER32;
  PImageOptionalHeader32 = PIMAGE_OPTIONAL_HEADER32;

  PIMAGE_ROM_OPTIONAL_HEADER = ^IMAGE_ROM_OPTIONAL_HEADER;
  {$EXTERNALSYM PIMAGE_ROM_OPTIONAL_HEADER}
  _IMAGE_ROM_OPTIONAL_HEADER = record
    Magic: Word;
    MajorLinkerVersion: Byte;
    MinorLinkerVersion: Byte;
    SizeOfCode: DWORD;
    SizeOfInitializedData: DWORD;
    SizeOfUninitializedData: DWORD;
    AddressOfEntryPoint: DWORD;
    BaseOfCode: DWORD;
    BaseOfData: DWORD;
    BaseOfBss: DWORD;
    GprMask: DWORD;
    CprMask: array [0..3] of DWORD;
    GpValue: DWORD;
  end;
  {$EXTERNALSYM _IMAGE_ROM_OPTIONAL_HEADER}
  IMAGE_ROM_OPTIONAL_HEADER = _IMAGE_ROM_OPTIONAL_HEADER;
  {$EXTERNALSYM IMAGE_ROM_OPTIONAL_HEADER}
  TImageRomOptionalHeader = IMAGE_ROM_OPTIONAL_HEADER;
  PImageRomOptionalHeader = PIMAGE_ROM_OPTIONAL_HEADER;

  PIMAGE_OPTIONAL_HEADER64 = ^IMAGE_OPTIONAL_HEADER64;
  {$EXTERNALSYM PIMAGE_OPTIONAL_HEADER64}
  _IMAGE_OPTIONAL_HEADER64 = record
    Magic: Word;
    MajorLinkerVersion: Byte;
    MinorLinkerVersion: Byte;
    SizeOfCode: DWORD;
    SizeOfInitializedData: DWORD;
    SizeOfUninitializedData: DWORD;
    AddressOfEntryPoint: DWORD;
    BaseOfCode: DWORD;
    ImageBase: Int64;
    SectionAlignment: DWORD;
    FileAlignment: DWORD;
    MajorOperatingSystemVersion: Word;
    MinorOperatingSystemVersion: Word;
    MajorImageVersion: Word;
    MinorImageVersion: Word;
    MajorSubsystemVersion: Word;
    MinorSubsystemVersion: Word;
    Win32VersionValue: DWORD;
    SizeOfImage: DWORD;
    SizeOfHeaders: DWORD;
    CheckSum: DWORD;
    Subsystem: Word;
    DllCharacteristics: Word;
    SizeOfStackReserve: Int64;
    SizeOfStackCommit: Int64;
    SizeOfHeapReserve: Int64;
    SizeOfHeapCommit: Int64;
    LoaderFlags: DWORD;
    NumberOfRvaAndSizes: DWORD;
    DataDirectory: array [0..IMAGE_NUMBEROF_DIRECTORY_ENTRIES - 1] of IMAGE_DATA_DIRECTORY;
  end;
  {$EXTERNALSYM _IMAGE_OPTIONAL_HEADER64}
  IMAGE_OPTIONAL_HEADER64 = _IMAGE_OPTIONAL_HEADER64;
  {$EXTERNALSYM IMAGE_OPTIONAL_HEADER64}
  TImageOptionalHeader64 = IMAGE_OPTIONAL_HEADER64;
  PImageOptionalHeader64 = PIMAGE_OPTIONAL_HEADER64;

const
  IMAGE_SIZEOF_ROM_OPTIONAL_HEADER  = 56;
  {$EXTERNALSYM IMAGE_SIZEOF_ROM_OPTIONAL_HEADER}
  IMAGE_SIZEOF_STD_OPTIONAL_HEADER  = 28;
  {$EXTERNALSYM IMAGE_SIZEOF_STD_OPTIONAL_HEADER}
  IMAGE_SIZEOF_NT_OPTIONAL32_HEADER = 224;
  {$EXTERNALSYM IMAGE_SIZEOF_NT_OPTIONAL32_HEADER}
  IMAGE_SIZEOF_NT_OPTIONAL64_HEADER = 240;
  {$EXTERNALSYM IMAGE_SIZEOF_NT_OPTIONAL64_HEADER}

  IMAGE_NT_OPTIONAL_HDR32_MAGIC = $10b;
  {$EXTERNALSYM IMAGE_NT_OPTIONAL_HDR32_MAGIC}
  IMAGE_NT_OPTIONAL_HDR64_MAGIC = $20b;
  {$EXTERNALSYM IMAGE_NT_OPTIONAL_HDR64_MAGIC}
  IMAGE_ROM_OPTIONAL_HDR_MAGIC  = $107;
  {$EXTERNALSYM IMAGE_ROM_OPTIONAL_HDR_MAGIC}

type
  IMAGE_OPTIONAL_HEADER = IMAGE_OPTIONAL_HEADER32;
  {$EXTERNALSYM IMAGE_OPTIONAL_HEADER}
  PIMAGE_OPTIONAL_HEADER = PIMAGE_OPTIONAL_HEADER32;
  {$EXTERNALSYM PIMAGE_OPTIONAL_HEADER}

const
  IMAGE_SIZEOF_NT_OPTIONAL_HEADER = IMAGE_SIZEOF_NT_OPTIONAL32_HEADER;
  {$EXTERNALSYM IMAGE_SIZEOF_NT_OPTIONAL_HEADER}
  IMAGE_NT_OPTIONAL_HDR_MAGIC     = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
  {$EXTERNALSYM IMAGE_NT_OPTIONAL_HDR_MAGIC}

type
  PIMAGE_NT_HEADERS64 = ^IMAGE_NT_HEADERS64;
  {$EXTERNALSYM PIMAGE_NT_HEADERS64}
  _IMAGE_NT_HEADERS64 = record
    Signature: DWORD;
    FileHeader: IMAGE_FILE_HEADER;
    OptionalHeader: IMAGE_OPTIONAL_HEADER64;
  end;
  {$EXTERNALSYM _IMAGE_NT_HEADERS64}
  IMAGE_NT_HEADERS64 = _IMAGE_NT_HEADERS64;
  {$EXTERNALSYM IMAGE_NT_HEADERS64}
  TImageNtHeaders64 = IMAGE_NT_HEADERS64;
  PImageNtHeaders64 = PIMAGE_NT_HEADERS64;

  PIMAGE_NT_HEADERS32 = ^IMAGE_NT_HEADERS32;
  {$EXTERNALSYM PIMAGE_NT_HEADERS32}
  _IMAGE_NT_HEADERS = record
    Signature: DWORD;
    FileHeader: IMAGE_FILE_HEADER;
    OptionalHeader: IMAGE_OPTIONAL_HEADER32;
  end;
  {$EXTERNALSYM _IMAGE_NT_HEADERS}
  IMAGE_NT_HEADERS32 = _IMAGE_NT_HEADERS;
  {$EXTERNALSYM IMAGE_NT_HEADERS32}
  TImageNtHeaders32 = IMAGE_NT_HEADERS32;
  PImageNtHeaders32 = PIMAGE_NT_HEADERS32;

  PIMAGE_ROM_HEADERS = ^IMAGE_ROM_HEADERS;
  {$EXTERNALSYM PIMAGE_ROM_HEADERS}
  _IMAGE_ROM_HEADERS = record
    FileHeader: IMAGE_FILE_HEADER;
    OptionalHeader: IMAGE_ROM_OPTIONAL_HEADER;
  end;
  {$EXTERNALSYM _IMAGE_ROM_HEADERS}
  IMAGE_ROM_HEADERS = _IMAGE_ROM_HEADERS;
  {$EXTERNALSYM IMAGE_ROM_HEADERS}
  TImageRomHeaders = IMAGE_ROM_HEADERS;
  PImageRomHeaders = PIMAGE_ROM_HEADERS;

  IMAGE_NT_HEADERS = IMAGE_NT_HEADERS32;
  {$EXTERNALSYM IMAGE_NT_HEADERS}
  PIMAGE_NT_HEADERS = PIMAGE_NT_HEADERS32;
  {$EXTERNALSYM PIMAGE_NT_HEADERS}

// Subsystem Values

const
  IMAGE_SUBSYSTEM_UNKNOWN                 = 0; // Unknown subsystem.
  {$EXTERNALSYM IMAGE_SUBSYSTEM_UNKNOWN}
  IMAGE_SUBSYSTEM_NATIVE                  = 1; // Image doesn't require a subsystem.
  {$EXTERNALSYM IMAGE_SUBSYSTEM_NATIVE}
  IMAGE_SUBSYSTEM_WINDOWS_GUI             = 2; // Image runs in the Windows GUI subsystem.
  {$EXTERNALSYM IMAGE_SUBSYSTEM_WINDOWS_GUI}
  IMAGE_SUBSYSTEM_WINDOWS_CUI             = 3; // Image runs in the Windows character subsystem.
  {$EXTERNALSYM IMAGE_SUBSYSTEM_WINDOWS_CUI}
  IMAGE_SUBSYSTEM_OS2_CUI                 = 5; // image runs in the OS/2 character subsystem.
  {$EXTERNALSYM IMAGE_SUBSYSTEM_OS2_CUI}
  IMAGE_SUBSYSTEM_POSIX_CUI               = 7; // image runs in the Posix character subsystem.
  {$EXTERNALSYM IMAGE_SUBSYSTEM_POSIX_CUI}
  IMAGE_SUBSYSTEM_NATIVE_WINDOWS          = 8; // image is a native Win9x driver.
  {$EXTERNALSYM IMAGE_SUBSYSTEM_NATIVE_WINDOWS}
  IMAGE_SUBSYSTEM_WINDOWS_CE_GUI          = 9; // Image runs in the Windows CE subsystem.
  {$EXTERNALSYM IMAGE_SUBSYSTEM_WINDOWS_CE_GUI}
  IMAGE_SUBSYSTEM_EFI_APPLICATION         = 10;
  {$EXTERNALSYM IMAGE_SUBSYSTEM_EFI_APPLICATION}
  IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11;
  {$EXTERNALSYM IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER}
  IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER      = 12;
  {$EXTERNALSYM IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER}
  IMAGE_SUBSYSTEM_EFI_ROM                 = 13;
  {$EXTERNALSYM IMAGE_SUBSYSTEM_EFI_ROM}
  IMAGE_SUBSYSTEM_XBOX                    = 14;
  {$EXTERNALSYM IMAGE_SUBSYSTEM_XBOX}

// DllCharacteristics Entries

//      IMAGE_LIBRARY_PROCESS_INIT           0x0001     // Reserved.
//      IMAGE_LIBRARY_PROCESS_TERM           0x0002     // Reserved.
//      IMAGE_LIBRARY_THREAD_INIT            0x0004     // Reserved.
//      IMAGE_LIBRARY_THREAD_TERM            0x0008     // Reserved.

  IMAGE_DLLCHARACTERISTICS_NO_BIND = $0800; // Do not bind this image.
  {$EXTERNALSYM IMAGE_DLLCHARACTERISTICS_NO_BIND}

//                                           0x1000     // Reserved.

  IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = $2000; // Driver uses WDM model
  {$EXTERNALSYM IMAGE_DLLCHARACTERISTICS_WDM_DRIVER}

//                                           0x4000     // Reserved.

  IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = $8000;
  {$EXTERNALSYM IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE}

// Directory Entries

  IMAGE_DIRECTORY_ENTRY_EXPORT    = 0; // Export Directory
  {$EXTERNALSYM IMAGE_DIRECTORY_ENTRY_EXPORT}
  IMAGE_DIRECTORY_ENTRY_IMPORT    = 1; // Import Directory
  {$EXTERNALSYM IMAGE_DIRECTORY_ENTRY_IMPORT}
  IMAGE_DIRECTORY_ENTRY_RESOURCE  = 2; // Resource Directory
  {$EXTERNALSYM IMAGE_DIRECTORY_ENTRY_RESOURCE}
  IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3; // Exception Directory
  {$EXTERNALSYM IMAGE_DIRECTORY_ENTRY_EXCEPTION}
  IMAGE_DIRECTORY_ENTRY_SECURITY  = 4; // Security Directory
  {$EXTERNALSYM IMAGE_DIRECTORY_ENTRY_SECURITY}
  IMAGE_DIRECTORY_ENTRY_BASERELOC = 5; // Base Relocation Table
  {$EXTERNALSYM IMAGE_DIRECTORY_ENTRY_BASERELOC}
  IMAGE_DIRECTORY_ENTRY_DEBUG     = 6; // Debug Directory
  {$EXTERNALSYM IMAGE_DIRECTORY_ENTRY_DEBUG}

//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)

  IMAGE_DIRECTORY_ENTRY_ARCHITECTURE   = 7; // Architecture Specific Data
  {$EXTERNALSYM IMAGE_DIRECTORY_ENTRY_ARCHITECTURE}
  IMAGE_DIRECTORY_ENTRY_GLOBALPTR      = 8; // RVA of GP
  {$EXTERNALSYM IMAGE_DIRECTORY_ENTRY_GLOBALPTR}
  IMAGE_DIRECTORY_ENTRY_TLS            = 9; // TLS Directory
  {$EXTERNALSYM IMAGE_DIRECTORY_ENTRY_TLS}
  IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    = 10; // Load Configuration Directory
  {$EXTERNALSYM IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG}
  IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   = 11; // Bound Import Directory in headers
  {$EXTERNALSYM IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT}
  IMAGE_DIRECTORY_ENTRY_IAT            = 12; // Import Address Table
  {$EXTERNALSYM IMAGE_DIRECTORY_ENTRY_IAT}
  IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   = 13; // Delay Load Import Descriptors
  {$EXTERNALSYM IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT}
  IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14; // COM Runtime descriptor
  {$EXTERNALSYM IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR}

//
// Non-COFF Object file header
//

type
  PAnonObjectHeader = ^ANON_OBJECT_HEADER;
  ANON_OBJECT_HEADER = record
    Sig1: Word;        // Must be IMAGE_FILE_MACHINE_UNKNOWN
    Sig2: Word;        // Must be 0xffff
    Version: Word;     // >= 1 (implies the CLSID field is present)
    Machine: Word;
    TimeDateStamp: DWORD;
    ClassID: TGUID;    // Used to invoke CoCreateInstance
    SizeOfData: DWORD; // Size of data that follows the header
  end;
  {$EXTERNALSYM ANON_OBJECT_HEADER}
  TAnonObjectHeader = ANON_OBJECT_HEADER;

//
// Section header format.
//

const
  IMAGE_SIZEOF_SHORT_NAME = 8;
  {$EXTERNALSYM IMAGE_SIZEOF_SHORT_NAME}

type
  TImgSecHdrMisc = record
    case Integer of
      0: (PhysicalAddress: DWORD);
      1: (VirtualSize: DWORD);
  end;

  PIMAGE_SECTION_HEADER = ^IMAGE_SECTION_HEADER;
  {$EXTERNALSYM PIMAGE_SECTION_HEADER}
  _IMAGE_SECTION_HEADER = record
    Name: array [0..IMAGE_SIZEOF_SHORT_NAME - 1] of BYTE;
    Misc: TImgSecHdrMisc;
    VirtualAddress: DWORD;
    SizeOfRawData: DWORD;
    PointerToRawData: DWORD;
    PointerToRelocations: DWORD;
    PointerToLinenumbers: DWORD;
    NumberOfRelocations: WORD;
    NumberOfLinenumbers: WORD;
    Characteristics: DWORD;
  end;
  {$EXTERNALSYM _IMAGE_SECTION_HEADER}
  IMAGE_SECTION_HEADER = _IMAGE_SECTION_HEADER;
  {$EXTERNALSYM IMAGE_SECTION_HEADER}
  TImageSectionHeader = IMAGE_SECTION_HEADER;
  PImageSectionHeader = PIMAGE_SECTION_HEADER;

const
  IMAGE_SIZEOF_SECTION_HEADER = 40;
  {$EXTERNALSYM IMAGE_SIZEOF_SECTION_HEADER}

//
// Section characteristics.
//
//      IMAGE_SCN_TYPE_REG                   0x00000000  // Reserved.
//      IMAGE_SCN_TYPE_DSECT                 0x00000001  // Reserved.
//      IMAGE_SCN_TYPE_NOLOAD                0x00000002  // Reserved.
//      IMAGE_SCN_TYPE_GROUP                 0x00000004  // Reserved.

  IMAGE_SCN_TYPE_NO_PAD = $00000008; // Reserved.
  {$EXTERNALSYM IMAGE_SCN_TYPE_NO_PAD}

//      IMAGE_SCN_TYPE_COPY                  0x00000010  // Reserved.

  IMAGE_SCN_CNT_CODE               = $00000020; // Section contains code.
  {$EXTERNALSYM IMAGE_SCN_CNT_CODE}
  IMAGE_SCN_CNT_INITIALIZED_DATA   = $00000040; // Section contains initialized data.
  {$EXTERNALSYM IMAGE_SCN_CNT_INITIALIZED_DATA}
  IMAGE_SCN_CNT_UNINITIALIZED_DATA = $00000080; // Section contains uninitialized data.
  {$EXTERNALSYM IMAGE_SCN_CNT_UNINITIALIZED_DATA}

  IMAGE_SCN_LNK_OTHER = $00000100; // Reserved.
  {$EXTERNALSYM IMAGE_SCN_LNK_OTHER}
  IMAGE_SCN_LNK_INFO  = $00000200; // Section contains comments or some other type of information.
  {$EXTERNALSYM IMAGE_SCN_LNK_INFO}

//      IMAGE_SCN_TYPE_OVER                  0x00000400  // Reserved.

  IMAGE_SCN_LNK_REMOVE = $00000800; // Section contents will not become part of image.
  {$EXTERNALSYM IMAGE_SCN_LNK_REMOVE}
  IMAGE_SCN_LNK_COMDAT = $00001000; // Section contents comdat.
  {$EXTERNALSYM IMAGE_SCN_LNK_COMDAT}

//                                           0x00002000  // Reserved.
//      IMAGE_SCN_MEM_PROTECTED - Obsolete   0x00004000

  IMAGE_SCN_NO_DEFER_SPEC_EXC = $00004000; // Reset speculative exceptions handling bits in the TLB entries for this section.
  {$EXTERNALSYM IMAGE_SCN_NO_DEFER_SPEC_EXC}
  IMAGE_SCN_GPREL             = $00008000; // Section content can be accessed relative to GP
  {$EXTERNALSYM IMAGE_SCN_GPREL}
  IMAGE_SCN_MEM_FARDATA       = $00008000;
  {$EXTERNALSYM IMAGE_SCN_MEM_FARDATA}

//      IMAGE_SCN_MEM_SYSHEAP  - Obsolete    0x00010000

  IMAGE_SCN_MEM_PURGEABLE = $00020000;
  {$EXTERNALSYM IMAGE_SCN_MEM_PURGEABLE}
  IMAGE_SCN_MEM_16BIT     = $00020000;
  {$EXTERNALSYM IMAGE_SCN_MEM_16BIT}
  IMAGE_SCN_MEM_LOCKED    = $00040000;
  {$EXTERNALSYM IMAGE_SCN_MEM_LOCKED}
  IMAGE_SCN_MEM_PRELOAD   = $00080000;
  {$EXTERNALSYM IMAGE_SCN_MEM_PRELOAD}

  IMAGE_SCN_ALIGN_1BYTES    = $00100000;
  {$EXTERNALSYM IMAGE_SCN_ALIGN_1BYTES}
  IMAGE_SCN_ALIGN_2BYTES    = $00200000;
  {$EXTERNALSYM IMAGE_SCN_ALIGN_2BYTES}
  IMAGE_SCN_ALIGN_4BYTES    = $00300000;
  {$EXTERNALSYM IMAGE_SCN_ALIGN_4BYTES}
  IMAGE_SCN_ALIGN_8BYTES    = $00400000;
  {$EXTERNALSYM IMAGE_SCN_ALIGN_8BYTES}
  IMAGE_SCN_ALIGN_16BYTES   = $00500000; // Default alignment if no others are specified.
  {$EXTERNALSYM IMAGE_SCN_ALIGN_16BYTES}
  IMAGE_SCN_ALIGN_32BYTES   = $00600000;
  {$EXTERNALSYM IMAGE_SCN_ALIGN_32BYTES}
  IMAGE_SCN_ALIGN_64BYTES   = $00700000;
  {$EXTERNALSYM IMAGE_SCN_ALIGN_64BYTES}
  IMAGE_SCN_ALIGN_128BYTES  = $00800000;
  {$EXTERNALSYM IMAGE_SCN_ALIGN_128BYTES}
  IMAGE_SCN_ALIGN_256BYTES  = $00900000;
  {$EXTERNALSYM IMAGE_SCN_ALIGN_256BYTES}
  IMAGE_SCN_ALIGN_512BYTES  = $00A00000;
  {$EXTERNALSYM IMAGE_SCN_ALIGN_512BYTES}
  IMAGE_SCN_ALIGN_1024BYTES = $00B00000;
  {$EXTERNALSYM IMAGE_SCN_ALIGN_1024BYTES}
  IMAGE_SCN_ALIGN_2048BYTES = $00C00000;
  {$EXTERNALSYM IMAGE_SCN_ALIGN_2048BYTES}
  IMAGE_SCN_ALIGN_4096BYTES = $00D00000;
  {$EXTERNALSYM IMAGE_SCN_ALIGN_4096BYTES}
  IMAGE_SCN_ALIGN_8192BYTES = $00E00000;
  {$EXTERNALSYM IMAGE_SCN_ALIGN_8192BYTES}

// Unused                                    0x00F00000

  IMAGE_SCN_ALIGN_MASK = $00F00000;
  {$EXTERNALSYM IMAGE_SCN_ALIGN_MASK}

  IMAGE_SCN_LNK_NRELOC_OVFL = $01000000; // Section contains extended relocations.
  {$EXTERNALSYM IMAGE_SCN_LNK_NRELOC_OVFL}
  IMAGE_SCN_MEM_DISCARDABLE = $02000000; // Section can be discarded.
  {$EXTERNALSYM IMAGE_SCN_MEM_DISCARDABLE}
  IMAGE_SCN_MEM_NOT_CACHED  = $04000000; // Section is not cachable.
  {$EXTERNALSYM IMAGE_SCN_MEM_NOT_CACHED}
  IMAGE_SCN_MEM_NOT_PAGED   = $08000000; // Section is not pageable.
  {$EXTERNALSYM IMAGE_SCN_MEM_NOT_PAGED}
  IMAGE_SCN_MEM_SHARED      = $10000000; // Section is shareable.
  {$EXTERNALSYM IMAGE_SCN_MEM_SHARED}
  IMAGE_SCN_MEM_EXECUTE     = $20000000; // Section is executable.
  {$EXTERNALSYM IMAGE_SCN_MEM_EXECUTE}
  IMAGE_SCN_MEM_READ        = $40000000; // Section is readable.
  {$EXTERNALSYM IMAGE_SCN_MEM_READ}
  IMAGE_SCN_MEM_WRITE       = DWORD($80000000); // Section is writeable.
  {$EXTERNALSYM IMAGE_SCN_MEM_WRITE}

//
// TLS Chaacteristic Flags
//

  IMAGE_SCN_SCALE_INDEX = $00000001; // Tls index is scaled
  {$EXTERNALSYM IMAGE_SCN_SCALE_INDEX}

// #include "pshpack2.h"                       // Symbols, relocs, and linenumbers are 2 byte packed

//
// Symbol format.
//

type
  TImageSymbolN = record
    case Integer of
      0: (
        ShortName: array [0..7] of BYTE);
      1: (
        Short: DWORD;     // if 0, use LongName
        Long: DWORD);     // offset into string table
      2: (
        LongName: array [0..1] of DWORD);
  end;

  PIMAGE_SYMBOL = ^IMAGE_SYMBOL;
  {$EXTERNALSYM PIMAGE_SYMBOL}
  _IMAGE_SYMBOL = record
    N: TImageSymbolN;
    Value: DWORD;
    SectionNumber: SHORT;
    Type_: WORD;
    StorageClass: BYTE;
    NumberOfAuxSymbols: BYTE;
  end;
  {$EXTERNALSYM _IMAGE_SYMBOL}
  IMAGE_SYMBOL = _IMAGE_SYMBOL;
  {$EXTERNALSYM IMAGE_SYMBOL}
  TImageSymbol = IMAGE_SYMBOL;
  PImageSymbol = PIMAGE_SYMBOL;

const
  IMAGE_SIZEOF_SYMBOL = 18;
  {$EXTERNALSYM IMAGE_SIZEOF_SYMBOL}

//
// Section values.
//
// Symbols have a section number of the section in which they are
// defined. Otherwise, section numbers have the following meanings:
//

  IMAGE_SYM_UNDEFINED = SHORT(0);  // Symbol is undefined or is common.
  {$EXTERNALSYM IMAGE_SYM_UNDEFINED}
  IMAGE_SYM_ABSOLUTE  = SHORT(-1); // Symbol is an absolute value.
  {$EXTERNALSYM IMAGE_SYM_ABSOLUTE}
  IMAGE_SYM_DEBUG     = SHORT(-2); // Symbol is a special debug item.
  {$EXTERNALSYM IMAGE_SYM_DEBUG}
  IMAGE_SYM_SECTION_MAX = SHORT($FEFF ); // Values 0xFF00-0xFFFF are special
  {$EXTERNALSYM IMAGE_SYM_SECTION_MAX}

//
// Type (fundamental) values.
//

  IMAGE_SYM_TYPE_NULL   = $0000; // no type.
  {$EXTERNALSYM IMAGE_SYM_TYPE_NULL}
  IMAGE_SYM_TYPE_VOID   = $0001;
  {$EXTERNALSYM IMAGE_SYM_TYPE_VOID}
  IMAGE_SYM_TYPE_CHAR   = $0002; // type character.
  {$EXTERNALSYM IMAGE_SYM_TYPE_CHAR}
  IMAGE_SYM_TYPE_SHORT  = $0003; // type short integer.
  {$EXTERNALSYM IMAGE_SYM_TYPE_SHORT}
  IMAGE_SYM_TYPE_INT    = $0004;
  {$EXTERNALSYM IMAGE_SYM_TYPE_INT}
  IMAGE_SYM_TYPE_LONG   = $0005;
  {$EXTERNALSYM IMAGE_SYM_TYPE_LONG}
  IMAGE_SYM_TYPE_FLOAT  = $0006;
  {$EXTERNALSYM IMAGE_SYM_TYPE_FLOAT}
  IMAGE_SYM_TYPE_DOUBLE = $0007;
  {$EXTERNALSYM IMAGE_SYM_TYPE_DOUBLE}
  IMAGE_SYM_TYPE_STRUCT = $0008;
  {$EXTERNALSYM IMAGE_SYM_TYPE_STRUCT}
  IMAGE_SYM_TYPE_UNION  = $0009;
  {$EXTERNALSYM IMAGE_SYM_TYPE_UNION}
  IMAGE_SYM_TYPE_ENUM   = $000A; // enumeration.
  {$EXTERNALSYM IMAGE_SYM_TYPE_ENUM}
  IMAGE_SYM_TYPE_MOE    = $000B; // member of enumeration.
  {$EXTERNALSYM IMAGE_SYM_TYPE_MOE}
  IMAGE_SYM_TYPE_BYTE   = $000C;
  {$EXTERNALSYM IMAGE_SYM_TYPE_BYTE}
  IMAGE_SYM_TYPE_WORD   = $000D;
  {$EXTERNALSYM IMAGE_SYM_TYPE_WORD}
  IMAGE_SYM_TYPE_UINT   = $000E;
  {$EXTERNALSYM IMAGE_SYM_TYPE_UINT}
  IMAGE_SYM_TYPE_DWORD  = $000F;
  {$EXTERNALSYM IMAGE_SYM_TYPE_DWORD}
  IMAGE_SYM_TYPE_PCODE  = $8000;
  {$EXTERNALSYM IMAGE_SYM_TYPE_PCODE}

//
// Type (derived) values.
//

  IMAGE_SYM_DTYPE_NULL     = 0; // no derived type.
  {$EXTERNALSYM IMAGE_SYM_DTYPE_NULL}
  IMAGE_SYM_DTYPE_POINTER  = 1; // pointer.
  {$EXTERNALSYM IMAGE_SYM_DTYPE_POINTER}
  IMAGE_SYM_DTYPE_FUNCTION = 2; // function.
  {$EXTERNALSYM IMAGE_SYM_DTYPE_FUNCTION}
  IMAGE_SYM_DTYPE_ARRAY    = 3; // array.
  {$EXTERNALSYM IMAGE_SYM_DTYPE_ARRAY}

//
// Storage classes.
//

  IMAGE_SYM_CLASS_END_OF_FUNCTION  = BYTE(-1);
  {$EXTERNALSYM IMAGE_SYM_CLASS_END_OF_FUNCTION}
  IMAGE_SYM_CLASS_NULL             = $0000;
  {$EXTERNALSYM IMAGE_SYM_CLASS_NULL}
  IMAGE_SYM_CLASS_AUTOMATIC        = $0001;
  {$EXTERNALSYM IMAGE_SYM_CLASS_AUTOMATIC}
  IMAGE_SYM_CLASS_EXTERNAL         = $0002;
  {$EXTERNALSYM IMAGE_SYM_CLASS_EXTERNAL}
  IMAGE_SYM_CLASS_STATIC           = $0003;
  {$EXTERNALSYM IMAGE_SYM_CLASS_STATIC}
  IMAGE_SYM_CLASS_REGISTER         = $0004;
  {$EXTERNALSYM IMAGE_SYM_CLASS_REGISTER}
  IMAGE_SYM_CLASS_EXTERNAL_DEF     = $0005;
  {$EXTERNALSYM IMAGE_SYM_CLASS_EXTERNAL_DEF}
  IMAGE_SYM_CLASS_LABEL            = $0006;
  {$EXTERNALSYM IMAGE_SYM_CLASS_LABEL}
  IMAGE_SYM_CLASS_UNDEFINED_LABEL  = $0007;
  {$EXTERNALSYM IMAGE_SYM_CLASS_UNDEFINED_LABEL}
  IMAGE_SYM_CLASS_MEMBER_OF_STRUCT = $0008;
  {$EXTERNALSYM IMAGE_SYM_CLASS_MEMBER_OF_STRUCT}
  IMAGE_SYM_CLASS_ARGUMENT         = $0009;
  {$EXTERNALSYM IMAGE_SYM_CLASS_ARGUMENT}
  IMAGE_SYM_CLASS_STRUCT_TAG       = $000A;
  {$EXTERNALSYM IMAGE_SYM_CLASS_STRUCT_TAG}
  IMAGE_SYM_CLASS_MEMBER_OF_UNION  = $000B;
  {$EXTERNALSYM IMAGE_SYM_CLASS_MEMBER_OF_UNION}
  IMAGE_SYM_CLASS_UNION_TAG        = $000C;
  {$EXTERNALSYM IMAGE_SYM_CLASS_UNION_TAG}
  IMAGE_SYM_CLASS_TYPE_DEFINITION  = $000D;
  {$EXTERNALSYM IMAGE_SYM_CLASS_TYPE_DEFINITION}
  IMAGE_SYM_CLASS_UNDEFINED_STATIC = $000E;
  {$EXTERNALSYM IMAGE_SYM_CLASS_UNDEFINED_STATIC}
  IMAGE_SYM_CLASS_ENUM_TAG         = $000F;
  {$EXTERNALSYM IMAGE_SYM_CLASS_ENUM_TAG}
  IMAGE_SYM_CLASS_MEMBER_OF_ENUM   = $0010;
  {$EXTERNALSYM IMAGE_SYM_CLASS_MEMBER_OF_ENUM}
  IMAGE_SYM_CLASS_REGISTER_PARAM   = $0011;
  {$EXTERNALSYM IMAGE_SYM_CLASS_REGISTER_PARAM}
  IMAGE_SYM_CLASS_BIT_FIELD        = $0012;
  {$EXTERNALSYM IMAGE_SYM_CLASS_BIT_FIELD}

  IMAGE_SYM_CLASS_FAR_EXTERNAL = $0044;
  {$EXTERNALSYM IMAGE_SYM_CLASS_FAR_EXTERNAL}

  IMAGE_SYM_CLASS_BLOCK         = $0064;
  {$EXTERNALSYM IMAGE_SYM_CLASS_BLOCK}
  IMAGE_SYM_CLASS_FUNCTION      = $0065;
  {$EXTERNALSYM IMAGE_SYM_CLASS_FUNCTION}
  IMAGE_SYM_CLASS_END_OF_STRUCT = $0066;
  {$EXTERNALSYM IMAGE_SYM_CLASS_END_OF_STRUCT}
  IMAGE_SYM_CLASS_FILE          = $0067;
  {$EXTERNALSYM IMAGE_SYM_CLASS_FILE}

// new

  IMAGE_SYM_CLASS_SECTION       = $0068;
  {$EXTERNALSYM IMAGE_SYM_CLASS_SECTION}
  IMAGE_SYM_CLASS_WEAK_EXTERNAL = $0069;
  {$EXTERNALSYM IMAGE_SYM_CLASS_WEAK_EXTERNAL}

  IMAGE_SYM_CLASS_CLR_TOKEN     = $006B;
  {$EXTERNALSYM IMAGE_SYM_CLASS_CLR_TOKEN}

// type packing constants

  N_BTMASK = $000F;
  {$EXTERNALSYM N_BTMASK}
  N_TMASK  = $0030;
  {$EXTERNALSYM N_TMASK}
  N_TMASK1 = $00C0;
  {$EXTERNALSYM N_TMASK1}
  N_TMASK2 = $00F0;
  {$EXTERNALSYM N_TMASK2}
  N_BTSHFT = 4;
  {$EXTERNALSYM N_BTSHFT}
  N_TSHIFT = 2;
  {$EXTERNALSYM N_TSHIFT}

//
// Auxiliary entry format.
//

type
  TImgAuzSymSymMisc = record
    case Integer of
      0: (
        Linenumber: WORD;             // declaration line number
        Size: WORD);                  // size of struct, union, or enum
      1: (
        TotalSize: DWORD);
  end;

  TImgAuzSymSymFcnAry = record
    case Integer of
      0: ( // if ISFCN, tag, or .bb
        PointerToLinenumber: DWORD;
        PointerToNextFunction: DWORD);
      1: ( // if ISARY, up to 4 dimen.
        Dimension: array [0..3] of WORD);
  end;

  TImgAuxSymSym = record
    TagIndex: DWORD;                      // struct, union, or enum tag index
    Misc: TImgAuzSymSymMisc;
    FcnAry: TImgAuzSymSymFcnAry;
    TvIndex: WORD;                        // tv index
  end;

  TImgAuxSymFile = record
    Name: array [0..IMAGE_SIZEOF_SYMBOL - 1] of BYTE;
  end;

  TImgAuxSymSection = record
    Length: DWORD;                         // section length
    NumberOfRelocations: WORD;             // number of relocation entries
    NumberOfLinenumbers: WORD;             // number of line numbers
    CheckSum: DWORD;                       // checksum for communal
    Number: SHORT;                         // section number to associate with
    Selection: BYTE;                       // communal selection type
  end;

  PIMAGE_AUX_SYMBOL = ^IMAGE_AUX_SYMBOL;
  {$EXTERNALSYM PIMAGE_AUX_SYMBOL}
  _IMAGE_AUX_SYMBOL = record
    case Integer of
      0: (Sym: TImgAuxSymSym);
      1: (File_: TImgAuxSymFile);
      2: (Section: TImgAuxSymSection);
  end;
  {$EXTERNALSYM _IMAGE_AUX_SYMBOL}
  IMAGE_AUX_SYMBOL = _IMAGE_AUX_SYMBOL;
  {$EXTERNALSYM IMAGE_AUX_SYMBOL}
  TImageAuxSymbol = IMAGE_AUX_SYMBOL;
  PImageAuxSymbol = PIMAGE_AUX_SYMBOL;

const
  IMAGE_SIZEOF_AUX_SYMBOL = 18;
  {$EXTERNALSYM IMAGE_SIZEOF_AUX_SYMBOL}

  IMAGE_AUX_SYMBOL_TYPE_TOKEN_DEF = 1;
  {$EXTERNALSYM IMAGE_AUX_SYMBOL_TYPE_TOKEN_DEF}

type
  IMAGE_AUX_SYMBOL_TYPE = DWORD;
  {$EXTERNALSYM IMAGE_AUX_SYMBOL_TYPE}
  TImageAuxSymbolType = IMAGE_AUX_SYMBOL_TYPE;

  IMAGE_AUX_SYMBOL_TOKEN_DEF = packed record
    bAuxType: BYTE;                  // IMAGE_AUX_SYMBOL_TYPE
    bReserved: BYTE;                 // Must be 0
    SymbolTableIndex: DWORD;
    rgbReserved: array [0..11] of BYTE;           // Must be 0
  end;
  {$EXTERNALSYM IMAGE_AUX_SYMBOL_TOKEN_DEF}
  PIMAGE_AUX_SYMBOL_TOKEN_DEF = ^IMAGE_AUX_SYMBOL_TOKEN_DEF;
  {$EXTERNALSYM PIMAGE_AUX_SYMBOL_TOKEN_DEF}
  TImageAuxSymbolTokenDef = IMAGE_AUX_SYMBOL_TOKEN_DEF;
  PImageAuxSymbolTokenDef = PIMAGE_AUX_SYMBOL_TOKEN_DEF;

//
// Communal selection types.
//

const
  IMAGE_COMDAT_SELECT_NODUPLICATES = 1;
  {$EXTERNALSYM IMAGE_COMDAT_SELECT_NODUPLICATES}
  IMAGE_COMDAT_SELECT_ANY          = 2;
  {$EXTERNALSYM IMAGE_COMDAT_SELECT_ANY}
  IMAGE_COMDAT_SELECT_SAME_SIZE    = 3;
  {$EXTERNALSYM IMAGE_COMDAT_SELECT_SAME_SIZE}
  IMAGE_COMDAT_SELECT_EXACT_MATCH  = 4;
  {$EXTERNALSYM IMAGE_COMDAT_SELECT_EXACT_MATCH}
  IMAGE_COMDAT_SELECT_ASSOCIATIVE  = 5;
  {$EXTERNALSYM IMAGE_COMDAT_SELECT_ASSOCIATIVE}
  IMAGE_COMDAT_SELECT_LARGEST      = 6;
  {$EXTERNALSYM IMAGE_COMDAT_SELECT_LARGEST}
  IMAGE_COMDAT_SELECT_NEWEST       = 7;
  {$EXTERNALSYM IMAGE_COMDAT_SELECT_NEWEST}

  IMAGE_WEAK_EXTERN_SEARCH_NOLIBRARY = 1;
  {$EXTERNALSYM IMAGE_WEAK_EXTERN_SEARCH_NOLIBRARY}
  IMAGE_WEAK_EXTERN_SEARCH_LIBRARY   = 2;
  {$EXTERNALSYM IMAGE_WEAK_EXTERN_SEARCH_LIBRARY}
  IMAGE_WEAK_EXTERN_SEARCH_ALIAS     = 3;
  {$EXTERNALSYM IMAGE_WEAK_EXTERN_SEARCH_ALIAS}

//
// Relocation format.
//

type
  TImgRelocUnion = record
    case Integer of
      0: (VirtualAddress: DWORD);
      1: (RelocCount: DWORD);  // Set to the real count when IMAGE_SCN_LNK_NRELOC_OVFL is set
  end;

  PIMAGE_RELOCATION = ^IMAGE_RELOCATION;
  {$EXTERNALSYM PIMAGE_RELOCATION}
  _IMAGE_RELOCATION = record
    Union: TImgRelocUnion;
    SymbolTableIndex: DWORD;
    Type_: WORD;
  end;
  {$EXTERNALSYM _IMAGE_RELOCATION}
  IMAGE_RELOCATION = _IMAGE_RELOCATION;
  {$EXTERNALSYM IMAGE_RELOCATION}
  TImageRelocation = IMAGE_RELOCATION;
  PImageRelocation = PIMAGE_RELOCATION;

const
  IMAGE_SIZEOF_RELOCATION = 10;
  {$EXTERNALSYM IMAGE_SIZEOF_RELOCATION}

//
// I386 relocation types.
//

  IMAGE_REL_I386_ABSOLUTE = $0000; // Reference is absolute, no relocation is necessary
  {$EXTERNALSYM IMAGE_REL_I386_ABSOLUTE}
  IMAGE_REL_I386_DIR16    = $0001; // Direct 16-bit reference to the symbols virtual address
  {$EXTERNALSYM IMAGE_REL_I386_DIR16}
  IMAGE_REL_I386_REL16    = $0002; // PC-relative 16-bit reference to the symbols virtual address
  {$EXTERNALSYM IMAGE_REL_I386_REL16}
  IMAGE_REL_I386_DIR32    = $0006; // Direct 32-bit reference to the symbols virtual address
  {$EXTERNALSYM IMAGE_REL_I386_DIR32}
  IMAGE_REL_I386_DIR32NB  = $0007; // Direct 32-bit reference to the symbols virtual address, base not included
  {$EXTERNALSYM IMAGE_REL_I386_DIR32NB}
  IMAGE_REL_I386_SEG12    = $0009; // Direct 16-bit reference to the segment-selector bits of a 32-bit virtual address
  {$EXTERNALSYM IMAGE_REL_I386_SEG12}
  IMAGE_REL_I386_SECTION  = $000A;
  {$EXTERNALSYM IMAGE_REL_I386_SECTION}
  IMAGE_REL_I386_SECREL   = $000B;
  {$EXTERNALSYM IMAGE_REL_I386_SECREL}
  IMAGE_REL_MIPS_SECRELLO = $000C; // Low 16-bit section relative referemce (used for >32k TLS)
  {$EXTERNALSYM IMAGE_REL_MIPS_SECRELLO}
  IMAGE_REL_MIPS_SECRELHI = $000D; // High 16-bit section relative reference (used for >32k TLS)
  {$EXTERNALSYM IMAGE_REL_MIPS_SECRELHI}
  IMAGE_REL_I386_REL32    = $0014; // PC-relative 32-bit reference to the symbols virtual address
  {$EXTERNALSYM IMAGE_REL_I386_REL32}

//
// MIPS relocation types.
//

  IMAGE_REL_MIPS_ABSOLUTE  = $0000; // Reference is absolute, no relocation is necessary
  {$EXTERNALSYM IMAGE_REL_MIPS_ABSOLUTE}
  IMAGE_REL_MIPS_REFHALF   = $0001;
  {$EXTERNALSYM IMAGE_REL_MIPS_REFHALF}
  IMAGE_REL_MIPS_REFWORD   = $0002;
  {$EXTERNALSYM IMAGE_REL_MIPS_REFWORD}
  IMAGE_REL_MIPS_JMPADDR   = $0003;
  {$EXTERNALSYM IMAGE_REL_MIPS_JMPADDR}
  IMAGE_REL_MIPS_REFHI     = $0004;
  {$EXTERNALSYM IMAGE_REL_MIPS_REFHI}
  IMAGE_REL_MIPS_REFLO     = $0005;
  {$EXTERNALSYM IMAGE_REL_MIPS_REFLO}
  IMAGE_REL_MIPS_GPREL     = $0006;
  {$EXTERNALSYM IMAGE_REL_MIPS_GPREL}
  IMAGE_REL_MIPS_LITERAL   = $0007;
  {$EXTERNALSYM IMAGE_REL_MIPS_LITERAL}
  IMAGE_REL_MIPS_SECTION   = $000A;
  {$EXTERNALSYM IMAGE_REL_MIPS_SECTION}
  IMAGE_REL_MIPS_SECREL    = $000B;
  {$EXTERNALSYM IMAGE_REL_MIPS_SECREL}
  //IMAGE_REL_MIPS_SECRELLO  = $000C; // Low 16-bit section relative referemce (used for >32k TLS)
  //{$EXTERNALSYM IMAGE_REL_MIPS_SECRELLO}
  //IMAGE_REL_MIPS_SECRELHI  = $000D; // High 16-bit section relative reference (used for >32k TLS)
  //{$EXTERNALSYM IMAGE_REL_MIPS_SECRELHI}
  IMAGE_REL_MIPS_TOKEN     = $000E; // clr token
  {$EXTERNALSYM IMAGE_REL_MIPS_TOKEN}
  IMAGE_REL_MIPS_JMPADDR16 = $0010;
  {$EXTERNALSYM IMAGE_REL_MIPS_JMPADDR16}
  IMAGE_REL_MIPS_REFWORDNB = $0022;
  {$EXTERNALSYM IMAGE_REL_MIPS_REFWORDNB}
  IMAGE_REL_MIPS_PAIR      = $0025;
  {$EXTERNALSYM IMAGE_REL_MIPS_PAIR}

//
// Alpha Relocation types.
//

  IMAGE_REL_ALPHA_ABSOLUTE       = $0000;
  {$EXTERNALSYM IMAGE_REL_ALPHA_ABSOLUTE}
  IMAGE_REL_ALPHA_REFLONG        = $0001;
  {$EXTERNALSYM IMAGE_REL_ALPHA_REFLONG}
  IMAGE_REL_ALPHA_REFQUAD        = $0002;
  {$EXTERNALSYM IMAGE_REL_ALPHA_REFQUAD}
  IMAGE_REL_ALPHA_GPREL32        = $0003;
  {$EXTERNALSYM IMAGE_REL_ALPHA_GPREL32}
  IMAGE_REL_ALPHA_LITERAL        = $0004;
  {$EXTERNALSYM IMAGE_REL_ALPHA_LITERAL}
  IMAGE_REL_ALPHA_LITUSE         = $0005;
  {$EXTERNALSYM IMAGE_REL_ALPHA_LITUSE}
  IMAGE_REL_ALPHA_GPDISP         = $0006;
  {$EXTERNALSYM IMAGE_REL_ALPHA_GPDISP}
  IMAGE_REL_ALPHA_BRADDR         = $0007;
  {$EXTERNALSYM IMAGE_REL_ALPHA_BRADDR}
  IMAGE_REL_ALPHA_HINT           = $0008;
  {$EXTERNALSYM IMAGE_REL_ALPHA_HINT}
  IMAGE_REL_ALPHA_INLINE_REFLONG = $0009;
  {$EXTERNALSYM IMAGE_REL_ALPHA_INLINE_REFLONG}
  IMAGE_REL_ALPHA_REFHI          = $000A;
  {$EXTERNALSYM IMAGE_REL_ALPHA_REFHI}
  IMAGE_REL_ALPHA_REFLO          = $000B;
  {$EXTERNALSYM IMAGE_REL_ALPHA_REFLO}
  IMAGE_REL_ALPHA_PAIR           = $000C;
  {$EXTERNALSYM IMAGE_REL_ALPHA_PAIR}
  IMAGE_REL_ALPHA_MATCH          = $000D;
  {$EXTERNALSYM IMAGE_REL_ALPHA_MATCH}
  IMAGE_REL_ALPHA_SECTION        = $000E;
  {$EXTERNALSYM IMAGE_REL_ALPHA_SECTION}
  IMAGE_REL_ALPHA_SECREL         = $000F;
  {$EXTERNALSYM IMAGE_REL_ALPHA_SECREL}
  IMAGE_REL_ALPHA_REFLONGNB      = $0010;
  {$EXTERNALSYM IMAGE_REL_ALPHA_REFLONGNB}
  IMAGE_REL_ALPHA_SECRELLO       = $0011; // Low 16-bit section relative reference
  {$EXTERNALSYM IMAGE_REL_ALPHA_SECRELLO}
  IMAGE_REL_ALPHA_SECRELHI       = $0012; // High 16-bit section relative reference
  {$EXTERNALSYM IMAGE_REL_ALPHA_SECRELHI}
  IMAGE_REL_ALPHA_REFQ3          = $0013; // High 16 bits of 48 bit reference
  {$EXTERNALSYM IMAGE_REL_ALPHA_REFQ3}
  IMAGE_REL_ALPHA_REFQ2          = $0014; // Middle 16 bits of 48 bit reference
  {$EXTERNALSYM IMAGE_REL_ALPHA_REFQ2}
  IMAGE_REL_ALPHA_REFQ1          = $0015; // Low 16 bits of 48 bit reference
  {$EXTERNALSYM IMAGE_REL_ALPHA_REFQ1}
  IMAGE_REL_ALPHA_GPRELLO        = $0016; // Low 16-bit GP relative reference
  {$EXTERNALSYM IMAGE_REL_ALPHA_GPRELLO}
  IMAGE_REL_ALPHA_GPRELHI        = $0017; // High 16-bit GP relative reference
  {$EXTERNALSYM IMAGE_REL_ALPHA_GPRELHI}

//
// IBM PowerPC relocation types.
//

  IMAGE_REL_PPC_ABSOLUTE = $0000; // NOP
  {$EXTERNALSYM IMAGE_REL_PPC_ABSOLUTE}
  IMAGE_REL_PPC_ADDR64   = $0001; // 64-bit address
  {$EXTERNALSYM IMAGE_REL_PPC_ADDR64}
  IMAGE_REL_PPC_ADDR32   = $0002; // 32-bit address
  {$EXTERNALSYM IMAGE_REL_PPC_ADDR32}
  IMAGE_REL_PPC_ADDR24   = $0003; // 26-bit address, shifted left 2 (branch absolute)
  {$EXTERNALSYM IMAGE_REL_PPC_ADDR24}
  IMAGE_REL_PPC_ADDR16   = $0004; // 16-bit address
  {$EXTERNALSYM IMAGE_REL_PPC_ADDR16}
  IMAGE_REL_PPC_ADDR14   = $0005; // 16-bit address, shifted left 2 (load doubleword)
  {$EXTERNALSYM IMAGE_REL_PPC_ADDR14}
  IMAGE_REL_PPC_REL24    = $0006; // 26-bit PC-relative offset, shifted left 2 (branch relative)
  {$EXTERNALSYM IMAGE_REL_PPC_REL24}
  IMAGE_REL_PPC_REL14    = $0007; // 16-bit PC-relative offset, shifted left 2 (br cond relative)
  {$EXTERNALSYM IMAGE_REL_PPC_REL14}
  IMAGE_REL_PPC_TOCREL16 = $0008; // 16-bit offset from TOC base
  {$EXTERNALSYM IMAGE_REL_PPC_TOCREL16}
  IMAGE_REL_PPC_TOCREL14 = $0009; // 16-bit offset from TOC base, shifted left 2 (load doubleword)
  {$EXTERNALSYM IMAGE_REL_PPC_TOCREL14}

  IMAGE_REL_PPC_ADDR32NB = $000A; // 32-bit addr w/o image base
  {$EXTERNALSYM IMAGE_REL_PPC_ADDR32NB}
  IMAGE_REL_PPC_SECREL   = $000B; // va of containing section (as in an image sectionhdr)
  {$EXTERNALSYM IMAGE_REL_PPC_SECREL}
  IMAGE_REL_PPC_SECTION  = $000C; // sectionheader number
  {$EXTERNALSYM IMAGE_REL_PPC_SECTION}
  IMAGE_REL_PPC_IFGLUE   = $000D; // substitute TOC restore instruction iff symbol is glue code
  {$EXTERNALSYM IMAGE_REL_PPC_IFGLUE}
  IMAGE_REL_PPC_IMGLUE   = $000E; // symbol is glue code; virtual address is TOC restore instruction
  {$EXTERNALSYM IMAGE_REL_PPC_IMGLUE}
  IMAGE_REL_PPC_SECREL16 = $000F; // va of containing section (limited to 16 bits)
  {$EXTERNALSYM IMAGE_REL_PPC_SECREL16}
  IMAGE_REL_PPC_REFHI    = $0010;
  {$EXTERNALSYM IMAGE_REL_PPC_REFHI}
  IMAGE_REL_PPC_REFLO    = $0011;
  {$EXTERNALSYM IMAGE_REL_PPC_REFLO}
  IMAGE_REL_PPC_PAIR     = $0012;
  {$EXTERNALSYM IMAGE_REL_PPC_PAIR}
  IMAGE_REL_PPC_SECRELLO = $0013; // Low 16-bit section relative reference (used for >32k TLS)
  {$EXTERNALSYM IMAGE_REL_PPC_SECRELLO}
  IMAGE_REL_PPC_SECRELHI = $0014; // High 16-bit section relative reference (used for >32k TLS)
  {$EXTERNALSYM IMAGE_REL_PPC_SECRELHI}
  IMAGE_REL_PPC_GPREL    = $0015;
  {$EXTERNALSYM IMAGE_REL_PPC_GPREL}
  IMAGE_REL_PPC_TOKEN    = $0016; // clr token
  {$EXTERNALSYM IMAGE_REL_PPC_TOKEN}

  IMAGE_REL_PPC_TYPEMASK = $00FF; // mask to isolate above values in IMAGE_RELOCATION.Type
  {$EXTERNALSYM IMAGE_REL_PPC_TYPEMASK}

// Flag bits in IMAGE_RELOCATION.TYPE

  IMAGE_REL_PPC_NEG      = $0100; // subtract reloc value rather than adding it
  {$EXTERNALSYM IMAGE_REL_PPC_NEG}
  IMAGE_REL_PPC_BRTAKEN  = $0200; // fix branch prediction bit to predict branch taken
  {$EXTERNALSYM IMAGE_REL_PPC_BRTAKEN}
  IMAGE_REL_PPC_BRNTAKEN = $0400; // fix branch prediction bit to predict branch not taken
  {$EXTERNALSYM IMAGE_REL_PPC_BRNTAKEN}
  IMAGE_REL_PPC_TOCDEFN  = $0800; // toc slot defined in file (or, data in toc)
  {$EXTERNALSYM IMAGE_REL_PPC_TOCDEFN}

//
// Hitachi SH3 relocation types.
//

  IMAGE_REL_SH3_ABSOLUTE        = $0000; // No relocation
  {$EXTERNALSYM IMAGE_REL_SH3_ABSOLUTE}
  IMAGE_REL_SH3_DIRECT16        = $0001; // 16 bit direct
  {$EXTERNALSYM IMAGE_REL_SH3_DIRECT16}
  IMAGE_REL_SH3_DIRECT32        = $0002; // 32 bit direct
  {$EXTERNALSYM IMAGE_REL_SH3_DIRECT32}
  IMAGE_REL_SH3_DIRECT8         = $0003; // 8 bit direct, -128..255
  {$EXTERNALSYM IMAGE_REL_SH3_DIRECT8}
  IMAGE_REL_SH3_DIRECT8_WORD    = $0004; // 8 bit direct .W (0 ext.)
  {$EXTERNALSYM IMAGE_REL_SH3_DIRECT8_WORD}
  IMAGE_REL_SH3_DIRECT8_LONG    = $0005; // 8 bit direct .L (0 ext.)
  {$EXTERNALSYM IMAGE_REL_SH3_DIRECT8_LONG}
  IMAGE_REL_SH3_DIRECT4         = $0006; // 4 bit direct (0 ext.)
  {$EXTERNALSYM IMAGE_REL_SH3_DIRECT4}
  IMAGE_REL_SH3_DIRECT4_WORD    = $0007; // 4 bit direct .W (0 ext.)
  {$EXTERNALSYM IMAGE_REL_SH3_DIRECT4_WORD}
  IMAGE_REL_SH3_DIRECT4_LONG    = $0008; // 4 bit direct .L (0 ext.)
  {$EXTERNALSYM IMAGE_REL_SH3_DIRECT4_LONG}
  IMAGE_REL_SH3_PCREL8_WORD     = $0009; // 8 bit PC relative .W
  {$EXTERNALSYM IMAGE_REL_SH3_PCREL8_WORD}
  IMAGE_REL_SH3_PCREL8_LONG     = $000A; // 8 bit PC relative .L
  {$EXTERNALSYM IMAGE_REL_SH3_PCREL8_LONG}
  IMAGE_REL_SH3_PCREL12_WORD    = $000B; // 12 LSB PC relative .W
  {$EXTERNALSYM IMAGE_REL_SH3_PCREL12_WORD}
  IMAGE_REL_SH3_STARTOF_SECTION = $000C; // Start of EXE section
  {$EXTERNALSYM IMAGE_REL_SH3_STARTOF_SECTION}
  IMAGE_REL_SH3_SIZEOF_SECTION  = $000D; // Size of EXE section
  {$EXTERNALSYM IMAGE_REL_SH3_SIZEOF_SECTION}
  IMAGE_REL_SH3_SECTION         = $000E; // Section table index
  {$EXTERNALSYM IMAGE_REL_SH3_SECTION}
  IMAGE_REL_SH3_SECREL          = $000F; // Offset within section
  {$EXTERNALSYM IMAGE_REL_SH3_SECREL}
  IMAGE_REL_SH3_DIRECT32_NB     = $0010; // 32 bit direct not based
  {$EXTERNALSYM IMAGE_REL_SH3_DIRECT32_NB}
  IMAGE_REL_SH3_GPREL4_LONG     = $0011; // GP-relative addressing
  {$EXTERNALSYM IMAGE_REL_SH3_GPREL4_LONG}
  IMAGE_REL_SH3_TOKEN           = $0012; // clr token
  {$EXTERNALSYM IMAGE_REL_SH3_TOKEN}

  IMAGE_REL_ARM_ABSOLUTE = $0000; // No relocation required
  {$EXTERNALSYM IMAGE_REL_ARM_ABSOLUTE}
  IMAGE_REL_ARM_ADDR32   = $0001; // 32 bit address
  {$EXTERNALSYM IMAGE_REL_ARM_ADDR32}
  IMAGE_REL_ARM_ADDR32NB = $0002; // 32 bit address w/o image base
  {$EXTERNALSYM IMAGE_REL_ARM_ADDR32NB}
  IMAGE_REL_ARM_BRANCH24 = $0003; // 24 bit offset << 2 & sign ext.
  {$EXTERNALSYM IMAGE_REL_ARM_BRANCH24}
  IMAGE_REL_ARM_BRANCH11 = $0004; // Thumb: 2 11 bit offsets
  {$EXTERNALSYM IMAGE_REL_ARM_BRANCH11}
  IMAGE_REL_ARM_TOKEN    = $0005; // clr token
  {$EXTERNALSYM IMAGE_REL_ARM_TOKEN}
  IMAGE_REL_ARM_GPREL12  = $0006; // GP-relative addressing (ARM)
  {$EXTERNALSYM IMAGE_REL_ARM_GPREL12}
  IMAGE_REL_ARM_GPREL7   = $0007; // GP-relative addressing (Thumb)
  {$EXTERNALSYM IMAGE_REL_ARM_GPREL7}
  IMAGE_REL_ARM_BLX24    = $0008;
  {$EXTERNALSYM IMAGE_REL_ARM_BLX24}
  IMAGE_REL_ARM_BLX11    = $0009;
  {$EXTERNALSYM IMAGE_REL_ARM_BLX11}
  IMAGE_REL_ARM_SECTION  = $000E; // Section table index
  {$EXTERNALSYM IMAGE_REL_ARM_SECTION}
  IMAGE_REL_ARM_SECREL   = $000F; // Offset within section
  {$EXTERNALSYM IMAGE_REL_ARM_SECREL}

  IMAGE_REL_AM_ABSOLUTE = $0000;
  {$EXTERNALSYM IMAGE_REL_AM_ABSOLUTE}
  IMAGE_REL_AM_ADDR32   = $0001;
  {$EXTERNALSYM IMAGE_REL_AM_ADDR32}
  IMAGE_REL_AM_ADDR32NB = $0002;
  {$EXTERNALSYM IMAGE_REL_AM_ADDR32NB}
  IMAGE_REL_AM_CALL32   = $0003;
  {$EXTERNALSYM IMAGE_REL_AM_CALL32}
  IMAGE_REL_AM_FUNCINFO = $0004;
  {$EXTERNALSYM IMAGE_REL_AM_FUNCINFO}
  IMAGE_REL_AM_REL32_1  = $0005;
  {$EXTERNALSYM IMAGE_REL_AM_REL32_1}
  IMAGE_REL_AM_REL32_2  = $0006;
  {$EXTERNALSYM IMAGE_REL_AM_REL32_2}
  IMAGE_REL_AM_SECREL   = $0007;
  {$EXTERNALSYM IMAGE_REL_AM_SECREL}
  IMAGE_REL_AM_SECTION  = $0008;
  {$EXTERNALSYM IMAGE_REL_AM_SECTION}
  IMAGE_REL_AM_TOKEN    = $0009;
  {$EXTERNALSYM IMAGE_REL_AM_TOKEN}

//
// X86-64 relocations
//

  IMAGE_REL_AMD64_ABSOLUTE = $0000; // Reference is absolute, no relocation is necessary
  {$EXTERNALSYM IMAGE_REL_AMD64_ABSOLUTE}
  IMAGE_REL_AMD64_ADDR64   = $0001; // 64-bit address (VA).
  {$EXTERNALSYM IMAGE_REL_AMD64_ADDR64}
  IMAGE_REL_AMD64_ADDR32   = $0002; // 32-bit address (VA).
  {$EXTERNALSYM IMAGE_REL_AMD64_ADDR32}
  IMAGE_REL_AMD64_ADDR32NB = $0003; // 32-bit address w/o image base (RVA).
  {$EXTERNALSYM IMAGE_REL_AMD64_ADDR32NB}
  IMAGE_REL_AMD64_REL32    = $0004; // 32-bit relative address from byte following reloc
  {$EXTERNALSYM IMAGE_REL_AMD64_REL32}
  IMAGE_REL_AMD64_REL32_1  = $0005; // 32-bit relative address from byte distance 1 from reloc
  {$EXTERNALSYM IMAGE_REL_AMD64_REL32_1}
  IMAGE_REL_AMD64_REL32_2  = $0006; // 32-bit relative address from byte distance 2 from reloc
  {$EXTERNALSYM IMAGE_REL_AMD64_REL32_2}
  IMAGE_REL_AMD64_REL32_3  = $0007; // 32-bit relative address from byte distance 3 from reloc
  {$EXTERNALSYM IMAGE_REL_AMD64_REL32_3}
  IMAGE_REL_AMD64_REL32_4  = $0008; // 32-bit relative address from byte distance 4 from reloc
  {$EXTERNALSYM IMAGE_REL_AMD64_REL32_4}
  IMAGE_REL_AMD64_REL32_5  = $0009; // 32-bit relative address from byte distance 5 from reloc
  {$EXTERNALSYM IMAGE_REL_AMD64_REL32_5}
  IMAGE_REL_AMD64_SECTION  = $000A; // Section index
  {$EXTERNALSYM IMAGE_REL_AMD64_SECTION}
  IMAGE_REL_AMD64_SECREL   = $000B; // 32 bit offset from base of section containing target
  {$EXTERNALSYM IMAGE_REL_AMD64_SECREL}
  IMAGE_REL_AMD64_SECREL7  = $000C; // 7 bit unsigned offset from base of section containing target
  {$EXTERNALSYM IMAGE_REL_AMD64_SECREL7}
  IMAGE_REL_AMD64_TOKEN    = $000D; // 32 bit metadata token
  {$EXTERNALSYM IMAGE_REL_AMD64_TOKEN}

//
// IA64 relocation types.
//

  IMAGE_REL_IA64_ABSOLUTE  = $0000;
  {$EXTERNALSYM IMAGE_REL_IA64_ABSOLUTE}
  IMAGE_REL_IA64_IMM14     = $0001;
  {$EXTERNALSYM IMAGE_REL_IA64_IMM14}
  IMAGE_REL_IA64_IMM22     = $0002;
  {$EXTERNALSYM IMAGE_REL_IA64_IMM22}
  IMAGE_REL_IA64_IMM64     = $0003;
  {$EXTERNALSYM IMAGE_REL_IA64_IMM64}
  IMAGE_REL_IA64_DIR32     = $0004;
  {$EXTERNALSYM IMAGE_REL_IA64_DIR32}
  IMAGE_REL_IA64_DIR64     = $0005;
  {$EXTERNALSYM IMAGE_REL_IA64_DIR64}
  IMAGE_REL_IA64_PCREL21B  = $0006;
  {$EXTERNALSYM IMAGE_REL_IA64_PCREL21B}
  IMAGE_REL_IA64_PCREL21M  = $0007;
  {$EXTERNALSYM IMAGE_REL_IA64_PCREL21M}
  IMAGE_REL_IA64_PCREL21F  = $0008;
  {$EXTERNALSYM IMAGE_REL_IA64_PCREL21F}
  IMAGE_REL_IA64_GPREL22   = $0009;
  {$EXTERNALSYM IMAGE_REL_IA64_GPREL22}
  IMAGE_REL_IA64_LTOFF22   = $000A;
  {$EXTERNALSYM IMAGE_REL_IA64_LTOFF22}
  IMAGE_REL_IA64_SECTION   = $000B;
  {$EXTERNALSYM IMAGE_REL_IA64_SECTION}
  IMAGE_REL_IA64_SECREL22  = $000C;
  {$EXTERNALSYM IMAGE_REL_IA64_SECREL22}
  IMAGE_REL_IA64_SECREL64I = $000D;
  {$EXTERNALSYM IMAGE_REL_IA64_SECREL64I}
  IMAGE_REL_IA64_SECREL32  = $000E;
  {$EXTERNALSYM IMAGE_REL_IA64_SECREL32}

//

  IMAGE_REL_IA64_DIR32NB    = $0010;
  {$EXTERNALSYM IMAGE_REL_IA64_DIR32NB}
  IMAGE_REL_IA64_SREL14     = $0011;
  {$EXTERNALSYM IMAGE_REL_IA64_SREL14}
  IMAGE_REL_IA64_SREL22     = $0012;
  {$EXTERNALSYM IMAGE_REL_IA64_SREL22}
  IMAGE_REL_IA64_SREL32     = $0013;
  {$EXTERNALSYM IMAGE_REL_IA64_SREL32}
  IMAGE_REL_IA64_UREL32     = $0014;
  {$EXTERNALSYM IMAGE_REL_IA64_UREL32}
  IMAGE_REL_IA64_PCREL60X   = $0015; // This is always a BRL and never converted
  {$EXTERNALSYM IMAGE_REL_IA64_PCREL60X}
  IMAGE_REL_IA64_PCREL60B   = $0016; // If possible, convert to MBB bundle with NOP.B in slot 1
  {$EXTERNALSYM IMAGE_REL_IA64_PCREL60B}
  IMAGE_REL_IA64_PCREL60F   = $0017; // If possible, convert to MFB bundle with NOP.F in slot 1
  {$EXTERNALSYM IMAGE_REL_IA64_PCREL60F}
  IMAGE_REL_IA64_PCREL60I   = $0018; // If possible, convert to MIB bundle with NOP.I in slot 1
  {$EXTERNALSYM IMAGE_REL_IA64_PCREL60I}
  IMAGE_REL_IA64_PCREL60M   = $0019; // If possible, convert to MMB bundle with NOP.M in slot 1
  {$EXTERNALSYM IMAGE_REL_IA64_PCREL60M}
  IMAGE_REL_IA64_IMMGPREL64 = $001A;
  {$EXTERNALSYM IMAGE_REL_IA64_IMMGPREL64}
  IMAGE_REL_IA64_TOKEN      = $001B; // clr token
  {$EXTERNALSYM IMAGE_REL_IA64_TOKEN}
  IMAGE_REL_IA64_GPREL32    = $001C;
  {$EXTERNALSYM IMAGE_REL_IA64_GPREL32}
  IMAGE_REL_IA64_ADDEND     = $001F;
  {$EXTERNALSYM IMAGE_REL_IA64_ADDEND}

//
// CEF relocation types.
//

  IMAGE_REL_CEF_ABSOLUTE = $0000; // Reference is absolute, no relocation is necessary
  {$EXTERNALSYM IMAGE_REL_CEF_ABSOLUTE}
  IMAGE_REL_CEF_ADDR32   = $0001; // 32-bit address (VA).
  {$EXTERNALSYM IMAGE_REL_CEF_ADDR32}
  IMAGE_REL_CEF_ADDR64   = $0002; // 64-bit address (VA).
  {$EXTERNALSYM IMAGE_REL_CEF_ADDR64}
  IMAGE_REL_CEF_ADDR32NB = $0003; // 32-bit address w/o image base (RVA).
  {$EXTERNALSYM IMAGE_REL_CEF_ADDR32NB}
  IMAGE_REL_CEF_SECTION  = $0004; // Section index
  {$EXTERNALSYM IMAGE_REL_CEF_SECTION}
  IMAGE_REL_CEF_SECREL   = $0005; // 32 bit offset from base of section containing target
  {$EXTERNALSYM IMAGE_REL_CEF_SECREL}
  IMAGE_REL_CEF_TOKEN    = $0006; // 32 bit metadata token
  {$EXTERNALSYM IMAGE_REL_CEF_TOKEN}

//
// clr relocation types.
//

  IMAGE_REL_CEE_ABSOLUTE = $0000; // Reference is absolute, no relocation is necessary
  {$EXTERNALSYM IMAGE_REL_CEE_ABSOLUTE}
  IMAGE_REL_CEE_ADDR32   = $0001; // 32-bit address (VA).
  {$EXTERNALSYM IMAGE_REL_CEE_ADDR32}
  IMAGE_REL_CEE_ADDR64   = $0002; // 64-bit address (VA).
  {$EXTERNALSYM IMAGE_REL_CEE_ADDR64}
  IMAGE_REL_CEE_ADDR32NB = $0003; // 32-bit address w/o image base (RVA).
  {$EXTERNALSYM IMAGE_REL_CEE_ADDR32NB}
  IMAGE_REL_CEE_SECTION  = $0004; // Section index
  {$EXTERNALSYM IMAGE_REL_CEE_SECTION}
  IMAGE_REL_CEE_SECREL   = $0005; // 32 bit offset from base of section containing target
  {$EXTERNALSYM IMAGE_REL_CEE_SECREL}
  IMAGE_REL_CEE_TOKEN    = $0006; // 32 bit metadata token
  {$EXTERNALSYM IMAGE_REL_CEE_TOKEN}

  IMAGE_REL_M32R_ABSOLUTE = $0000; // No relocation required
  {$EXTERNALSYM IMAGE_REL_M32R_ABSOLUTE}
  IMAGE_REL_M32R_ADDR32   = $0001; // 32 bit address
  {$EXTERNALSYM IMAGE_REL_M32R_ADDR32}
  IMAGE_REL_M32R_ADDR32NB = $0002; // 32 bit address w/o image base
  {$EXTERNALSYM IMAGE_REL_M32R_ADDR32NB}
  IMAGE_REL_M32R_ADDR24   = $0003; // 24 bit address
  {$EXTERNALSYM IMAGE_REL_M32R_ADDR24}
  IMAGE_REL_M32R_GPREL16  = $0004; // GP relative addressing
  {$EXTERNALSYM IMAGE_REL_M32R_GPREL16}
  IMAGE_REL_M32R_PCREL24  = $0005; // 24 bit offset << 2 & sign ext.
  {$EXTERNALSYM IMAGE_REL_M32R_PCREL24}
  IMAGE_REL_M32R_PCREL16  = $0006; // 16 bit offset << 2 & sign ext.
  {$EXTERNALSYM IMAGE_REL_M32R_PCREL16}
  IMAGE_REL_M32R_PCREL8   = $0007; // 8 bit offset << 2 & sign ext.
  {$EXTERNALSYM IMAGE_REL_M32R_PCREL8}
  IMAGE_REL_M32R_REFHALF  = $0008; // 16 MSBs
  {$EXTERNALSYM IMAGE_REL_M32R_REFHALF}
  IMAGE_REL_M32R_REFHI    = $0009; // 16 MSBs; adj for LSB sign ext.
  {$EXTERNALSYM IMAGE_REL_M32R_REFHI}
  IMAGE_REL_M32R_REFLO    = $000A; // 16 LSBs
  {$EXTERNALSYM IMAGE_REL_M32R_REFLO}
  IMAGE_REL_M32R_PAIR     = $000B; // Link HI and LO
  {$EXTERNALSYM IMAGE_REL_M32R_PAIR}
  IMAGE_REL_M32R_SECTION  = $000C; // Section table index
  {$EXTERNALSYM IMAGE_REL_M32R_SECTION}
  IMAGE_REL_M32R_SECREL32 = $000D; // 32 bit section relative reference
  {$EXTERNALSYM IMAGE_REL_M32R_SECREL32}
  IMAGE_REL_M32R_TOKEN    = $000E; // clr token
  {$EXTERNALSYM IMAGE_REL_M32R_TOKEN}

// Please contact INTEL to get IA64-specific information

(* TODO
#define EXT_IMM64(Value, Address, Size, InstPos, ValPos)
    Value |= (((ULONGLONG)((*(Address) >> InstPos) & (((ULONGLONG)1 << Size) - 1))) << ValPos)  // Intel-IA64-Filler

#define INS_IMM64(Value, Address, Size, InstPos, ValPos)  /* Intel-IA64-Filler */\
    *(PDWORD)Address = (*(PDWORD)Address & ~(((1 << Size) - 1) << InstPos)) | /* Intel-IA64-Filler */\
          ((DWORD)((((ULONGLONG)Value >> ValPos) & (((ULONGLONG)1 << Size) - 1))) << InstPos)  // Intel-IA64-Filler
*)

const
  EMARCH_ENC_I17_IMM7B_INST_WORD_X     = 3; // Intel-IA64-Filler
  {$EXTERNALSYM EMARCH_ENC_I17_IMM7B_INST_WORD_X}
  EMARCH_ENC_I17_IMM7B_SIZE_X          = 7; // Intel-IA64-Filler
  {$EXTERNALSYM EMARCH_ENC_I17_IMM7B_SIZE_X}
  EMARCH_ENC_I17_IMM7B_INST_WORD_POS_X = 4; // Intel-IA64-Filler
  {$EXTERNALSYM EMARCH_ENC_I17_IMM7B_INST_WORD_POS_X}
  EMARCH_ENC_I17_IMM7B_VAL_POS_X       = 0; // Intel-IA64-Filler
  {$EXTERNALSYM EMARCH_ENC_I17_IMM7B_VAL_POS_X}

  EMARCH_ENC_I17_IMM9D_INST_WORD_X     = 3; // Intel-IA64-Filler
  {$EXTERNALSYM EMARCH_ENC_I17_IMM9D_INST_WORD_X}
  EMARCH_ENC_I17_IMM9D_SIZE_X          = 9; // Intel-IA64-Filler
  {$EXTERNALSYM EMARCH_ENC_I17_IMM9D_SIZE_X}
  EMARCH_ENC_I17_IMM9D_INST_WORD_POS_X = 18; // Intel-IA64-Filler
  {$EXTERNALSYM EMARCH_ENC_I17_IMM9D_INST_WORD_POS_X}
  EMARCH_ENC_I17_IMM9D_VAL_POS_X       = 7; // Intel-IA64-Filler
  {$EXTERNALSYM EMARCH_ENC_I17_IMM9D_VAL_POS_X}

  EMARCH_ENC_I17_IMM5C_INST_WORD_X     = 3; // Intel-IA64-Filler
  {$EXTERNALSYM EMARCH_ENC_I17_IMM5C_INST_WORD_X}
  EMARCH_ENC_I17_IMM5C_SIZE_X          = 5; // Intel-IA64-Filler
  {$EXTERNALSYM EMARCH_ENC_I17_IMM5C_SIZE_X}
  EMARCH_ENC_I17_IMM5C_INST_WORD_POS_X = 13; // Intel-IA64-Filler
  {$EXTERNALSYM EMARCH_ENC_I17_IMM5C_INST_WORD_POS_X}
  EMARCH_ENC_I17_IMM5C_VAL_POS_X       = 16; // Intel-IA64-Filler
  {$EXTERNALSYM EMARCH_ENC_I17_IMM5C_VAL_POS_X}

  EMARCH_ENC_I17_IC_INST_WORD_X     = 3; // Intel-IA64-Filler
  {$EXTERNALSYM EMARCH_ENC_I17_IC_INST_WORD_X}
  EMARCH_ENC_I17_IC_SIZE_X          = 1; // Intel-IA64-Filler
  {$EXTERNALSYM EMARCH_ENC_I17_IC_SIZE_X}
  EMARCH_ENC_I17_IC_INST_WORD_POS_X = 12; // Intel-IA64-Filler
  {$EXTERNALSYM EMARCH_ENC_I17_IC_INST_WORD_POS_X}
  EMARCH_ENC_I17_IC_VAL_POS_X       = 21; // Intel-IA64-Filler
  {$EXTERNALSYM EMARCH_ENC_I17_IC_VAL_POS_X}

  EMARCH_ENC_I17_IMM41a_INST_WORD_X     = 1; // Intel-IA64-Filler
  {$EXTERNALSYM EMARCH_ENC_I17_IMM41a_INST_WORD_X}
  EMARCH_ENC_I17_IMM41a_SIZE_X          = 10; // Intel-IA64-Filler
  {$EXTERNALSYM EMARCH_ENC_I17_IMM41a_SIZE_X}
  EMARCH_ENC_I17_IMM41a_INST_WORD_POS_X = 14; // Intel-IA64-Filler
  {$EXTERNALSYM EMARCH_ENC_I17_IMM41a_INST_WORD_POS_X}
  EMARCH_ENC_I17_IMM41a_VAL_POS_X       = 22; // Intel-IA64-Filler
  {$EXTERNALSYM EMARCH_ENC_I17_IMM41a_VAL_POS_X}

  EMARCH_ENC_I17_IMM41b_INST_WORD_X     = 1; // Intel-IA64-Filler
  {$EXTERNALSYM EMARCH_ENC_I17_IMM41b_INST_WORD_X}
  EMARCH_ENC_I17_IMM41b_SIZE_X          = 8; // Intel-IA64-Filler
  {$EXTERNALSYM EMARCH_ENC_I17_IMM41b_SIZE_X}
  EMARCH_ENC_I17_IMM41b_INST_WORD_POS_X = 24; // Intel-IA64-Filler
  {$EXTERNALSYM EMARCH_ENC_I17_IMM41b_INST_WORD_POS_X}
  EMARCH_ENC_I17_IMM41b_VAL_POS_X       = 32; // Intel-IA64-Filler
  {$EXTERNALSYM EMARCH_ENC_I17_IMM41b_VAL_POS_X}

  EMARCH_ENC_I17_IMM41c_INST_WORD_X     = 2; // Intel-IA64-Filler
  {$EXTERNALSYM EMARCH_ENC_I17_IMM41c_INST_WORD_X}
  EMARCH_ENC_I17_IMM41c_SIZE_X          = 23; // Intel-IA64-Filler
  {$EXTERNALSYM EMARCH_ENC_I17_IMM41c_SIZE_X}
  EMARCH_ENC_I17_IMM41c_INST_WORD_POS_X = 0; // Intel-IA64-Filler
  {$EXTERNALSYM EMARCH_ENC_I17_IMM41c_INST_WORD_POS_X}
  EMARCH_ENC_I17_IMM41c_VAL_POS_X       = 40; // Intel-IA64-Filler
  {$EXTERNALSYM EMARCH_ENC_I17_IMM41c_VAL_POS_X}

  EMARCH_ENC_I17_SIGN_INST_WORD_X     = 3; // Intel-IA64-Filler
  {$EXTERNALSYM EMARCH_ENC_I17_SIGN_INST_WORD_X}
  EMARCH_ENC_I17_SIGN_SIZE_X          = 1; // Intel-IA64-Filler
  {$EXTERNALSYM EMARCH_ENC_I17_SIGN_SIZE_X}
  EMARCH_ENC_I17_SIGN_INST_WORD_POS_X = 27; // Intel-IA64-Filler
  {$EXTERNALSYM EMARCH_ENC_I17_SIGN_INST_WORD_POS_X}
  EMARCH_ENC_I17_SIGN_VAL_POS_X       = 63; // Intel-IA64-Filler
  {$EXTERNALSYM EMARCH_ENC_I17_SIGN_VAL_POS_X}

//
// Line number format.
//

type
  TImgLineNoType = record
    case Integer of
      0: (SymbolTableIndex: DWORD);               // Symbol table index of function name if Linenumber is 0.
      1: (VirtualAddress: DWORD);                 // Virtual address of line number.
  end;

  PIMAGE_LINENUMBER = ^IMAGE_LINENUMBER;
  {$EXTERNALSYM PIMAGE_LINENUMBER}
  _IMAGE_LINENUMBER = record
    Type_: TImgLineNoType;
    Linenumber: WORD;                         // Line number.
  end;
  {$EXTERNALSYM _IMAGE_LINENUMBER}
  IMAGE_LINENUMBER = _IMAGE_LINENUMBER;
  {$EXTERNALSYM IMAGE_LINENUMBER}
  TImageLineNumber = IMAGE_LINENUMBER;
  PImageLineNumber = PIMAGE_LINENUMBER;

const
  IMAGE_SIZEOF_LINENUMBER = 6;
  {$EXTERNALSYM IMAGE_SIZEOF_LINENUMBER}

// #include "poppack.h"                        // Back to 4 byte packing

//
// Based relocation format.
//

type
  PIMAGE_BASE_RELOCATION = ^IMAGE_BASE_RELOCATION;
  {$EXTERNALSYM PIMAGE_BASE_RELOCATION}
  _IMAGE_BASE_RELOCATION = record
    VirtualAddress: DWORD;
    SizeOfBlock: DWORD;
    //  WORD    TypeOffset[1];
  end;
  {$EXTERNALSYM _IMAGE_BASE_RELOCATION}
  IMAGE_BASE_RELOCATION = _IMAGE_BASE_RELOCATION;
  {$EXTERNALSYM IMAGE_BASE_RELOCATION}
  TImageBaseRelocation = IMAGE_BASE_RELOCATION;
  PImageBaseRelocation = PIMAGE_BASE_RELOCATION;

const
  IMAGE_SIZEOF_BASE_RELOCATION = 8;
  {$EXTERNALSYM IMAGE_SIZEOF_BASE_RELOCATION}

//
// Based relocation types.
//

  IMAGE_REL_BASED_ABSOLUTE     = 0;
  {$EXTERNALSYM IMAGE_REL_BASED_ABSOLUTE}
  IMAGE_REL_BASED_HIGH         = 1;
  {$EXTERNALSYM IMAGE_REL_BASED_HIGH}
  IMAGE_REL_BASED_LOW          = 2;
  {$EXTERNALSYM IMAGE_REL_BASED_LOW}
  IMAGE_REL_BASED_HIGHLOW      = 3;
  {$EXTERNALSYM IMAGE_REL_BASED_HIGHLOW}
  IMAGE_REL_BASED_HIGHADJ      = 4;
  {$EXTERNALSYM IMAGE_REL_BASED_HIGHADJ}
  IMAGE_REL_BASED_MIPS_JMPADDR = 5;
  {$EXTERNALSYM IMAGE_REL_BASED_MIPS_JMPADDR}

  IMAGE_REL_BASED_MIPS_JMPADDR16 = 9;
  {$EXTERNALSYM IMAGE_REL_BASED_MIPS_JMPADDR16}
  IMAGE_REL_BASED_IA64_IMM64     = 9;
  {$EXTERNALSYM IMAGE_REL_BASED_IA64_IMM64}
  IMAGE_REL_BASED_DIR64          = 10;
  {$EXTERNALSYM IMAGE_REL_BASED_DIR64}

//
// Archive format.
//

  IMAGE_ARCHIVE_START_SIZE       = 8;
  {$EXTERNALSYM IMAGE_ARCHIVE_START_SIZE}
  IMAGE_ARCHIVE_START            = '!<arch>\n';
  {$EXTERNALSYM IMAGE_ARCHIVE_START}
  IMAGE_ARCHIVE_END              = '`\n';
  {$EXTERNALSYM IMAGE_ARCHIVE_END}
  IMAGE_ARCHIVE_PAD              = '\n';
  {$EXTERNALSYM IMAGE_ARCHIVE_PAD}
  IMAGE_ARCHIVE_LINKER_MEMBER    = '/               ';
  {$EXTERNALSYM IMAGE_ARCHIVE_LINKER_MEMBER}
  IMAGE_ARCHIVE_LONGNAMES_MEMBER = '//              ';
  {$EXTERNALSYM IMAGE_ARCHIVE_LONGNAMES_MEMBER}

type
  PIMAGE_ARCHIVE_MEMBER_HEADER = ^IMAGE_ARCHIVE_MEMBER_HEADER;
  {$EXTERNALSYM PIMAGE_ARCHIVE_MEMBER_HEADER}
  _IMAGE_ARCHIVE_MEMBER_HEADER = record
    Name: array [0..15] of Byte; // File member name - `/' terminated.
    Date: array [0..11] of Byte; // File member date - decimal.
    UserID: array [0..5] of Byte; // File member user id - decimal.
    GroupID: array [0..5] of Byte; // File member group id - decimal.
    Mode: array [0..7] of Byte; // File member mode - octal.
    Size: array [0..9] of Byte; // File member size - decimal.
    EndHeader: array [0..1] of Byte; // String to end header.
  end;
  {$EXTERNALSYM _IMAGE_ARCHIVE_MEMBER_HEADER}
  IMAGE_ARCHIVE_MEMBER_HEADER = _IMAGE_ARCHIVE_MEMBER_HEADER;
  {$EXTERNALSYM IMAGE_ARCHIVE_MEMBER_HEADER}
  TImageArchiveMemberHeader = IMAGE_ARCHIVE_MEMBER_HEADER;
  PImageArchiveMemberHeader = PIMAGE_ARCHIVE_MEMBER_HEADER;

const
  IMAGE_SIZEOF_ARCHIVE_MEMBER_HDR = 60;
  {$EXTERNALSYM IMAGE_SIZEOF_ARCHIVE_MEMBER_HDR}

//
// DLL support.
//

//
// Export Format
//

type
  PIMAGE_EXPORT_DIRECTORY = ^IMAGE_EXPORT_DIRECTORY;
  {$EXTERNALSYM PIMAGE_EXPORT_DIRECTORY}
  _IMAGE_EXPORT_DIRECTORY = record
    Characteristics: DWORD;
    TimeDateStamp: DWORD;
    MajorVersion: Word;
    MinorVersion: Word;
    Name: DWORD;
    Base: DWORD;
    NumberOfFunctions: DWORD;
    NumberOfNames: DWORD;
    AddressOfFunctions: DWORD; // RVA from base of image
    AddressOfNames: DWORD; // RVA from base of image
    AddressOfNameOrdinals: DWORD; // RVA from base of image
  end;
  {$EXTERNALSYM _IMAGE_EXPORT_DIRECTORY}
  IMAGE_EXPORT_DIRECTORY = _IMAGE_EXPORT_DIRECTORY;
  {$EXTERNALSYM IMAGE_EXPORT_DIRECTORY}
  TImageExportDirectory = IMAGE_EXPORT_DIRECTORY;
  PImageExportDirectory = PIMAGE_EXPORT_DIRECTORY;

//
// Import Format
//

  PIMAGE_IMPORT_BY_NAME = ^IMAGE_IMPORT_BY_NAME;
  {$EXTERNALSYM PIMAGE_IMPORT_BY_NAME}
  _IMAGE_IMPORT_BY_NAME = record
    Hint: Word;
    Name: array [0..0] of Byte;
  end;
  {$EXTERNALSYM _IMAGE_IMPORT_BY_NAME}
  IMAGE_IMPORT_BY_NAME = _IMAGE_IMPORT_BY_NAME;
  {$EXTERNALSYM IMAGE_IMPORT_BY_NAME}
  TImageImportByName = IMAGE_IMPORT_BY_NAME;
  PImageImportByName = PIMAGE_IMPORT_BY_NAME;

// #include "pshpack8.h"                       // Use align 8 for the 64-bit IAT.

  PIMAGE_THUNK_DATA64 = ^IMAGE_THUNK_DATA64;
  {$EXTERNALSYM PIMAGE_THUNK_DATA64}
  _IMAGE_THUNK_DATA64 = record
    case Integer of
      0: (ForwarderString: ULONGLONG);   // PBYTE
      1: (Function_: ULONGLONG);         // PDWORD
      2: (Ordinal: ULONGLONG);
      3: (AddressOfData: ULONGLONG);     // PIMAGE_IMPORT_BY_NAME
  end;
  {$EXTERNALSYM _IMAGE_THUNK_DATA64}
  IMAGE_THUNK_DATA64 = _IMAGE_THUNK_DATA64;
  {$EXTERNALSYM IMAGE_THUNK_DATA64}
  TImageThunkData64 = IMAGE_THUNK_DATA64;
  PImageThunkData64 = PIMAGE_THUNK_DATA64;

// #include "poppack.h"                        // Back to 4 byte packing

  PIMAGE_THUNK_DATA32 = ^IMAGE_THUNK_DATA32;
  {$EXTERNALSYM PIMAGE_THUNK_DATA32}
  _IMAGE_THUNK_DATA32 = record
    case Integer of
      0: (ForwarderString: DWORD);   // PBYTE
      1: (Function_: DWORD);         // PDWORD
      2: (Ordinal: DWORD);
      3: (AddressOfData: DWORD);     // PIMAGE_IMPORT_BY_NAME
  end;
  {$EXTERNALSYM _IMAGE_THUNK_DATA32}
  IMAGE_THUNK_DATA32 = _IMAGE_THUNK_DATA32;
  {$EXTERNALSYM IMAGE_THUNK_DATA32}
  TImageThunkData32 = IMAGE_THUNK_DATA32;
  PImageThunkData32 = PIMAGE_THUNK_DATA32;

const
  IMAGE_ORDINAL_FLAG64 = ULONGLONG($8000000000000000);
  {$EXTERNALSYM IMAGE_ORDINAL_FLAG64}
  IMAGE_ORDINAL_FLAG32 = DWORD($80000000);
  {$EXTERNALSYM IMAGE_ORDINAL_FLAG32}

//
// Thread Local Storage
//

type
  PIMAGE_TLS_CALLBACK = procedure (DllHandle: Pointer; Reason: DWORD; Reserved: Pointer); stdcall;
  {$EXTERNALSYM PIMAGE_TLS_CALLBACK}
  TImageTlsCallback = PIMAGE_TLS_CALLBACK;

  PIMAGE_TLS_DIRECTORY64 = ^IMAGE_TLS_DIRECTORY64;
  {$EXTERNALSYM PIMAGE_TLS_DIRECTORY64}
  _IMAGE_TLS_DIRECTORY64 = record
    StartAddressOfRawData: ULONGLONG;
    EndAddressOfRawData: ULONGLONG;
    AddressOfIndex: ULONGLONG;         // PDWORD
    AddressOfCallBacks: ULONGLONG;     // PIMAGE_TLS_CALLBACK *;
    SizeOfZeroFill: DWORD;
    Characteristics: DWORD;
  end;
  {$EXTERNALSYM _IMAGE_TLS_DIRECTORY64}
  IMAGE_TLS_DIRECTORY64 = _IMAGE_TLS_DIRECTORY64;
  {$EXTERNALSYM IMAGE_TLS_DIRECTORY64}
  TImageTlsDirectory64 = IMAGE_TLS_DIRECTORY64;
  PImageTlsDirectory64 = PIMAGE_TLS_DIRECTORY64;

  PIMAGE_TLS_DIRECTORY32 = ^IMAGE_TLS_DIRECTORY32;
  {$EXTERNALSYM PIMAGE_TLS_DIRECTORY32}
  _IMAGE_TLS_DIRECTORY32 = record
    StartAddressOfRawData: DWORD;
    EndAddressOfRawData: DWORD;
    AddressOfIndex: DWORD;             // PDWORD
    AddressOfCallBacks: DWORD;         // PIMAGE_TLS_CALLBACK *
    SizeOfZeroFill: DWORD;
    Characteristics: DWORD;
  end;
  {$EXTERNALSYM _IMAGE_TLS_DIRECTORY32}
  IMAGE_TLS_DIRECTORY32 = _IMAGE_TLS_DIRECTORY32;
  {$EXTERNALSYM IMAGE_TLS_DIRECTORY32}
  TImageTlsDirectory32 = IMAGE_TLS_DIRECTORY32;
  PImageTlsDirectory32 = PIMAGE_TLS_DIRECTORY32;

const
  IMAGE_ORDINAL_FLAG = IMAGE_ORDINAL_FLAG32;
  {$EXTERNALSYM IMAGE_ORDINAL_FLAG}

type
  IMAGE_THUNK_DATA = IMAGE_THUNK_DATA32;
  {$EXTERNALSYM IMAGE_THUNK_DATA}
  PIMAGE_THUNK_DATA = PIMAGE_THUNK_DATA32;
  {$EXTERNALSYM PIMAGE_THUNK_DATA}
  TImageThunkData = TImageThunkData32;
  PImageThunkData = PImageThunkData32;

type
  IMAGE_TLS_DIRECTORY = IMAGE_TLS_DIRECTORY32;
  {$EXTERNALSYM IMAGE_TLS_DIRECTORY}
  PIMAGE_TLS_DIRECTORY = PIMAGE_TLS_DIRECTORY32;
  {$EXTERNALSYM PIMAGE_TLS_DIRECTORY}
  TImageTlsDirectory = TImageTlsDirectory32;
  PImageTlsDirectory = PImageTlsDirectory32;

  TIIDUnion = record
    case Integer of
      0: (Characteristics: DWORD);         // 0 for terminating null import descriptor
      1: (OriginalFirstThunk: DWORD);      // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
  end;

  PIMAGE_IMPORT_DESCRIPTOR = ^IMAGE_IMPORT_DESCRIPTOR;
  {$EXTERNALSYM PIMAGE_IMPORT_DESCRIPTOR}
  _IMAGE_IMPORT_DESCRIPTOR = record
    Union: TIIDUnion;
    TimeDateStamp: DWORD;                  // 0 if not bound,
                                           // -1 if bound, and real date\time stamp
                                           //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                           // O.W. date/time stamp of DLL bound to (Old BIND)

    ForwarderChain: DWORD;                 // -1 if no forwarders
    Name: DWORD;
    FirstThunk: DWORD;                     // RVA to IAT (if bound this IAT has actual addresses)
  end;
  {$EXTERNALSYM _IMAGE_IMPORT_DESCRIPTOR}
  IMAGE_IMPORT_DESCRIPTOR = _IMAGE_IMPORT_DESCRIPTOR;
  {$EXTERNALSYM IMAGE_IMPORT_DESCRIPTOR}
  TImageImportDecriptor = IMAGE_IMPORT_DESCRIPTOR;
  PImageImportDecriptor = PIMAGE_IMPORT_DESCRIPTOR;

//
// New format import descriptors pointed to by DataDirectory[ IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT ]
//

type
  PIMAGE_BOUND_IMPORT_DESCRIPTOR = ^IMAGE_BOUND_IMPORT_DESCRIPTOR;
  {$EXTERNALSYM PIMAGE_BOUND_IMPORT_DESCRIPTOR}
  _IMAGE_BOUND_IMPORT_DESCRIPTOR = record
    TimeDateStamp: DWORD;
    OffsetModuleName: Word;
    NumberOfModuleForwarderRefs: Word;
    // Array of zero or more IMAGE_BOUND_FORWARDER_REF follows
  end;
  {$EXTERNALSYM _IMAGE_BOUND_IMPORT_DESCRIPTOR}
  IMAGE_BOUND_IMPORT_DESCRIPTOR = _IMAGE_BOUND_IMPORT_DESCRIPTOR;
  {$EXTERNALSYM IMAGE_BOUND_IMPORT_DESCRIPTOR}
  TImageBoundImportDescriptor = IMAGE_BOUND_IMPORT_DESCRIPTOR;
  PImageBoundImportDescriptor = PIMAGE_BOUND_IMPORT_DESCRIPTOR;

  PIMAGE_BOUND_FORWARDER_REF = ^IMAGE_BOUND_FORWARDER_REF;
  {$EXTERNALSYM PIMAGE_BOUND_FORWARDER_REF}
  _IMAGE_BOUND_FORWARDER_REF = record
    TimeDateStamp: DWORD;
    OffsetModuleName: Word;
    Reserved: Word;
  end;
  {$EXTERNALSYM _IMAGE_BOUND_FORWARDER_REF}
  IMAGE_BOUND_FORWARDER_REF = _IMAGE_BOUND_FORWARDER_REF;
  {$EXTERNALSYM IMAGE_BOUND_FORWARDER_REF}
  TImageBoundForwarderRef = IMAGE_BOUND_FORWARDER_REF;
  PImageBoundForwarderRef = PIMAGE_BOUND_FORWARDER_REF;

//
// Resource Format.
//

//
// Resource directory consists of two counts, following by a variable length
// array of directory entries.  The first count is the number of entries at
// beginning of the array that have actual names associated with each entry.
// The entries are in ascending order, case insensitive strings.  The second
// count is the number of entries that immediately follow the named entries.
// This second count identifies the number of entries that have 16-bit integer
// Ids as their name.  These entries are also sorted in ascending order.
//
// This structure allows fast lookup by either name or number, but for any
// given resource entry only one form of lookup is supported, not both.
// This is consistant with the syntax of the .RC file and the .RES file.
//

  PIMAGE_RESOURCE_DIRECTORY = ^IMAGE_RESOURCE_DIRECTORY;
  {$EXTERNALSYM PIMAGE_RESOURCE_DIRECTORY}
  _IMAGE_RESOURCE_DIRECTORY = record
    Characteristics: DWORD;
    TimeDateStamp: DWORD;
    MajorVersion: Word;
    MinorVersion: Word;
    NumberOfNamedEntries: Word;
    NumberOfIdEntries: Word;
    // IMAGE_RESOURCE_DIRECTORY_ENTRY DirectoryEntries[];
  end;
  {$EXTERNALSYM _IMAGE_RESOURCE_DIRECTORY}
  IMAGE_RESOURCE_DIRECTORY = _IMAGE_RESOURCE_DIRECTORY;
  {$EXTERNALSYM IMAGE_RESOURCE_DIRECTORY}
  TImageResourceDirectory = IMAGE_RESOURCE_DIRECTORY;
  PImageResourceDirectory = PIMAGE_RESOURCE_DIRECTORY;

const
  IMAGE_RESOURCE_NAME_IS_STRING    = DWORD($80000000);
  {$EXTERNALSYM IMAGE_RESOURCE_NAME_IS_STRING}
  IMAGE_RESOURCE_DATA_IS_DIRECTORY = DWORD($80000000);
  {$EXTERNALSYM IMAGE_RESOURCE_DATA_IS_DIRECTORY}

//
// Each directory contains the 32-bit Name of the entry and an offset,
// relative to the beginning of the resource directory of the data associated
// with this directory entry.  If the name of the entry is an actual text
// string instead of an integer Id, then the high order bit of the name field
// is set to one and the low order 31-bits are an offset, relative to the
// beginning of the resource directory of the string, which is of type
// IMAGE_RESOURCE_DIRECTORY_STRING.  Otherwise the high bit is clear and the
// low-order 16-bits are the integer Id that identify this resource directory
// entry. If the directory entry is yet another resource directory (i.e. a
// subdirectory), then the high order bit of the offset field will be
// set to indicate this.  Otherwise the high bit is clear and the offset
// field points to a resource data entry.
//

type
  TIRDEName = record
    case Integer of
      0: (
        NameOffset: DWORD); // 0..30: NameOffset; 31: NameIsString
      1: (
        Name: DWORD);
      2: (
        Id: WORD);
  end;

  TIRDEDirectory = record
    case Integer of
      0: (
        OffsetToData: DWORD);
      1: (
        OffsetToDirectory: DWORD); // 0..30: OffsetToDirectory; 31: DataIsDirectory
  end;

  PIMAGE_RESOURCE_DIRECTORY_ENTRY = ^IMAGE_RESOURCE_DIRECTORY_ENTRY;
  {$EXTERNALSYM PIMAGE_RESOURCE_DIRECTORY_ENTRY}
  _IMAGE_RESOURCE_DIRECTORY_ENTRY = record
    Name: TIRDEName;
    Directory: TIRDEDirectory;
  end;
  {$EXTERNALSYM _IMAGE_RESOURCE_DIRECTORY_ENTRY}
  IMAGE_RESOURCE_DIRECTORY_ENTRY = _IMAGE_RESOURCE_DIRECTORY_ENTRY;
  {$EXTERNALSYM IMAGE_RESOURCE_DIRECTORY_ENTRY}
  TImageResourceDirectoryEntry = IMAGE_RESOURCE_DIRECTORY_ENTRY;
  PImageResourceDirectoryEntry = PIMAGE_RESOURCE_DIRECTORY_ENTRY;

//
// For resource directory entries that have actual string names, the Name
// field of the directory entry points to an object of the following type.
// All of these string objects are stored together after the last resource
// directory entry and before the first resource data object.  This minimizes
// the impact of these variable length objects on the alignment of the fixed
// size directory entry objects.
//

type
  PIMAGE_RESOURCE_DIRECTORY_STRING = ^IMAGE_RESOURCE_DIRECTORY_STRING;
  {$EXTERNALSYM PIMAGE_RESOURCE_DIRECTORY_STRING}
  _IMAGE_RESOURCE_DIRECTORY_STRING = record
    Length: Word;
    NameString: array [0..0] of CHAR;
  end;
  {$EXTERNALSYM _IMAGE_RESOURCE_DIRECTORY_STRING}
  IMAGE_RESOURCE_DIRECTORY_STRING = _IMAGE_RESOURCE_DIRECTORY_STRING;
  {$EXTERNALSYM IMAGE_RESOURCE_DIRECTORY_STRING}
  TImageResourceDirectoryString = IMAGE_RESOURCE_DIRECTORY_STRING;
  PImageResourceDirectoryString = PIMAGE_RESOURCE_DIRECTORY_STRING;

  PIMAGE_RESOURCE_DIR_STRING_U = ^IMAGE_RESOURCE_DIR_STRING_U;
  {$EXTERNALSYM PIMAGE_RESOURCE_DIR_STRING_U}
  _IMAGE_RESOURCE_DIR_STRING_U = record
    Length: Word;
    NameString: array [0..0] of WCHAR;
  end;
  {$EXTERNALSYM _IMAGE_RESOURCE_DIR_STRING_U}
  IMAGE_RESOURCE_DIR_STRING_U = _IMAGE_RESOURCE_DIR_STRING_U;
  {$EXTERNALSYM IMAGE_RESOURCE_DIR_STRING_U}
  TImageResourceDirStringU = IMAGE_RESOURCE_DIR_STRING_U;
  PImageResourceDirStringU = PIMAGE_RESOURCE_DIR_STRING_U;

//
// Each resource data entry describes a leaf node in the resource directory
// tree.  It contains an offset, relative to the beginning of the resource
// directory of the data for the resource, a size field that gives the number
// of bytes of data at that offset, a CodePage that should be used when
// decoding code point values within the resource data.  Typically for new
// applications the code page would be the unicode code page.
//

  PIMAGE_RESOURCE_DATA_ENTRY = ^IMAGE_RESOURCE_DATA_ENTRY;
  {$EXTERNALSYM PIMAGE_RESOURCE_DATA_ENTRY}
  _IMAGE_RESOURCE_DATA_ENTRY = record
    OffsetToData: DWORD;
    Size: DWORD;
    CodePage: DWORD;
    Reserved: DWORD;
  end;
  {$EXTERNALSYM _IMAGE_RESOURCE_DATA_ENTRY}
  IMAGE_RESOURCE_DATA_ENTRY = _IMAGE_RESOURCE_DATA_ENTRY;
  {$EXTERNALSYM IMAGE_RESOURCE_DATA_ENTRY}
  TImageResourceDataEntry = IMAGE_RESOURCE_DATA_ENTRY;
  PImageResourceDataEntry = PIMAGE_RESOURCE_DATA_ENTRY;

//
// Load Configuration Directory Entry
//

type
  PIMAGE_LOAD_CONFIG_DIRECTORY32 = ^IMAGE_LOAD_CONFIG_DIRECTORY32;
  {$EXTERNALSYM PIMAGE_LOAD_CONFIG_DIRECTORY32}
  IMAGE_LOAD_CONFIG_DIRECTORY32 = record
    Characteristics: DWORD;
    TimeDateStamp: DWORD;
    MajorVersion: WORD;
    MinorVersion: WORD;
    GlobalFlagsClear: DWORD;
    GlobalFlagsSet: DWORD;
    CriticalSectionDefaultTimeout: DWORD;
    DeCommitFreeBlockThreshold: DWORD;
    DeCommitTotalFreeThreshold: DWORD;
    LockPrefixTable: DWORD;            // VA
    MaximumAllocationSize: DWORD;
    VirtualMemoryThreshold: DWORD;
    ProcessHeapFlags: DWORD;
    ProcessAffinityMask: DWORD;
    CSDVersion: WORD;
    Reserved1: WORD;
    EditList: DWORD;                   // VA
    Reserved: array [0..0] of DWORD;
  end;
  {$EXTERNALSYM IMAGE_LOAD_CONFIG_DIRECTORY32}
  TImageLoadConfigDirectory32 = IMAGE_LOAD_CONFIG_DIRECTORY32;
  PImageLoadConfigDirectory32 = PIMAGE_LOAD_CONFIG_DIRECTORY32;

  PIMAGE_LOAD_CONFIG_DIRECTORY64 = ^IMAGE_LOAD_CONFIG_DIRECTORY64;
  {$EXTERNALSYM PIMAGE_LOAD_CONFIG_DIRECTORY64}
  IMAGE_LOAD_CONFIG_DIRECTORY64 = record
    Characteristics: DWORD;
    TimeDateStamp: DWORD;
    MajorVersion: WORD;
    MinorVersion: WORD;
    GlobalFlagsClear: DWORD;
    GlobalFlagsSet: DWORD;
    CriticalSectionDefaultTimeout: DWORD;
    DeCommitFreeBlockThreshold: ULONGLONG;
    DeCommitTotalFreeThreshold: ULONGLONG;
    LockPrefixTable: ULONGLONG;         // VA
    MaximumAllocationSize: ULONGLONG;
    VirtualMemoryThreshold: ULONGLONG;
    ProcessAffinityMask: ULONGLONG;
    ProcessHeapFlags: DWORD;
    CSDVersion: WORD;
    Reserved1: WORD;
    EditList: ULONGLONG;                // VA
    Reserved: array [0..1] of DWORD;
  end;
  {$EXTERNALSYM IMAGE_LOAD_CONFIG_DIRECTORY64}
  TImageLoadConfigDirectory64 = IMAGE_LOAD_CONFIG_DIRECTORY64;
  PImageLoadConfigDirectory64 = PIMAGE_LOAD_CONFIG_DIRECTORY64;

  IMAGE_LOAD_CONFIG_DIRECTORY = IMAGE_LOAD_CONFIG_DIRECTORY32;
  {$EXTERNALSYM IMAGE_LOAD_CONFIG_DIRECTORY}
  PIMAGE_LOAD_CONFIG_DIRECTORY = PIMAGE_LOAD_CONFIG_DIRECTORY32;
  {$EXTERNALSYM PIMAGE_LOAD_CONFIG_DIRECTORY}
  TImageLoadConfigDirectory = TImageLoadConfigDirectory32;
  PImageLoadConfigDirectory = PImageLoadConfigDirectory32;

//
// WIN CE Exception table format
//

//
// Function table entry format.  Function table is pointed to by the
// IMAGE_DIRECTORY_ENTRY_EXCEPTION directory entry.
//

type
  PIMAGE_CE_RUNTIME_FUNCTION_ENTRY = ^IMAGE_CE_RUNTIME_FUNCTION_ENTRY;
  {$EXTERNALSYM PIMAGE_CE_RUNTIME_FUNCTION_ENTRY}
  _IMAGE_CE_RUNTIME_FUNCTION_ENTRY = record
    FuncStart: DWORD;
    Flags: DWORD;
    //DWORD PrologLen : 8;
    //DWORD FuncLen : 22;
    //DWORD ThirtyTwoBit : 1;
    //DWORD ExceptionFlag : 1;
  end;
  {$EXTERNALSYM _IMAGE_CE_RUNTIME_FUNCTION_ENTRY}
  IMAGE_CE_RUNTIME_FUNCTION_ENTRY = _IMAGE_CE_RUNTIME_FUNCTION_ENTRY;
  {$EXTERNALSYM IMAGE_CE_RUNTIME_FUNCTION_ENTRY}
  TImageCERuntimeFunctionEntry = IMAGE_CE_RUNTIME_FUNCTION_ENTRY;
  PImageCERuntimeFunctionEntry = PIMAGE_CE_RUNTIME_FUNCTION_ENTRY;

//
// Debug Format
//

type
  PIMAGE_DEBUG_DIRECTORY = ^IMAGE_DEBUG_DIRECTORY;
  {$EXTERNALSYM PIMAGE_DEBUG_DIRECTORY}
  _IMAGE_DEBUG_DIRECTORY = record
    Characteristics: DWORD;
    TimeDateStamp: DWORD;
    MajorVersion: Word;
    MinorVersion: Word;
    Type_: DWORD;
    SizeOfData: DWORD;
    AddressOfRawData: DWORD;
    PointerToRawData: DWORD;
  end;
  {$EXTERNALSYM _IMAGE_DEBUG_DIRECTORY}
  IMAGE_DEBUG_DIRECTORY = _IMAGE_DEBUG_DIRECTORY;
  {$EXTERNALSYM IMAGE_DEBUG_DIRECTORY}
  TImageDebugDirectory = IMAGE_DEBUG_DIRECTORY;
  PImageDebugDirectory = PIMAGE_DEBUG_DIRECTORY;

const
  IMAGE_DEBUG_TYPE_UNKNOWN       = 0;
  {$EXTERNALSYM IMAGE_DEBUG_TYPE_UNKNOWN}
  IMAGE_DEBUG_TYPE_COFF          = 1;
  {$EXTERNALSYM IMAGE_DEBUG_TYPE_COFF}
  IMAGE_DEBUG_TYPE_CODEVIEW      = 2;
  {$EXTERNALSYM IMAGE_DEBUG_TYPE_CODEVIEW}
  IMAGE_DEBUG_TYPE_FPO           = 3;
  {$EXTERNALSYM IMAGE_DEBUG_TYPE_FPO}
  IMAGE_DEBUG_TYPE_MISC          = 4;
  {$EXTERNALSYM IMAGE_DEBUG_TYPE_MISC}
  IMAGE_DEBUG_TYPE_EXCEPTION     = 5;
  {$EXTERNALSYM IMAGE_DEBUG_TYPE_EXCEPTION}
  IMAGE_DEBUG_TYPE_FIXUP         = 6;
  {$EXTERNALSYM IMAGE_DEBUG_TYPE_FIXUP}
  IMAGE_DEBUG_TYPE_OMAP_TO_SRC   = 7;
  {$EXTERNALSYM IMAGE_DEBUG_TYPE_OMAP_TO_SRC}
  IMAGE_DEBUG_TYPE_OMAP_FROM_SRC = 8;
  {$EXTERNALSYM IMAGE_DEBUG_TYPE_OMAP_FROM_SRC}
  IMAGE_DEBUG_TYPE_BORLAND       = 9;
  {$EXTERNALSYM IMAGE_DEBUG_TYPE_BORLAND}
  IMAGE_DEBUG_TYPE_RESERVED10    = 10;
  {$EXTERNALSYM IMAGE_DEBUG_TYPE_RESERVED10}
  IMAGE_DEBUG_TYPE_CLSID         = 11;
  {$EXTERNALSYM IMAGE_DEBUG_TYPE_CLSID}

type
  PIMAGE_COFF_SYMBOLS_HEADER = ^IMAGE_COFF_SYMBOLS_HEADER;
  {$EXTERNALSYM PIMAGE_COFF_SYMBOLS_HEADER}
  _IMAGE_COFF_SYMBOLS_HEADER = record
    NumberOfSymbols: DWORD;
    LvaToFirstSymbol: DWORD;
    NumberOfLinenumbers: DWORD;
    LvaToFirstLinenumber: DWORD;
    RvaToFirstByteOfCode: DWORD;
    RvaToLastByteOfCode: DWORD;
    RvaToFirstByteOfData: DWORD;
    RvaToLastByteOfData: DWORD;
  end;
  {$EXTERNALSYM _IMAGE_COFF_SYMBOLS_HEADER}
  IMAGE_COFF_SYMBOLS_HEADER = _IMAGE_COFF_SYMBOLS_HEADER;
  {$EXTERNALSYM IMAGE_COFF_SYMBOLS_HEADER}
  TImageCoffSymbolsHeader = IMAGE_COFF_SYMBOLS_HEADER;
  PImageCoffSymbolsHeader = PIMAGE_COFF_SYMBOLS_HEADER;

const
  FRAME_FPO    = 0;
  {$EXTERNALSYM FRAME_FPO}
  FRAME_TRAP   = 1;
  {$EXTERNALSYM FRAME_TRAP}
  FRAME_TSS    = 2;
  {$EXTERNALSYM FRAME_TSS}
  FRAME_NONFPO = 3;
  {$EXTERNALSYM FRAME_NONFPO}

  FPOFLAGS_PROLOG   = $00FF; // # bytes in prolog
  FPOFLAGS_REGS     = $0700; // # regs saved
  FPOFLAGS_HAS_SEH  = $0800; // TRUE if SEH in func
  FPOFLAGS_USE_BP   = $1000; // TRUE if EBP has been allocated
  FPOFLAGS_RESERVED = $2000; // reserved for future use
  FPOFLAGS_FRAME    = $C000; // frame type

type
  PFPO_DATA = ^FPO_DATA;
  {$EXTERNALSYM PFPO_DATA}
  _FPO_DATA = record
    ulOffStart: DWORD;       // offset 1st byte of function code
    cbProcSize: DWORD;       // # bytes in function
    cdwLocals: DWORD;        // # bytes in locals/4
    cdwParams: WORD;         // # bytes in params/4
    Flags: WORD;
  end;
  {$EXTERNALSYM _FPO_DATA}
  FPO_DATA = _FPO_DATA;
  {$EXTERNALSYM FPO_DATA}
  TFpoData = FPO_DATA;
  PFpoData = PFPO_DATA;

const
  SIZEOF_RFPO_DATA = 16;
  {$EXTERNALSYM SIZEOF_RFPO_DATA}

  IMAGE_DEBUG_MISC_EXENAME = 1;
  {$EXTERNALSYM IMAGE_DEBUG_MISC_EXENAME}

type
  PIMAGE_DEBUG_MISC = ^IMAGE_DEBUG_MISC;
  {$EXTERNALSYM PIMAGE_DEBUG_MISC}
  _IMAGE_DEBUG_MISC = record
    DataType: DWORD;   // type of misc data, see defines
    Length: DWORD;     // total length of record, rounded to four byte multiple.
    Unicode: ByteBool; // TRUE if data is unicode string
    Reserved: array [0..2] of Byte;
    Data: array [0..0] of Byte; // Actual data
  end;
  {$EXTERNALSYM _IMAGE_DEBUG_MISC}
  IMAGE_DEBUG_MISC = _IMAGE_DEBUG_MISC;
  {$EXTERNALSYM IMAGE_DEBUG_MISC}
  TImageDebugMisc = IMAGE_DEBUG_MISC;
  PImageDebugMisc = PIMAGE_DEBUG_MISC;

//
// Function table extracted from MIPS/ALPHA/IA64 images.  Does not contain
// information needed only for runtime support.  Just those fields for
// each entry needed by a debugger.
//

  PIMAGE_FUNCTION_ENTRY = ^IMAGE_FUNCTION_ENTRY;
  {$EXTERNALSYM PIMAGE_FUNCTION_ENTRY}
  _IMAGE_FUNCTION_ENTRY = record
    StartingAddress: DWORD;
    EndingAddress: DWORD;
    EndOfPrologue: DWORD;
  end;
  {$EXTERNALSYM _IMAGE_FUNCTION_ENTRY}
  IMAGE_FUNCTION_ENTRY = _IMAGE_FUNCTION_ENTRY;
  {$EXTERNALSYM IMAGE_FUNCTION_ENTRY}
  TImageFunctionEntry = IMAGE_FUNCTION_ENTRY;
  PImageFunctionEntry = PIMAGE_FUNCTION_ENTRY;

  PIMAGE_FUNCTION_ENTRY64 = ^IMAGE_FUNCTION_ENTRY64;
  {$EXTERNALSYM PIMAGE_FUNCTION_ENTRY64}
  _IMAGE_FUNCTION_ENTRY64 = record
    StartingAddress: ULONGLONG;
    EndingAddress: ULONGLONG;
    case Integer of
      0: (EndOfPrologue: ULONGLONG);
      1: (UnwindInfoAddress: ULONGLONG);
  end;
  {$EXTERNALSYM _IMAGE_FUNCTION_ENTRY64}
  IMAGE_FUNCTION_ENTRY64 = _IMAGE_FUNCTION_ENTRY64;
  {$EXTERNALSYM IMAGE_FUNCTION_ENTRY64}
  TImageFunctionEntry64 = IMAGE_FUNCTION_ENTRY64;
  PImageFunctionEntry64 = PIMAGE_FUNCTION_ENTRY64;

//
// Debugging information can be stripped from an image file and placed
// in a separate .DBG file, whose file name part is the same as the
// image file name part (e.g. symbols for CMD.EXE could be stripped
// and placed in CMD.DBG).  This is indicated by the IMAGE_FILE_DEBUG_STRIPPED
// flag in the Characteristics field of the file header.  The beginning of
// the .DBG file contains the following structure which captures certain
// information from the image file.  This allows a debug to proceed even if
// the original image file is not accessable.  This header is followed by
// zero of more IMAGE_SECTION_HEADER structures, followed by zero or more
// IMAGE_DEBUG_DIRECTORY structures.  The latter structures and those in
// the image file contain file offsets relative to the beginning of the
// .DBG file.
//
// If symbols have been stripped from an image, the IMAGE_DEBUG_MISC structure
// is left in the image file, but not mapped.  This allows a debugger to
// compute the name of the .DBG file, from the name of the image in the
// IMAGE_DEBUG_MISC structure.
//

  PIMAGE_SEPARATE_DEBUG_HEADER = ^IMAGE_SEPARATE_DEBUG_HEADER;
  {$EXTERNALSYM PIMAGE_SEPARATE_DEBUG_HEADER}
  _IMAGE_SEPARATE_DEBUG_HEADER = record
    Signature: Word;
    Flags: Word;
    Machine: Word;
    Characteristics: Word;
    TimeDateStamp: DWORD;
    CheckSum: DWORD;
    ImageBase: DWORD;
    SizeOfImage: DWORD;
    NumberOfSections: DWORD;
    ExportedNamesSize: DWORD;
    DebugDirectorySize: DWORD;
    SectionAlignment: DWORD;
    Reserved: array [0..1] of DWORD;
  end;
  {$EXTERNALSYM _IMAGE_SEPARATE_DEBUG_HEADER}
  IMAGE_SEPARATE_DEBUG_HEADER = _IMAGE_SEPARATE_DEBUG_HEADER;
  {$EXTERNALSYM IMAGE_SEPARATE_DEBUG_HEADER}
  TImageSeparateDebugHeader = IMAGE_SEPARATE_DEBUG_HEADER;
  PImageSeparateDebugHeader = PIMAGE_SEPARATE_DEBUG_HEADER;

  _NON_PAGED_DEBUG_INFO = record
    Signature: WORD;
    Flags: WORD;
    Size: DWORD;
    Machine: WORD;
    Characteristics: WORD;
    TimeDateStamp: DWORD;
    CheckSum: DWORD;
    SizeOfImage: DWORD;
    ImageBase: ULONGLONG;
    //DebugDirectorySize
    //IMAGE_DEBUG_DIRECTORY
  end;
  {$EXTERNALSYM _NON_PAGED_DEBUG_INFO}
  NON_PAGED_DEBUG_INFO = _NON_PAGED_DEBUG_INFO;
  {$EXTERNALSYM NON_PAGED_DEBUG_INFO}
  PNON_PAGED_DEBUG_INFO = ^NON_PAGED_DEBUG_INFO;
  {$EXTERNALSYM PNON_PAGED_DEBUG_INFO}

const
  IMAGE_SEPARATE_DEBUG_SIGNATURE = $4944;
  {$EXTERNALSYM IMAGE_SEPARATE_DEBUG_SIGNATURE}
  NON_PAGED_DEBUG_SIGNATURE      = $494E;
  {$EXTERNALSYM NON_PAGED_DEBUG_SIGNATURE}

  IMAGE_SEPARATE_DEBUG_FLAGS_MASK = $8000;
  {$EXTERNALSYM IMAGE_SEPARATE_DEBUG_FLAGS_MASK}
  IMAGE_SEPARATE_DEBUG_MISMATCH   = $8000; // when DBG was updated, the old checksum didn't match.
  {$EXTERNALSYM IMAGE_SEPARATE_DEBUG_MISMATCH}

//
//  The .arch section is made up of headers, each describing an amask position/value
//  pointing to an array of IMAGE_ARCHITECTURE_ENTRY's.  Each "array" (both the header
//  and entry arrays) are terminiated by a quadword of 0xffffffffL.
//
//  NOTE: There may be quadwords of 0 sprinkled around and must be skipped.
//

const
  IAHMASK_VALUE = $00000001; // 1 -> code section depends on mask bit
                             // 0 -> new instruction depends on mask bit
  IAHMASK_MBZ7  = $000000FE; // MBZ
  IAHMASK_SHIFT = $0000FF00; // Amask bit in question for this fixup
  IAHMASK_MBZ16 = DWORD($FFFF0000); // MBZ

type
  PIMAGE_ARCHITECTURE_HEADER = ^IMAGE_ARCHITECTURE_HEADER;
  {$EXTERNALSYM PIMAGE_ARCHITECTURE_HEADER}
  _ImageArchitectureHeader = record
    Mask: DWORD;
    FirstEntryRVA: DWORD;    // RVA into .arch section to array of ARCHITECTURE_ENTRY's
  end;
  {$EXTERNALSYM _ImageArchitectureHeader}
  IMAGE_ARCHITECTURE_HEADER = _ImageArchitectureHeader;
  {$EXTERNALSYM IMAGE_ARCHITECTURE_HEADER}
  TImageArchitectureHeader = IMAGE_ARCHITECTURE_HEADER;
  PImageArchitectureHeader = PIMAGE_ARCHITECTURE_HEADER;

  PIMAGE_ARCHITECTURE_ENTRY = ^IMAGE_ARCHITECTURE_ENTRY;
  {$EXTERNALSYM PIMAGE_ARCHITECTURE_ENTRY}
  _ImageArchitectureEntry = record
    FixupInstRVA: DWORD;                         // RVA of instruction to fixup
    NewInst: DWORD;                              // fixup instruction (see alphaops.h)
  end;
  {$EXTERNALSYM _ImageArchitectureEntry}
  IMAGE_ARCHITECTURE_ENTRY = _ImageArchitectureEntry;
  {$EXTERNALSYM IMAGE_ARCHITECTURE_ENTRY}
  TImageArchitectureEntry = IMAGE_ARCHITECTURE_ENTRY;
  PImageArchitectureEntry = PIMAGE_ARCHITECTURE_ENTRY;

// #include "poppack.h"                // Back to the initial value


// The following structure defines the new import object.  Note the values of the first two fields,
// which must be set as stated in order to differentiate old and new import members.
// Following this structure, the linker emits two null-terminated strings used to recreate the
// import at the time of use.  The first string is the import's name, the second is the dll's name.

const
  IMPORT_OBJECT_HDR_SIG2 = $ffff;
  {$EXTERNALSYM IMPORT_OBJECT_HDR_SIG2}

const
  IOHFLAGS_TYPE = $0003;      // IMPORT_TYPE
  IAHFLAGS_NAMETYPE = $001C;  // IMPORT_NAME_TYPE
  IAHFLAGS_RESERVED = $FFE0;  // Reserved. Must be zero.

type
  PImportObjectHeader = ^IMPORT_OBJECT_HEADER;
  IMPORT_OBJECT_HEADER = record
    Sig1: WORD;                       // Must be IMAGE_FILE_MACHINE_UNKNOWN
    Sig2: WORD;                       // Must be IMPORT_OBJECT_HDR_SIG2.
    Version: WORD;
    Machine: WORD;
    TimeDateStamp: DWORD;             // Time/date stamp
    SizeOfData: DWORD;                // particularly useful for incremental links
    OrdinalOrHint: record
    case Integer of
      0: (Ordinal: WORD);             // if grf & IMPORT_OBJECT_ORDINAL
      1: (Flags: DWORD);
    end;
    Flags: WORD;
    //WORD    Type : 2;                   // IMPORT_TYPE
    //WORD    NameType : 3;               // IMPORT_NAME_TYPE
    //WORD    Reserved : 11;              // Reserved. Must be zero.
  end;
  {$EXTERNALSYM IMPORT_OBJECT_HEADER}
  TImportObjectHeader = IMPORT_OBJECT_HEADER;

  IMPORT_OBJECT_TYPE = (IMPORT_OBJECT_CODE, IMPORT_OBJECT_DATA, IMPORT_OBJECT_CONST);
  {$EXTERNALSYM IMPORT_OBJECT_TYPE}
  TImportObjectType = IMPORT_OBJECT_TYPE;

  IMPORT_OBJECT_NAME_TYPE = (
    IMPORT_OBJECT_ORDINAL,          // Import by ordinal
    IMPORT_OBJECT_NAME,             // Import name == public symbol name.
    IMPORT_OBJECT_NAME_NO_PREFIX,   // Import name == public symbol name skipping leading ?, @, or optionally _.
    IMPORT_OBJECT_NAME_UNDECORATE); // Import name == public symbol name skipping leading ?, @, or optionally _
                                    // and truncating at first @
  {$EXTERNALSYM IMPORT_OBJECT_NAME_TYPE}
  TImportObjectNameType = IMPORT_OBJECT_NAME_TYPE;

  ReplacesCorHdrNumericDefines = DWORD;
  {$EXTERNALSYM ReplacesCorHdrNumericDefines}

const

// COM+ Header entry point flags.

  COMIMAGE_FLAGS_ILONLY               = $00000001;
  {$EXTERNALSYM COMIMAGE_FLAGS_ILONLY}
  COMIMAGE_FLAGS_32BITREQUIRED        = $00000002;
  {$EXTERNALSYM COMIMAGE_FLAGS_32BITREQUIRED}
  COMIMAGE_FLAGS_IL_LIBRARY           = $00000004;
  {$EXTERNALSYM COMIMAGE_FLAGS_IL_LIBRARY}
  COMIMAGE_FLAGS_STRONGNAMESIGNED     = $00000008;
  {$EXTERNALSYM COMIMAGE_FLAGS_STRONGNAMESIGNED}
  COMIMAGE_FLAGS_TRACKDEBUGDATA       = $00010000;
  {$EXTERNALSYM COMIMAGE_FLAGS_TRACKDEBUGDATA}

// Version flags for image.

  COR_VERSION_MAJOR_V2                = 2;
  {$EXTERNALSYM COR_VERSION_MAJOR_V2}
  COR_VERSION_MAJOR                   = COR_VERSION_MAJOR_V2;
  {$EXTERNALSYM COR_VERSION_MAJOR}
  COR_VERSION_MINOR                   = 0;
  {$EXTERNALSYM COR_VERSION_MINOR}
  COR_DELETED_NAME_LENGTH             = 8;
  {$EXTERNALSYM COR_DELETED_NAME_LENGTH}
  COR_VTABLEGAP_NAME_LENGTH           = 8;
  {$EXTERNALSYM COR_VTABLEGAP_NAME_LENGTH}

// Maximum size of a NativeType descriptor.

  NATIVE_TYPE_MAX_CB                  = 1;
  {$EXTERNALSYM NATIVE_TYPE_MAX_CB}
  COR_ILMETHOD_SECT_SMALL_MAX_DATASIZE= $FF;
  {$EXTERNALSYM COR_ILMETHOD_SECT_SMALL_MAX_DATASIZE}

// #defines for the MIH FLAGS

  IMAGE_COR_MIH_METHODRVA             = $01;
  {$EXTERNALSYM IMAGE_COR_MIH_METHODRVA}
  IMAGE_COR_MIH_EHRVA                 = $02;
  {$EXTERNALSYM IMAGE_COR_MIH_EHRVA}
  IMAGE_COR_MIH_BASICBLOCK            = $08;
  {$EXTERNALSYM IMAGE_COR_MIH_BASICBLOCK}

// V-table constants

  COR_VTABLE_32BIT                    = $01;          // V-table slots are 32-bits in size.
  {$EXTERNALSYM COR_VTABLE_32BIT}
  COR_VTABLE_64BIT                    = $02;          // V-table slots are 64-bits in size.
  {$EXTERNALSYM COR_VTABLE_64BIT}
  COR_VTABLE_FROM_UNMANAGED           = $04;          // If set, transition from unmanaged.
  {$EXTERNALSYM COR_VTABLE_FROM_UNMANAGED}
  COR_VTABLE_CALL_MOST_DERIVED        = $10;          // Call most derived method described by
  {$EXTERNALSYM COR_VTABLE_CALL_MOST_DERIVED}

// EATJ constants

  IMAGE_COR_EATJ_THUNK_SIZE           = 32;            // Size of a jump thunk reserved range.
  {$EXTERNALSYM IMAGE_COR_EATJ_THUNK_SIZE}

// Max name lengths
// Change to unlimited name lengths.

  MAX_CLASS_NAME                      = 1024;
  {$EXTERNALSYM MAX_CLASS_NAME}
  MAX_PACKAGE_NAME                    = 1024;
  {$EXTERNALSYM MAX_PACKAGE_NAME}

// COM+ 2.0 header structure.

type
  IMAGE_COR20_HEADER = record

    // Header versioning

    cb: DWORD;
    MajorRuntimeVersion: WORD;
    MinorRuntimeVersion: WORD;

    // Symbol table and startup information

    MetaData: IMAGE_DATA_DIRECTORY;
    Flags: DWORD;
    EntryPointToken: DWORD;

    // Binding information

    Resources: IMAGE_DATA_DIRECTORY;
    StrongNameSignature: IMAGE_DATA_DIRECTORY;

    // Regular fixup and binding information

    CodeManagerTable: IMAGE_DATA_DIRECTORY;
    VTableFixups: IMAGE_DATA_DIRECTORY;
    ExportAddressTableJumps: IMAGE_DATA_DIRECTORY;

    // Precompiled image info (internal use only - set to zero)

    ManagedNativeHeader: IMAGE_DATA_DIRECTORY;
  end;
  {$EXTERNALSYM IMAGE_COR20_HEADER}
  PIMAGE_COR20_HEADER = ^IMAGE_COR20_HEADER;
  {$EXTERNALSYM PIMAGE_COR20_HEADER}
  TImageCor20Header = IMAGE_COR20_HEADER;
  PImageCor20Header = PIMAGE_COR20_HEADER;

//
// End Image Format
//

implementation

end.
