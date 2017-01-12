Simple DLL dependency scanner.

Point to a set of directories (usually Windows\System32) and scan to construct a list of EXE and DLL files with imports and exports. You can then see which libraries use any given one.

Results are saved in a database and can be loaded without rescan.

Note that static import is not the only way in which a library can be used by others.

1. A library can be loaded dynamically (with LoadLibrary). This tool does not detect such use.

2. A library can register COM objects and then be loaded automatically when those objects are requested. This tool cannot track this use, and there's little that can even be done in principle to statically analyze it.

Requires sqlite3 and pascal sqlite imports.

The code may lack some utility routines from support files. At the moment I'm just writing this for myself, so I'm not going to bother including or specifying every single dependency. Download binary version if its available, or if you're trying to compile this and some function is missing, just write it or google it or whatever.
