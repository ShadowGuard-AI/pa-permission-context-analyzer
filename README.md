# pa-permission-context-analyzer
Determines the context in which a permission is being used. For example, if a particular file permission is only utilized by a specific script, it reports this context, facilitating better-informed permission tightening. - Focused on Tools for analyzing and assessing file system permissions

Context is found with the optional repeatable --search-root argument, which names a script or configuration tree to scan for references to each analyzed path. A reference is a match on the full path or on the file name. The context field reports the referencing files found, or states that no references were found in the named trees, or that no search roots were named.

Each directory, including the root directory and each subdirectory, is reported as its own result row in both recursive and non recursive modes, along with each regular file. A directory with no entries at all is a nothing analyzed run.

When the result list is empty, the empty list is still written to the named output file, and the run exits 1: with a no matching files line when the input held files but the filters matched none, and with a nothing analyzed line when the input held no files. If the output file resolves to the analyzed file, or to a file that was analyzed inside the analyzed tree, the run exits 1 and refuses to overwrite it.

## Install
`git clone https://github.com/ShadowGuardAI/pa-permission-context-analyzer`

## Usage
`./pa-permission-context-analyzer [params]`

## Parameters
- `-h`: Show help message and exit
- `-r`: Recursively analyze permissions for all files and subdirectories.
- `-o`: No description provided
- `-l`: No description provided
- `--check-uid`: Check usage by specific UID.
- `--check-gid`: Check usage by specific GID.
- `--search-root`: A script or configuration tree to scan for references to each analyzed path. May be given more than once.

## License
Copyright (c) ShadowGuardAI
