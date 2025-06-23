# pa-permission-context-analyzer
Determines the context in which a permission is being used. For example, if a particular file permission is only utilized by a specific script, it reports this context, facilitating better-informed permission tightening. - Focused on Tools for analyzing and assessing file system permissions

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

## License
Copyright (c) ShadowGuardAI
