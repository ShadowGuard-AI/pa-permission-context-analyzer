# pa-permission-context-analyzer

Determines the context in which a permission is being used. For example, if a particular file permission is only utilized by a specific script, it reports this context, facilitating better-informed permission tightening. Focused on tools for analyzing and assessing file system permissions.

Context is found with the optional repeatable --search-root argument, which names a script or configuration tree to scan for references to each analyzed path. A reference is a match on the full path or on the file name. The context field reports the referencing files found, or states that no references were found in the named trees, or that no search roots were named.

Each directory, including the root directory and each subdirectory, is reported as its own result row in both recursive and non recursive modes, along with each regular file. A directory with no entries at all is a nothing analyzed run.

When the result list is empty, the empty list is still written to the named output file, and the run exits 1: with a no matching files line when the input held files but the filters matched none, and with a nothing analyzed line when the input held no files. If the output file resolves to the analyzed file, or to a file that was analyzed inside the analyzed tree, the run exits 1 and refuses to overwrite it.

## Install

```
git clone https://github.com/ShadowGuard-AI/pa-permission-context-analyzer.git
cd pa-permission-context-analyzer
pip install -r requirements.txt
```

## Usage

```
python3 main.py PATH [options]
```

## Parameters

- `PATH`: Required positional. The path to analyze permissions for (file or directory).
- `-r, --recursive`: Recursively analyze permissions for all files and subdirectories.
- `-o, --output FILE`: Output the results to a file (JSON format).
- `-l, --log-file FILE`: Specify a log file, default `pa_permission_analyzer.log`.
- `--check-uid`: Check usage by specific UID (integer).
- `--check-gid`: Check usage by specific GID (integer).
- `--search-root DIR`: A script or configuration tree to scan for references to each analyzed path. May be given more than once.

## Verified in this wave

`python3 main.py --help` could not run in this sandbox: it exits 1 at import with `ModuleNotFoundError: No module named 'rich'`, because `rich` is not installed and installs are not made in this wave. Parameters above are taken from the argument parser in `main.py`, and `main.py` passes `py_compile`. No live analysis run is claimed.

## License

See LICENSE.
