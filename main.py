import argparse
import os
import logging
import stat
import sys
from typing import List, Dict, Any
from rich.console import Console
from rich.table import Column, Table

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
DEFAULT_LOG_FILE = "pa_permission_analyzer.log"
MAX_PATH_LENGTH = 4096  # Maximum path length to prevent buffer overflows.


def setup_argparse() -> argparse.ArgumentParser:
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(
        description="Determines the context in which a permission is being used."
    )
    parser.add_argument(
        "path",
        help="The path to analyze permissions for (file or directory)."
    )
    parser.add_argument(
        "-r",
        "--recursive",
        action="store_true",
        help="Recursively analyze permissions for all files and subdirectories."
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Output the results to a file (JSON format).",
        metavar="FILE"
    )
    parser.add_argument(
        "-l",
        "--log-file",
        help=f"Specify a log file (default: {DEFAULT_LOG_FILE}).",
        default=DEFAULT_LOG_FILE,
        metavar="FILE"
    )
    parser.add_argument(
        "--check-uid",
        type=int,
        help="Check usage by specific UID."
    )
    parser.add_argument(
        "--check-gid",
        type=int,
        help="Check usage by specific GID."
    )
    parser.add_argument(
        "--search-root",
        action="append",
        default=[],
        metavar="DIR",
        help="A script or configuration tree to scan for references to each analyzed path. May be given more than once."
    )
    return parser


def find_reference_context(file_path: str, search_roots=None) -> str:
    """Scan named search roots for references to a path."""
    if not search_roots:
        return "No search roots were named, so no references were searched for."
    full_path = os.path.abspath(file_path)
    base_name = os.path.basename(file_path)
    found = []
    for root in search_roots:
        if os.path.isfile(root):
            candidates = [root]
        elif os.path.isdir(root):
            candidates = []
            for dir_path, _dir_names, file_names in os.walk(root):
                for name in file_names:
                    candidates.append(os.path.join(dir_path, name))
        else:
            continue
        for candidate in candidates:
            try:
                # Files over a megabyte are skipped with no note in the result. A reference living
                # in one large file reads exactly like no references found.
                if os.path.getsize(candidate) > 1048576:
                    continue
                with open(candidate, "r", errors="ignore") as handle:
                    text = handle.read()
            except OSError:
                continue
            # The basename fallback is the noisy half of this search. A file named config or app
            # matches any passing mention of that word, so a Referenced by line can mean only
            # that the name is a common one.
            if full_path in text or (base_name and base_name in text):
                found.append(candidate)
    if found:
        return "Referenced by: " + ", ".join(sorted(set(found)))
    return "No references found in the named search roots."


def analyze_file_permissions(file_path: str, check_uid: int = None, check_gid: int = None, search_roots=None) -> Dict[str, Any]:
    """
    Analyzes the permissions of a single file.

    Args:
        file_path (str): The path to the file.
        check_uid (int, optional): Analyze only if owned by this UID. Defaults to None.
        check_gid (int, optional): Analyze only if owned by this GID. Defaults to None.

    Returns:
        Dict[str, Any]: A dictionary containing the file path and its permissions context.
                           Returns None if an error occurs or file doesn't match uid/gid filter.
    """

    if not os.path.exists(file_path):
        logging.error(f"File not found: {file_path}")
        return None

    if len(file_path) > MAX_PATH_LENGTH:
        logging.error(f"Path too long: {file_path}")
        return None
    
    try:
        # os.stat follows symlinks, so for a link I report the target's owner and mode, never the
        # link's own. A tree full of links reads as a report about its targets.
        stat_info = os.stat(file_path)
        uid = stat_info.st_uid
        gid = stat_info.st_gid

        if check_uid is not None and uid != check_uid:
            return None  # Skip if UID doesn't match
        if check_gid is not None and gid != check_gid:
            return None  # Skip if GID doesn't match

        permissions = stat.filemode(stat_info.st_mode)
        file_type = "File" if stat.S_ISREG(stat_info.st_mode) else "Directory" if stat.S_ISDIR(stat_info.st_mode) else "Other"

        context = {
            "file_path": file_path,
            "file_type": file_type,
            "permissions": permissions,
            "owner_uid": uid,
            "owner_gid": gid,
            # Context here means text references only. I rescan the search roots from scratch for
            # every file, and ACLs or extended attributes on the file never enter the picture.
            "context": find_reference_context(file_path, search_roots)
        }

        return context

    except OSError as e:
        logging.error(f"Error analyzing file {file_path}: {e}")
        return None
    except Exception as e:
         logging.exception(f"Unexpected error analyzing {file_path}")
         return None


def analyze_directory_permissions(dir_path: str, recursive: bool = False, check_uid: int = None, check_gid: int = None, search_roots=None) -> List[Dict[str, Any]]:
    """
    Analyzes the permissions of files and subdirectories within a directory.

    Args:
        dir_path (str): The path to the directory.
        recursive (bool, optional): Whether to recursively analyze subdirectories. Defaults to False.
        check_uid (int, optional): Analyze only if owned by this UID. Defaults to None.
        check_gid (int, optional): Analyze only if owned by this GID. Defaults to None.

    Returns:
        List[Dict[str, Any]]: A list of dictionaries, each containing the permissions context for a file.
    """
    if not os.path.isdir(dir_path):
        logging.error(f"Not a directory: {dir_path}")
        return []

    results = []
    try:
        own_context = analyze_file_permissions(dir_path, check_uid, check_gid, search_roots)
        if own_context:
            results.append(own_context)
        for item in os.listdir(dir_path):
            item_path = os.path.join(dir_path, item)

            if os.path.isfile(item_path):
                file_context = analyze_file_permissions(item_path, check_uid, check_gid, search_roots)
                if file_context:  # Only add if not None
                    results.append(file_context)
            elif os.path.isdir(item_path):
                if recursive:
                    # This recursion follows symlinked directories with no visited set. A link pointing
                    # back into its own tree sends me around until something gives up.
                    results.extend(analyze_directory_permissions(item_path, recursive, check_uid, check_gid, search_roots))
                else:
                    dir_context = analyze_file_permissions(item_path, check_uid, check_gid, search_roots)
                    if dir_context:
                        results.append(dir_context)
    except OSError as e:
        logging.error(f"Error reading directory {dir_path}: {e}")
    except Exception as e:
        logging.exception(f"Unexpected error analyzing directory {dir_path}")

    return results


def print_results(results: List[Dict[str, Any]]):
    """
    Prints the analysis results in a formatted table using the rich library.

    Args:
        results (List[Dict[str, Any]]): A list of dictionaries containing the analysis results.
    """
    console = Console()

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("File Path", style="dim", width=40)
    table.add_column("File Type")
    table.add_column("Permissions")
    table.add_column("Owner UID", justify="right")
    table.add_column("Owner GID", justify="right")
    table.add_column("Context", width=40)

    for result in results:
        table.add_row(
            result["file_path"],
            result["file_type"],
            result["permissions"],
            str(result["owner_uid"]),
            str(result["owner_gid"]),
            result["context"]
        )

    console.print(table)


def write_results_to_file(results: List[Dict[str, Any]], output_file: str):
    """
    Writes the analysis results to a JSON file.

    Args:
        results (List[Dict[str, Any]]): A list of dictionaries containing the analysis results.
        output_file (str): The path to the output file.
    """
    import json

    try:
        with open(output_file, "w") as f:
            json.dump(results, f, indent=4)
        logging.info(f"Results written to {output_file}")
    except OSError as e:
        logging.error(f"Error writing to file {output_file}: {e}")
    except Exception as e:
        logging.exception(f"Unexpected error writing to file {output_file}")


def main():
    """
    Main function to parse arguments, analyze permissions, and display results.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Configure logging to file
    file_handler = logging.FileHandler(args.log_file)
    file_handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    logging.getLogger().addHandler(file_handler)

    path_to_analyze = args.path

    # Validate input path
    if not os.path.exists(path_to_analyze):
        print(f"Error: Path '{path_to_analyze}' does not exist.")
        sys.exit(1)

    # In place check: the output file must not be the analyzed file or
    # a file that will be analyzed inside the analyzed tree.
    if args.output:
        output_resolved = os.path.realpath(args.output)
        analyzed_paths = set()
        if os.path.isfile(path_to_analyze):
            analyzed_paths.add(os.path.realpath(path_to_analyze))
        elif os.path.isdir(path_to_analyze):
            analyzed_paths.add(os.path.realpath(path_to_analyze))
            if args.recursive:
                for dir_path, dir_names, file_names in os.walk(path_to_analyze):
                    analyzed_paths.add(os.path.realpath(dir_path))
                    for name in file_names + dir_names:
                        analyzed_paths.add(os.path.realpath(os.path.join(dir_path, name)))
            else:
                for name in os.listdir(path_to_analyze):
                    analyzed_paths.add(os.path.realpath(os.path.join(path_to_analyze, name)))
        if output_resolved in analyzed_paths:
            print("Error: Output file must not be the same as a file being analyzed.")
            sys.exit(1)

    input_held_files = False
    if os.path.isfile(path_to_analyze):
        input_held_files = True
        result = analyze_file_permissions(path_to_analyze, args.check_uid, args.check_gid, args.search_root)
        results = [result] if result else []
    elif os.path.isdir(path_to_analyze):
        # Determine whether the input held any entries at all.
        def _count_entries(base):
            count = 0
            for dir_path, dir_names, file_names in os.walk(base):
                count += len(dir_names) + len(file_names)
            return count
        input_held_files = _count_entries(path_to_analyze) > 0
        if input_held_files:
            results = analyze_directory_permissions(path_to_analyze, args.recursive, args.check_uid, args.check_gid, args.search_root)
        else:
            # A directory with no entries at all is a nothing analyzed run.
            results = []
    else:
        print(f"Error: '{path_to_analyze}' is neither a file nor a directory.")
        sys.exit(1)

    if results:
        print_results(results)
        if args.output:
            write_results_to_file(results, args.output)
        logging.info("Analysis completed.")
        return

    # Empty result list: still write the named output file, then exit 1
    # with a distinct line.
    if args.output:
        write_results_to_file([], args.output)
    if input_held_files:
        print("No matching files: the filters matched none of the input files.")
        logging.warning("No matching files.")
    else:
        print("Nothing analyzed: the input held no files.")
        logging.warning("Nothing analyzed.")
    sys.exit(1)

# Example Usage
if __name__ == "__main__":
    main()