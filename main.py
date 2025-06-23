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
    return parser


def analyze_file_permissions(file_path: str, check_uid: int = None, check_gid: int = None) -> Dict[str, Any]:
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
        stat_info = os.stat(file_path)
        uid = stat_info.st_uid
        gid = stat_info.st_gid

        if check_uid is not None and uid != check_uid:
            return None  # Skip if UID doesn't match
        if check_gid is not None and gid != check_gid:
            return None  # Skip if GID doesn't match

        permissions = stat.filemode(stat_info.st_mode)
        file_type = "File" if stat.S_ISREG(stat_info.st_mode) else "Directory" if stat.S_ISDIR(stat_info.st_mode) else "Other"

        # Basic context (expand later to analyze which scripts use the file, etc.)
        context = {
            "file_path": file_path,
            "file_type": file_type,
            "permissions": permissions,
            "owner_uid": uid,
            "owner_gid": gid,
            "context": "No specific context identified (basic analysis)."  # Placeholder, improve later
        }

        return context

    except OSError as e:
        logging.error(f"Error analyzing file {file_path}: {e}")
        return None
    except Exception as e:
         logging.exception(f"Unexpected error analyzing {file_path}")
         return None


def analyze_directory_permissions(dir_path: str, recursive: bool = False, check_uid: int = None, check_gid: int = None) -> List[Dict[str, Any]]:
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
        for item in os.listdir(dir_path):
            item_path = os.path.join(dir_path, item)

            if os.path.isfile(item_path):
                file_context = analyze_file_permissions(item_path, check_uid, check_gid)
                if file_context:  # Only add if not None
                    results.append(file_context)
            elif os.path.isdir(item_path) and recursive:
                results.extend(analyze_directory_permissions(item_path, recursive, check_uid, check_gid))
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

    if os.path.isfile(path_to_analyze):
        result = analyze_file_permissions(path_to_analyze, args.check_uid, args.check_gid)
        if result:
            print_results([result])
            if args.output:
                write_results_to_file([result], args.output)

    elif os.path.isdir(path_to_analyze):
        results = analyze_directory_permissions(path_to_analyze, args.recursive, args.check_uid, args.check_gid)
        if results:  #check if results is not empty before printing
            print_results(results)
            if args.output:
                write_results_to_file(results, args.output)
    else:
        print(f"Error: '{path_to_analyze}' is neither a file nor a directory.")
        sys.exit(1)

    logging.info("Analysis completed.")

# Example Usage
if __name__ == "__main__":
    # Create a dummy file for demonstration
    if not os.path.exists("dummy_file.txt"):
        try:
           with open("dummy_file.txt", "w") as f:
               f.write("This is a dummy file for testing.")
           os.chmod("dummy_file.txt", 0o644)  # Set some basic permissions

        except OSError as e:
            print(f"Error creating dummy file: {e}")
            sys.exit(1)

    main()