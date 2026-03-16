import os
import sys

MAN_DIR = "man"
GREEN = "\033[32m"
BOLD = "\033[1m"
RESET = "\033[0m"

SECTION_HEADER = {
    "NAME",
    "DESCRIPTION",
    "UNDERLYING TOOL",
    "EXECUTION",
    "USAGE",
    "MODULE OPTION",
    "COMMANDS",
    "EXAMPLE",
    "OUTPUT",
    "REQUIREMENTS",
    "AUTHOR",
    "VERSION"
}
def open_manual(module):

    path = os.path.join(MAN_DIR, f"{module}.man")

    if not os.path.exists(path):
        print(f"Manual page not found for '{module}'")
        print("Press Enter to exit..")
        sys.exit(1)

    with open(path, "r") as f:
        lines = f.readlines()
    for line in lines:
        stripped = line.strip()
        if stripped in SECTION_HEADER:
            print(f"{GREEN}{BOLD}{line}{RESET}",end="")
        else:
            print(f"{GREEN}{line}{RESET}",end="")
    print("\nPress ctrl+z and Enter to exit")
    try:
        while True:
            input()
    except EOFError:
        sys.exit(0)


if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage: man_viewer.py <module>")
        sys.exit(1)

    open_manual(sys.argv[1])