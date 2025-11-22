#!/usr/bin/env python3
"""
Script to rename SUARON to CobaltGraph throughout the codebase
"""
import os
import re
from pathlib import Path

# Define replacement patterns
REPLACEMENTS = [
    # Exact case replacements
    (r'\bSUARON\b', 'CobaltGraph'),  # All caps -> CamelCase title
    (r'\bsuaron\b', 'cobaltgraph'),  # All lowercase
    (r'\bSuaron\b', 'CobaltGraph'),  # Title case
]

# Files to skip
SKIP_PATTERNS = [
    '.git',
    '__pycache__',
    '.pyc',
    'rename_project.py',  # Skip this script itself
    '.db',
    '.log',
    '.pid',
]

def should_skip(filepath):
    """Check if file should be skipped"""
    path_str = str(filepath)
    for pattern in SKIP_PATTERNS:
        if pattern in path_str:
            return True
    return False

def replace_in_file(filepath):
    """Replace SUARON with CobaltGraph in a file"""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        original_content = content

        # Apply all replacements
        for pattern, replacement in REPLACEMENTS:
            content = re.sub(pattern, replacement, content)

        # Only write if content changed
        if content != original_content:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        return False
    except Exception as e:
        print(f"Error processing {filepath}: {e}")
        return False

def main():
    """Main function"""
    root_dir = Path('/home/tachyon/SUARON')
    modified_files = []

    # Walk through all files
    for filepath in root_dir.rglob('*'):
        if filepath.is_file() and not should_skip(filepath):
            if replace_in_file(filepath):
                modified_files.append(str(filepath))
                print(f"Modified: {filepath}")

    print(f"\nTotal files modified: {len(modified_files)}")

    # Save list of modified files
    with open('/home/tachyon/SUARON/modified_files.txt', 'w') as f:
        for filepath in modified_files:
            f.write(filepath + '\n')

if __name__ == '__main__':
    main()
