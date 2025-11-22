#!/usr/bin/env python3
"""
Enhanced script to rename SUARON to CobaltGraph throughout the codebase
Handles function names, class names, and other identifiers
"""
import os
import re
from pathlib import Path

# Define replacement patterns - order matters!
REPLACEMENTS = [
    # Class/Function names with SUARON prefix
    (r'SUARONOrchestrator', 'CobaltGraphOrchestrator'),
    (r'initialize_suaron', 'initialize_cobaltgraph'),
    (r'suaron_', 'cobaltgraph_'),
    (r'_suaron', '_cobaltgraph'),

    # All caps SUARON
    (r'SUARON', 'CobaltGraph'),

    # Title case Suaron
    (r'Suaron', 'CobaltGraph'),

    # All lowercase suaron (but not already part of cobaltgraph)
    (r'(?<!cobalt)suaron(?!graph)', 'cobaltgraph'),
]

# Files to skip
SKIP_PATTERNS = [
    '.git',
    '__pycache__',
    '.pyc',
    'rename_project.py',
    'rename_project_v2.py',
    'modified_files.txt',
    'modified_files_v2.txt',
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
    root_dir = Path('/home/tachyon/CobaltGraph')
    modified_files = []

    # Walk through all files
    for filepath in root_dir.rglob('*'):
        if filepath.is_file() and not should_skip(filepath):
            if replace_in_file(filepath):
                modified_files.append(str(filepath))
                print(f"Modified: {filepath}")

    print(f"\nTotal files modified: {len(modified_files)}")

    # Save list of modified files
    with open('/home/tachyon/CobaltGraph/modified_files_v2.txt', 'w') as f:
        for filepath in modified_files:
            f.write(filepath + '\n')

if __name__ == '__main__':
    main()
