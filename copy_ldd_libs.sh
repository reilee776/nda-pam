#!/bin/bash

# Target directory to copy libraries
TARGET_DIR="/hiagt/lib/nda-pam/"

# Ensure the target directory exists
mkdir -p "$TARGET_DIR"

# Get the list of required libraries from ldd
LDD_OUTPUT=$(ldd nda-pam.so)

# Loop through each line in the ldd output
while read -r line; do
    # Extract the library path (second field after "=>")
    LIB_PATH=$(echo "$line" | awk -F"=>" '{if (NF > 1) print $2}' | awk '{print $1}')

    # If a library path is found and it exists
    if [ -n "$LIB_PATH" ] && [ -f "$LIB_PATH" ]; then
        echo "Copying $LIB_PATH to $TARGET_DIR"
        cp -u "$LIB_PATH" "$TARGET_DIR"
    fi

    # Handle vdso (special case)
    if [[ "$line" == *"linux-vdso.so.1"* ]]; then
        echo "Skipping linux-vdso.so.1 (not a physical library)"
    fi

done <<< "$LDD_OUTPUT"

# Verify copied files
echo "Libraries copied to $TARGET_DIR:"
ls -l "$TARGET_DIR"

