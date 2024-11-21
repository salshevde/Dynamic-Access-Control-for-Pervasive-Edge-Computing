#!/bin/bash

# File name for the generated text file
output_file="data.txt"

# Size in bytes (1MB = 1024 * 1024 bytes)
size=1048576
# Generate the file with random content
head -c $size /dev/urandom | tr -dc 'a-zA-Z0-9' > $output_file

echo "Generated a 1MB text file: $output_file"
