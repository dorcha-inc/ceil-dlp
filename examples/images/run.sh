#!/bin/bash

# clean up any existing redacted images
rm examples/images/*.redacted.png

# for each image in the images directory, run ceil-dlp test on it and save the redacted image to the same directory
for image in examples/images/*.png; do
    base_name=$(basename "$image" .png)
    uv run ceil-dlp test "$image" --config "examples/images/$base_name.yaml" --output "examples/images/$base_name.redacted.png"
done
