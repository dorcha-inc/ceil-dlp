#!/bin/bash

# clean up any existing redacted pdfs
rm examples/pdf/*.redacted.pdf

# for each pdf in the pdf directory, run ceil-dlp test on it and save the redacted pdf to the same directory
for pdf in examples/pdf/*.pdf; do
    base_name=$(basename "$pdf" .pdf)
    uv run ceil-dlp test "$pdf" --config "examples/pdf/$base_name.yaml" --output "examples/pdf/$base_name.redacted.pdf"
done
