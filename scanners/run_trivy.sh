#!/bin/bash

TARGET_IMAGE="$1"
echo "Running trivy scan on vulnerable application"
mkdir -p scanners/sample_output
trivy image -f json -o scanners/sample_output/trivy_output.json "$TARGET_IMAGE"
