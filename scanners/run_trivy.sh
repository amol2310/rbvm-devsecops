TARGET_IMAGE=$1
echo "Running trivy scan on vulnerable application"
trivy image -f json -o scanners/sample_output/trivy_output.json $TARGET_IMAGE
