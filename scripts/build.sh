#!/bin/bash

echo "Building IdorPlus..."

mkdir -p bin

# Build for multiple platforms
echo "Building for Linux (amd64)..."
GOOS=linux GOARCH=amd64 go build -o bin/idorplus-linux-amd64 ./cmd/idorplus

echo "Building for macOS (amd64)..."
GOOS=darwin GOARCH=amd64 go build -o bin/idorplus-darwin-amd64 ./cmd/idorplus

echo "Building for Windows (amd64)..."
GOOS=windows GOARCH=amd64 go build -o bin/idorplus-windows-amd64.exe ./cmd/idorplus

echo "Build complete! Artifacts in bin/"
