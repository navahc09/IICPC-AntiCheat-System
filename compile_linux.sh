#!/bin/bash
mkdir -p bin/linux
echo "Compiling for Linux..."
g++ -o bin/linux/main src/common/*.cpp src/linux/*.cpp -I include -pthread
if [ $? -eq 0 ]; then
    echo "Compilation Successful! Output: bin/linux/main"
else
    echo "Compilation Failed!"
    exit 1
fi
