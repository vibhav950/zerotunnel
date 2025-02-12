#!/bin/zsh

total_tests=0
successful_tests=0

for makefile in Makefile_*.txt; do
    exec_name=$(echo "$makefile" | sed 's/Makefile_//; s/\.txt//')
    exec_path="./bin/${exec_name}"
    
    echo "Building: $exec_name"
    
    make -f "$makefile"
    
    ((total_tests++))
    
    if [ -x "$exec_path" ]; then
        echo "Running: $exec_path"
        "$exec_path"
        
        if [ $? -eq 0 ]; then
            echo -e "\e[32mPASS: $exec_name\e[0m"
            ((successful_tests++))
        else
            echo -e "\e[31mFAIL: $exec_name\e[0m"
        fi
    else
        echo -e "\e[31mFAIL: $exec_name (Executable not found)\e[0m"
    fi
    
    make -f "$makefile" clean
    echo
done

echo -e "Total Tests: $total_tests, Successful Tests: $successful_tests"
