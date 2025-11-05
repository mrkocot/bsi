#!/bin/bash

# Get the directory of the current script
DIR=$(dirname $(readlink -f $0))

# Define an array of folder names
declare -a arr=("3des" "aes" "elgamal" "rsa")

# Loop through the array
for i in "${arr[@]}"
do
   # Combine the directory of the script with the current folder name
   CURRENT_DIR="$DIR/$i"

   # Check if directory exists
   if [ -d "$CURRENT_DIR" ]; then
      echo "Directory $CURRENT_DIR exists."
      # Clear the directory by removing and creating it again
      rm -rd "$CURRENT_DIR"
      mkdir "$CURRENT_DIR"
      echo "$CURRENT_DIR is cleared."
   else
      # Create the directory
      mkdir "$CURRENT_DIR"
      echo "Directory $CURRENT_DIR is created."
   fi
done
