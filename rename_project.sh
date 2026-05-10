#!/bin/bash
set -e

echo "Renaming pipelock-* crates to agent-*..."

cd agent-isolate/crates

# Rename all directories
for dir in pipelock*; do
    if [ -d "$dir" ]; then
        new_name=$(echo "$dir" | sed 's/pipelock/agent/')
        echo "Renaming $dir -> $new_name"
        mv "$dir" "$new_name"
    fi
done

cd ../..

echo "Updating Cargo.toml references..."

# Update workspace Cargo.toml
sed -i 's/pipelock/agent/g' agent-isolate/Cargo.toml
sed -i 's|github.com/dgithinjibit/pipelock|github.com/dgithinjibit/agent-isolate|g' agent-isolate/Cargo.toml
sed -i 's/pipelock-rs contributors/agent-isolate contributors/g' agent-isolate/Cargo.toml

echo "Updating all crate Cargo.toml files..."

# Update all crate Cargo.toml files
find agent-isolate/crates -name "Cargo.toml" -type f -exec sed -i 's/pipelock/agent/g' {} \;

echo "Updating Rust source files..."

# Update all Rust source files
find agent-isolate -name "*.rs" -type f -exec sed -i 's/pipelock/agent/g' {} \;

echo "Updating documentation files..."

# Update markdown files
find agent-isolate -name "*.md" -type f -exec sed -i 's/pipelock-/agent-/g' {} \;

echo "Done! All references updated."
