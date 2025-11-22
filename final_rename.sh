#!/bin/bash
# Final comprehensive rename script

cd /home/tachyon/CobaltGraph

# Find all text files (excluding .git, __pycache__, .db, .log, .pid files)
find . -type f \( -name "*.py" -o -name "*.md" -o -name "*.txt" -o -name "*.sh" -o -name "*.bat" -o -name "*.conf" -o -name "*.html" -o -name "*.js" -o -name "*.css" -o -name "*.json" \) \
  -not -path "*/.git/*" \
  -not -path "*/__pycache__/*" \
  -not -name "rename_project.py" \
  -not -name "rename_project_v2.py" \
  -not -name "final_rename.sh" \
  -not -name "modified_files*.txt" | while read file; do

  # Use sed to replace all variations
  sed -i 's/SUARONOrchestrator/CobaltGraphOrchestrator/g' "$file"
  sed -i 's/SUARONInitializer/CobaltGraphInitializer/g' "$file"
  sed -i 's/initialize_suaron/initialize_cobaltgraph/g' "$file"
  sed -i 's/verify_suaron_modules/verify_cobaltgraph_modules/g' "$file"
  sed -i 's/suaron_/cobaltgraph_/g' "$file"
  sed -i 's/_suaron/_cobaltgraph/g' "$file"

done

echo "Final rename complete!"
