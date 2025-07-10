import os

# Files to keep
KEEP_FILES = {'config.conf'}
# File extensions to delete
DELETE_EXTENSIONS = {'.json', '.txt', '.enc', '.bin', '.pem'}
# Specific files to delete
DELETE_FILES = {'server.crt', 'server.key'}

for filename in os.listdir('.'):
    if filename in KEEP_FILES:
        continue
    if filename.endswith('.py'):
        continue
    if filename in DELETE_FILES or any(filename.endswith(ext) for ext in DELETE_EXTENSIONS):
        try:
            os.remove(filename)
            print(f"Deleted: {filename}")
        except Exception as e:
            print(f"Failed to delete {filename}: {e}") 