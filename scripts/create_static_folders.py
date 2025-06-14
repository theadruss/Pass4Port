import os

# Define the folders to create
folders = [
    'static/uploads',
    'static/images',
    'static/css',
    'static/js'
]

# Create each folder if it doesn't exist
for folder in folders:
    if not os.path.exists(folder):
        os.makedirs(folder, exist_ok=True)
        print(f"Created folder: {folder}")
    else:
        print(f"Folder already exists: {folder}")

print("All static folders created successfully!")
