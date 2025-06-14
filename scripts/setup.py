import subprocess
import sys
import os

def install_dependencies():
    """Install required dependencies for the visitor management system"""
    print("Installing dependencies for the visitor management system...")
    
    # Check if pip is available
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "--version"])
    except subprocess.CalledProcessError:
        print("Error: pip is not installed or not working properly.")
        sys.exit(1)
    
    # Install dependencies from requirements.txt
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("Successfully installed dependencies!")
    except subprocess.CalledProcessError:
        print("Error: Failed to install dependencies.")
        sys.exit(1)
    
    # Create necessary directories
    os.makedirs("static/uploads", exist_ok=True)
    os.makedirs("static/images", exist_ok=True)
    print("Created necessary directories.")
    
    print("\nSetup complete! You can now run the application with:")
    print("python app.py")

if __name__ == "__main__":
    install_dependencies()
