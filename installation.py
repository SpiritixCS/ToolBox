import subprocess
import sys
import os

def install_requirements():
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
    except subprocess.CalledProcessError as e:
        print(f"Failed to install requirements: {e}")
        sys.exit(1)

def install_villain():
    try:
        subprocess.check_call(["sudo", "apt", "install", "villain"])
    except subprocess.CalledProcessError as e:
        print(f"Failed to install villain: {e}")
        sys.exit(1)

def main():
    current_directory = os.getcwd()
    requirements_path = os.path.join(current_directory, "requirements.txt")

    if not os.path.exists(requirements_path):
        print("requirements.txt not found in the current directory.")
        sys.exit(1)

    print("Installing requirements...")
    install_requirements()
    print("Requirements installed successfully.")

    print("Installing villain...")
    install_villain()
    print("villain installed successfully.")

    print("All installations completed successfully! Enjoy using the toolbox")

if __name__ == "__main__":
    main()
