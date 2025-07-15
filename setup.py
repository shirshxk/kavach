#!/usr/bin/env python3

import os
import stat
import subprocess
import sys
from pathlib import Path

def check_system_dependencies():
    print("🔍 Checking for system-level dependencies...")
    result = subprocess.run(['dpkg', '-s', 'libnetfilter-queue-dev'], stdout=subprocess.DEVNULL)
    if result.returncode != 0:
        print("\n❗ 'libnetfilter-queue-dev' is not installed.")
        print("👉 Please install it manually using:")
        print("   sudo apt update && sudo apt install libnetfilter-queue-dev -y\n")
        sys.exit("⛔ Cannot proceed until system dependency is resolved.")

def make_executable(filepath):
    """Make a Python file executable."""
    if not os.path.exists(filepath):
        print(f"❌ File not found: {filepath}")
        return
    st = os.stat(filepath)
    os.chmod(filepath, st.st_mode | stat.S_IEXEC)
    print(f"✅ Made executable: {filepath}")

def install_requirements():
    req_path = os.path.join(os.getcwd(), "requirements.txt")
    if os.path.exists(req_path):
        print("📦 Installing Python dependencies from requirements.txt...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", req_path, "--break-system-packages"])
            print("✅ Dependencies installed successfully.")
        except subprocess.CalledProcessError:
            print("❌ Failed to install dependencies.")
    else:
        print("⚠️ No requirements.txt found. Skipping dependency installation.")

def append_aliases():
    home = str(Path.home())
    shell = os.environ.get("SHELL", "")
    shell_rc = os.path.join(home, ".zshrc") if shell.endswith("zsh") else os.path.join(home, ".bashrc")

    kavach_path = os.path.abspath("main.py")
    gui_path = os.path.abspath("gui/gui_app.py")

    alias_block = f"""
alias kavach='sudo {kavach_path}'
alias kavachgui='sudo {gui_path}'
"""

    with open(shell_rc, "a") as f:
        f.write(alias_block)

    print(f"✅ Aliases added to {shell_rc}")
    print(f"💡 Run `source {shell_rc}` to activate them in your terminal.")

def main():
    cwd = os.getcwd()
    cli_path = os.path.join(cwd, "main.py")
    gui_path = os.path.join(cwd, "gui", "gui_app.py")

    if not os.path.exists(cli_path) or not os.path.exists(gui_path):
        print("❌ Please run this script from the root of your firewall project directory.")
        sys.exit(1)

    print("⚙️ Setting up Kavach Firewall...\n")
    check_system_dependencies()
    make_executable(cli_path)
    make_executable(gui_path)
    install_requirements()
    append_aliases()

    print("\n🎉 Setup complete.")
    print("➡️ Use `kavach` for CLI or `kavachgui` for GUI (after restarting your shell).")
    print("🛡️ Enjoy using Kavach Firewall securely!")

if __name__ == "__main__":
    main()
