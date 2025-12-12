#!/usr/bin/env python3
"""
Cleanup script for Obsidian Sovereign
Removes runtime artifacts, temporary files, and duplicates.
"""
import os
import shutil
import glob
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

def remove_file(path):
    try:
        if os.path.exists(path):
            os.remove(path)
            logger.info(f"✅ Removed file: {path}")
        else:
            logger.debug(f"Skipped (not found): {path}")
    except Exception as e:
        logger.error(f"❌ Failed to remove {path}: {e}")

def remove_dir(path):
    try:
        if os.path.exists(path):
            shutil.rmtree(path)
            logger.info(f"✅ Removed directory: {path}")
        else:
            logger.debug(f"Skipped (not found): {path}")
    except Exception as e:
        logger.error(f"❌ Failed to remove {path}: {e}")

def cleanup():
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    logger.info(f"🧹 Starting cleanup in {root_dir}...")

    # Files to remove
    files_to_remove = [
        "obsidian_keys.json",
        "obsidian_keys.json.tmp",
        "obsidian_audit.log",
        "test_audit.log",
        "BENCHMARK_REPORT.md",
        "Obsidian_Sovereign_Whitepaper.pdf",
        "status.html", # Root status.html (duplicate of web/status.html or unused)
        "fix_server.py",
        "verify_fixes.py",
        "obsidian/server.py.backup",
        "obsidian/obsidian_engine.dll", # Rebuild this
        "obsidian/obsidian_engine.so",
    ]

    # Directories to remove
    dirs_to_remove = [
        "certs",
        "obsidian_sovereign.egg-info",
        ".pytest_cache",
        "build",
        "dist",
    ]

    # Remove specific files
    for file in files_to_remove:
        remove_file(os.path.join(root_dir, file))

    # Remove directories
    for directory in dirs_to_remove:
        remove_dir(os.path.join(root_dir, directory))

    # Recursive cleanup
    for root, dirs, files in os.walk(root_dir):
        # Remove __pycache__
        if "__pycache__" in dirs:
            remove_dir(os.path.join(root, "__pycache__"))
        
        # Remove .pyc files
        for file in files:
            if file.endswith(".pyc"):
                remove_file(os.path.join(root, file))

    logger.info("✨ Cleanup complete!")

if __name__ == "__main__":
    cleanup()
