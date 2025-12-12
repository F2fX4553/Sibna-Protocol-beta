# tools/check_environment.py
import platform
import subprocess
import sys
import os

def check_environment():
    """أداة للتحقق من بيئة التطوير"""
    
    print("🔍 Checking Obsidian SDK Environment...")
    
    # التحقق من Python
    print(f"✅ Python {sys.version}")
    
    # التحقق من المترجم
    try:
        if platform.system() == "Windows":
            result = subprocess.run(["g++", "--version"], capture_output=True, text=True)
        else:
            result = subprocess.run(["g++", "--version"], capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ C++ compiler (g++) is available")
        else:
            print("❌ C++ compiler not found")
    except:
        print("❌ C++ compiler not found")
    
    # التحقق من المكتبات
    try:
        import cryptography
        print(f"✅ cryptography {cryptography.__version__}")
    except ImportError:
        print("❌ cryptography not installed")
    
    # التحقق من المكتبة المترجمة
    lib_path = os.path.join(os.path.dirname(__file__), "..", "obsidian", "obsidian_engine.dll" 
                           if platform.system() == "Windows" else "obsidian_engine.so")
    
    if os.path.exists(lib_path):
        print("✅ Native crypto engine found")
    else:
        print("⚠️ Native crypto engine not found (will use fallback)")
    
    print("\n🎯 Status: Ready for development!")

if __name__ == "__main__":
    check_environment()