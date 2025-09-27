#!/usr/bin/env python3
"""
Build script for creating source-protected distribution of Alqudimi Encryption System.
This script compiles Python files to bytecode and creates a distribution without source code.
"""

import os
import sys
import shutil
import py_compile
import tempfile
from pathlib import Path
import subprocess

def compile_python_files(source_dir, target_dir):
    """Compile all Python files to bytecode and copy to target directory"""
    source_path = Path(source_dir)
    target_path = Path(target_dir)
    
    # Create target directory structure
    target_path.mkdir(parents=True, exist_ok=True)
    
    compiled_files = []
    
    for py_file in source_path.rglob("*.py"):
        # Skip test files and __pycache__
        if "__pycache__" in str(py_file) or "test_" in py_file.name:
            continue
            
        # Calculate relative path and target path
        rel_path = py_file.relative_to(source_path)
        target_file = target_path / rel_path
        
        # Create target directory if needed
        target_file.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            # For __init__.py files, keep as source but minimal
            if py_file.name == "__init__.py":
                # Copy minimal __init__.py files
                shutil.copy2(py_file, target_file)
                print(f"Copied: {rel_path}")
            else:
                # Compile to bytecode
                compiled_path = target_file.with_suffix(".pyc")
                py_compile.compile(py_file, compiled_path, doraise=True)
                compiled_files.append(compiled_path)
                print(f"Compiled: {rel_path} -> {compiled_path.name}")
        except Exception as e:
            print(f"Warning: Could not compile {py_file}: {e}")
            # Fall back to copying source file
            shutil.copy2(py_file, target_file)
            
    return compiled_files

def create_protected_package():
    """Create the protected package distribution"""
    
    # Setup directories
    base_dir = Path(__file__).parent
    source_dir = base_dir / "encryption_system" / "src"
    build_dir = base_dir / "build" / "protected"
    dist_dir = base_dir / "dist" / "protected"
    
    # Clean previous builds
    if build_dir.exists():
        shutil.rmtree(build_dir)
    if dist_dir.exists():
        shutil.rmtree(dist_dir)
        
    build_dir.mkdir(parents=True, exist_ok=True)
    dist_dir.mkdir(parents=True, exist_ok=True)
    
    print("=== Building Protected Alqudimi Encryption System ===")
    print(f"Source: {source_dir}")
    print(f"Build: {build_dir}")
    print(f"Dist: {dist_dir}")
    
    # Copy package structure
    package_build_dir = build_dir / "alqudimi_encryption_system" / "encryption_system" / "src"
    
    # Compile Python files to bytecode
    print("\n1. Compiling Python files to bytecode...")
    compiled_files = compile_python_files(source_dir, package_build_dir)
    
    # Copy other necessary files
    print("\n2. Copying additional files...")
    
    # Copy requirements.txt
    req_file = base_dir / "encryption_system" / "requirements.txt"
    if req_file.exists():
        shutil.copy2(req_file, build_dir / "alqudimi_encryption_system" / "encryption_system" / "requirements.txt")
    
    # Copy docs (optional)
    docs_dir = base_dir / "encryption_system" / "docs"
    if docs_dir.exists():
        shutil.copytree(docs_dir, build_dir / "alqudimi_encryption_system" / "encryption_system" / "docs")
    
    # Create main package __init__.py files
    package_init_files = [
        build_dir / "alqudimi_encryption_system" / "__init__.py",
        build_dir / "alqudimi_encryption_system" / "encryption_system" / "__init__.py",
    ]
    
    for init_file in package_init_files:
        init_file.parent.mkdir(parents=True, exist_ok=True)
        with open(init_file, 'w') as f:
            f.write(f'# Alqudimi Encryption System - Protected Distribution\n__version__ = "2.0.0"\n')
    
    # Create setup.py for the protected package
    print("\n3. Creating setup.py for protected package...")
    create_protected_setup_py(build_dir)
    
    # Create wheel package
    print("\n4. Building wheel package...")
    os.chdir(build_dir)
    
    try:
        result = subprocess.run([sys.executable, "setup.py", "bdist_wheel"], 
                              capture_output=True, text=True, check=True)
        print("Wheel build successful!")
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Wheel build failed: {e}")
        print(f"stdout: {e.stdout}")
        print(f"stderr: {e.stderr}")
        return False
    
    # Copy wheel to dist directory
    wheel_dir = build_dir / "dist"
    if wheel_dir.exists():
        for wheel_file in wheel_dir.glob("*.whl"):
            shutil.copy2(wheel_file, dist_dir)
            print(f"Created wheel: {dist_dir / wheel_file.name}")
    
    print(f"\n=== Protected package created in: {dist_dir} ===")
    print("Files in distribution:")
    for file in dist_dir.iterdir():
        print(f"  - {file.name}")
    
    return True

def create_protected_setup_py(build_dir):
    """Create a simple setup.py for the protected package"""
    setup_content = '''#!/usr/bin/env python3
from setuptools import setup, find_packages

setup(
    name="alqudimi_encryption_system",
    version="2.0.0",
    description="Enterprise-grade cryptographic library (Protected Distribution)",
    long_description="Advanced cryptographic library providing enterprise-grade encryption services with post-quantum cryptography, key management, and advanced security features. This is a protected distribution with compiled bytecode.",
    long_description_content_type="text/plain",
    author="Alqudimi Systems",
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    python_requires='>=3.11',
    install_requires=[
        "argon2-cffi>=25.1.0",
        "boto3>=1.40.39", 
        "cryptography>=46.0.1",
        "liboqs-python>=0.14.1",
        "pillow>=11.3.0",
        "pqcrypto>=0.3.4",
        "pynacl>=1.6.0",
        "quantcrypt>=1.0.1",
        "requests>=2.32.5",
    ],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Topic :: Security :: Cryptography',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'License :: Other/Proprietary License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Operating System :: OS Independent',
    ],
    keywords=['cryptography', 'encryption', 'security', 'post-quantum', 'enterprise'],
)
'''
    
    with open(build_dir / "setup.py", 'w') as f:
        f.write(setup_content)

if __name__ == "__main__":
    success = create_protected_package()
    if success:
        print("\n✅ Protected package build completed successfully!")
        sys.exit(0)
    else:
        print("\n❌ Protected package build failed!")
        sys.exit(1)