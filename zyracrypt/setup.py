#!/usr/bin/env python3
"""
Setup script for ZyraCrypt - Advanced Encryption System
Compiles Python source to Cython extensions for source code protection
Developer: Abdulaziz Alqudimi | Company: Alqudimi Technology
"""

import os
import sys
from setuptools import setup, Extension, find_packages

# Try to import Cython, fall back to setuptools if not available
try:
    from Cython.Build import cythonize
    from Cython.Distutils import build_ext
    CYTHON_AVAILABLE = True
except ImportError:
    CYTHON_AVAILABLE = False
    print("Warning: Cython not available, installing without compiled extensions")
    cythonize = None
    build_ext = None

# Package information
PACKAGE_NAME = "zyracrypt"
VERSION = "2.0.1"
DESCRIPTION = "ZyraCrypt - Enterprise-grade cryptographic library with advanced security features"

# Get the directory containing this setup.py
SETUP_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(SETUP_DIR, "encryption_system", "src")

def find_all_python_files(directory):
    """Find all Python files to be compiled to Cython extensions"""
    python_files = []
    for root, dirs, files in os.walk(directory):
        # Skip __pycache__ directories
        dirs[:] = [d for d in dirs if d != '__pycache__']
        for file in files:
            if file.endswith('.py') and not file.startswith('__'):
                filepath = os.path.join(root, file)
                python_files.append(filepath)
    return python_files

def create_extensions():
    """Create Cython extension modules for core security-critical modules only"""
    if not CYTHON_AVAILABLE:
        return []
    
    extensions = []
    
    # Only compile core modules that are security-critical and performance-sensitive
    core_modules = [
        'core_cryptography/symmetric_encryption.py',
        'core_cryptography/asymmetric_encryption.py', 
        'core_cryptography/encryption_framework.py',
        'key_management/key_manager.py',
        'key_management/enhanced_kdf_password.py',
        'key_management/envelope_encryption_kms.py',
        'data_protection/data_protection_manager.py',
        'advanced_features/hybrid_pqc_enhanced.py',
        'advanced_features/threshold_multisig_enhanced.py',
        'advanced_features/side_channel_protection.py',
    ]
    
    for module_path in core_modules:
        py_file = os.path.join(SRC_DIR, module_path)
        if os.path.exists(py_file):
            # Convert file path to module name
            module_name = module_path.replace(os.sep, '.').replace('.py', '')
            module_name = f"{PACKAGE_NAME}.encryption_system.src.{module_name}"
            
            # Create extension
            ext = Extension(
                name=module_name,
                sources=[py_file],
                include_dirs=[],
                library_dirs=[],
                libraries=[],
            )
            extensions.append(ext)
            print(f"Adding Cython extension: {module_name}")
    
    return extensions

# Create extensions
extensions = create_extensions()

# Build extensions with Cython (if available)
if CYTHON_AVAILABLE and extensions:
    # Cython compiler directives for optimization and security
    compiler_directives = {
        'language_level': 3,
        'annotation_typing': False,  # Ignore Python type annotations for Cython
        'binding': True,             # Enable Python binding for better compatibility
        'boundscheck': False,        # Disable bounds checking for performance
        'wraparound': False,         # Disable negative index wrapping
        'initializedcheck': False,   # Disable initialization checking
        'cdivision': True,           # Use C division semantics
        'embedsignature': False,     # Don't embed function signatures (security)
        'emit_code_comments': False, # No code comments in output
    }
    
    cython_extensions = cythonize(
        extensions,
        compiler_directives=compiler_directives,
        build_dir="build/cython",
        include_path=[SRC_DIR]
    )
else:
    cython_extensions = []

# Dependencies - match the ones from pyproject.toml
install_requires = [
    "argon2-cffi>=25.1.0",
    "boto3>=1.40.39", 
    "cryptography>=46.0.1",
    "liboqs-python>=0.14.1",
    "pillow>=11.3.0",
    "pqcrypto>=0.3.4",
    "pynacl>=1.6.0",
    "quantcrypt>=1.0.1",
    "requests>=2.32.5",
]

# Package data - include any non-Python files needed
package_data = {
    f'{PACKAGE_NAME}': [
        'encryption_system/docs/*',
        'encryption_system/*.txt',
        'encryption_system/src/*/__init__.py',
        'encryption_system/src/__init__.py',
        'encryption_system/__init__.py',
    ],
}

# Setup configuration
setup(
    name=PACKAGE_NAME,
    version=VERSION,
    description=DESCRIPTION,
    long_description="ZyraCrypt: Advanced cryptographic library providing enterprise-grade encryption services with post-quantum cryptography, key management, and advanced security features. Developed by Abdulaziz Alqudimi at Alqudimi Technology.",
    long_description_content_type="text/plain",
    author="Abdulaziz Alqudimi",
    author_email="contact@alqudimi.tech",
    url="https://github.com/Alqudimi/ZyraCrypt",
    
    # Package configuration
    packages=find_packages(),
    package_data=package_data,
    include_package_data=True,
    
    # Compiled extensions
    ext_modules=cython_extensions,
    
    # Dependencies
    install_requires=install_requires,
    python_requires='>=3.11',
    
    # Build configuration (only if Cython is available)
    cmdclass={'build_ext': build_ext} if CYTHON_AVAILABLE else {},
    zip_safe=False,  # Cython extensions can't be zipped
    
    # Metadata
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Topic :: Security :: Cryptography',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'License :: Other/Proprietary License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Cython',
        'Operating System :: OS Independent',
    ],
    keywords=['cryptography', 'encryption', 'security', 'post-quantum', 'enterprise'],
    
    # Entry points for command line tools (optional)
    entry_points={
        'console_scripts': [
            f'{PACKAGE_NAME}=zyracrypt.cli:main',
        ],
    },
)