"""This file installs Pyfhel in your Python3 distribution.
#   > python3 -m pip install .
# PYPI -> https://packaging.python.org/tutorials/packaging-projects/
#   > python3 setup.py sdist
#   > twine upload dist/*
#   > python3 setup.py clean --all
"""
# ==============================================================================
# ============================ INITIALIZATION ==================================
# ==============================================================================
from typing import Union, List, Tuple
from pathlib import Path
import os
import re
import platform
import toml

# Create Extension modules written in C for Python
from setuptools import setup, Extension, find_packages

# Get platform system
platform_system = platform.system()
    
# Read config file
config = toml.load("pyproject.toml")
project_config = config['project']
project_name = project_config['name']

# -------------------------------- VERSION -------------------------------------
## Uniformize version across the entire project, taking pyproject.toml as truth.
# Reading version from pyproject.toml
VERSION = project_config['version']
def re_sub_file(regex: str, replace: str, filename: str):
    """Replaces all occurrences of regex in filename with re.sub

    Args:
        regex (str): Regular expression to be replaced
        replace (str): Replacement string
        filename (str): File to be modified
    """
    with open(filename) as sub_file:
        file_string = sub_file.read()
    with open(filename, 'w') as sub_file:
        sub_file.write(re.sub(regex, '{}'.format(replace), file_string))

# Writing version in __init__.py and README.md
V_README_REGEX = r'(?<=\* \*\*_Version_\*\*: )[0-9]+\.[0-9]+\.[0-9a-z]+'
V_INIT_REGEX = r'(?<=__version__ = \")[0-9]+\.[0-9]+\.[0-9a-z]+(?=\")'
re_sub_file(regex=V_README_REGEX, replace=VERSION, filename='README.md')
re_sub_file(regex=V_INIT_REGEX, replace=VERSION, filename=Path('funshade/py/__init__.py'))


# -------------------------------- OPTIONS -------------------------------------
# Compile cython files (.pyx) into C++ (.cpp) files to ship with the library.
CYTHONIZE = False
try:
    from Cython.Build import cythonize
    CYTHONIZE = True
except ImportError:
    pass    # Cython not available, reverting to previously cythonized C++ files

# ==============================================================================
# ======================== AUXILIARY FUNCS & COMMANDS ==========================
# ==============================================================================
# Generic utlilities that would normally go in a "utils" folder.
# -------------------------- CONFIG AUXILIARIES --------------------------------
def _pl(args: List[Union[str,dict]]) -> List[str]:
    """_pl: Instantiates platform-dependent args based on current platform.
    It takes the dict elements `el` in args and replaces them by `el[platform_system]"""
    args_pl = []
    for arg in args:
        if isinstance(arg, dict):
            if platform_system in arg:      # A platform-dependent arg
                args_pl += arg[platform_system]
        else:   args_pl.append(arg)
    return args_pl

def _path(args: List[str], base_dir=None) -> List[Path]:
    """_path: Turns all string elements into absolute paths with pathlib.Path"""
    base_dir = Path('') if base_dir is None else base_dir
    return  [(base_dir/arg).absolute().as_posix() if isinstance(arg, (str, Path)) else arg for arg in args]

def _npath(args: List[str], base_dir=None) -> List[Path]:
    """_npath: Normalizes path separations with is.path.normpath. Does not generate absolute paths"""
    base_dir = Path('') if base_dir is None else base_dir
    return [os.path.normpath((base_dir/arg).as_posix()) if isinstance(arg, (str, Path)) else arg for arg in args]
    
def _tupl(args: List[List[str]]) -> List[Tuple[str, str]]:
    """_tupl: Picks elements and turns them into tuples"""
    return  [tuple(arg) for arg in args]

# ==============================================================================
# ================================ EXTENSIONS ==================================
# ==============================================================================
# These are the Cython/C++ extensions callable from Python. More info:
#   https://cython.readthedocs.io/en/latest/src/userguide/wrapping_CPlusPlus
# ----------------------------- EXTENSION BUILDER ------------------------------
from setuptools.command.build_ext import build_ext
class SuperBuildExt(build_ext):
    def finalize_options(self):
        build_ext.finalize_options(self)
        # We need the numpy headers and cmake-built headers for compilation.
        #  We delay it for the setup to raise a nice error if numpy is not found.
        #  https://stackoverflow.com/questions/54117786
        import numpy
        self.include_dirs.append(numpy.get_include())
        print("cimporting numpy version '%s'", numpy.__version__)



# ----------------------------- EXTENSION CONFIG -------------------------------
# Generic compile & link arguments for extensions. Can be modified.
extensions          = config.pop('extensions', {})
config_all          = extensions.pop('config', {})

include_dirs        =  _path(_pl(config_all.get('include_dirs', [])))
define_macros       =  _tupl(_pl(config_all.get('define_macros', [])))
extra_compile_args  =  _pl(config_all.get('extra_compile_args', []))
extra_link_args     =  _pl(config_all.get('extra_link_args', []))
libraries           =  _pl(config_all.get('libraries', []))
library_dirs        =  _path(_pl(config_all.get('library_dirs', [])))

ext_modules = []
for ext_name, ext_conf in extensions.items():
    ext_modules.append(Extension(
        name            = ext_conf.pop('fullname', f"{project_name}.{ext_name}"),
        sources         =_npath(_pl(ext_conf.pop('sources', []))),
        include_dirs    = include_dirs,
        define_macros   = define_macros,
        extra_compile_args = extra_compile_args,
        extra_link_args = extra_link_args,
        libraries       = libraries,
        library_dirs    = library_dirs,
        language        = "c",
    ))


# Try cythonizing if cython is available
if CYTHONIZE:
    cython_directives = {
        'embedsignature': True,
        'language_level': 3,
        'cdivision': True,
        'boundscheck': False,
        'c_string_type': 'unicode',
        'c_string_encoding': 'ascii',
        'wraparound': False,
        'initializedcheck': False,
    }
    ext_modules=cythonize(
        ext_modules,
        compiler_directives=cython_directives)

else: # If cython is not available, we use the prebuilt C++ extensions if available
    for ext in ext_modules:
        ext.sources = [s.replace(".pyx", ".c") \
            if Path(s.replace(".pyx", ".c")).exists() else s for s in ext.sources]

# ==============================================================================
# ============================== SETUP INSTALLER ===============================
# ==============================================================================

# Including Readme in the module as long description.
with open(project_config['readme'], "r") as f:
    long_description = f.read()

setup(
    # Metadata
    name            = project_name,
    version         = VERSION,
    author          = ', '.join([n['name'] for n in project_config['authors']]),
    author_email    = ', '.join([n['email'] for n in project_config['authors']]),
    description     = project_config['description'],
    long_description= long_description,
    long_description_content_type="text/markdown",
    classifiers     = project_config['classifiers'],
    keywords        = ', '.join(project_config['keywords']),
    license         = project_config['license']['text'],
    # Options
    install_requires=project_config['dependencies'],
    python_requires =project_config['requires-python'],
    zip_safe        =False,
    packages        =find_packages(),
    include_package_data=False,
    ext_modules     =ext_modules,
    cmdclass        ={'build_ext' : SuperBuildExt},
)
