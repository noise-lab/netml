"""setup.py

Due to scikit-learn, pip is required:

    pip install .

"""
import pathlib

from setuptools import find_packages, setup


README_PATH = pathlib.Path(__file__).parent / 'README.md'

INSTALL_REQUIRES = [
    'netaddr ~= 1.3.0',
    'numpy ~= 2.0.1',
    'pandas ~= 2.2.2',
    'pyod ~= 2.0.1',
    'scapy ~= 2.5.0',
    'scikit-learn ~= 1.5.1',
]

_CLI_REQUIRES = [
    'argcmdr==0.13.1',
    'argparse-formatter==1.4',
    'PyYAML==6.0.1',
    'terminaltables==3.1.10',
]

_TESTS_REQUIRE = [
    'tox==3.26.0',
]

EXTRAS_REQUIRE = {
    'cli': _CLI_REQUIRES,

    'dev': _CLI_REQUIRES + _TESTS_REQUIRE + [
        'bumpversion==0.7.0',
        'twine==5.1.1',
        'wheel==0.43.0',
    ],

    # (as yet) unused:
    # 'visualize': ['matplotlib==3.2.1'],
}


setup(name='netml',
      version='0.7.0',
      description='Feature Extraction and Machine Learning from Network Traffic Traces',
      long_description=README_PATH.read_text(),
      long_description_content_type="text/markdown",
      url='https://github.com/noise-lab/netml',
      license='Apache 2.0',
      python_requires='>=3.8.11,<4',
      install_requires=INSTALL_REQUIRES,
      extras_require=EXTRAS_REQUIRE,
      classifiers=[
          'Development Status :: 2 - Pre-Alpha',
          'Intended Audience :: Developers',
          'Intended Audience :: Education',
          'Intended Audience :: Science/Research',
          'License :: OSI Approved :: Apache Software License',
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 3.9',
          'Programming Language :: Python :: 3.10',
          'Programming Language :: Python :: 3.11',
          'Programming Language :: Python :: 3.12',
          'Topic :: Software Development :: Libraries',
          'Topic :: Software Development :: Libraries :: Python Modules',
          'Topic :: Scientific/Engineering :: Artificial Intelligence',
          'Topic :: System :: Networking :: Monitoring',
      ],
      packages=find_packages('src'),
      package_dir={'': 'src'},
      entry_points={
          'console_scripts': ['netml=netml.cli:execute [cli]'],
      })
