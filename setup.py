"""setup.py

Due to scikit-learn, pip is required:

    pip install .

"""
import pathlib

from setuptools import find_packages, setup


README_PATH = pathlib.Path(__file__).parent / 'README.md'

INSTALL_REQUIRES = [
    'numpy ~= 1.23.3',
    'pandas ~= 1.5.0',
    'pyod ~= 1.0.5',
    'scapy ~= 2.4.5',
    'scikit-learn ~= 1.1.2',
]

_CLI_REQUIRES = [
    'argcmdr==0.13.1',
    'argparse-formatter==1.4',
    'PyYAML==6.0',
    'terminaltables==3.1.10',
]

_TESTS_REQUIRE = [
    'tox==3.26.0',
]

EXTRAS_REQUIRE = {
    'cli': _CLI_REQUIRES,

    'dev': _CLI_REQUIRES + _TESTS_REQUIRE + [
        'bumpversion==0.6.0',
        'twine==4.0.1',
        'wheel==0.37.1',
    ],

    # (as yet) unused:
    # 'visualize': ['matplotlib==3.2.1'],
}


setup(name='netml',
      version='0.2.1',
      description='Network anomaly detection via machine learning',
      long_description=README_PATH.read_text(),
      long_description_content_type="text/markdown",
      url='https://github.com/chicago-cdac/netml',
      # license='xxx',  # FIXME
      python_requires='>=3.8.11,<3.11',
      install_requires=INSTALL_REQUIRES,
      extras_require=EXTRAS_REQUIRE,
      classifiers=[
          'Development Status :: 2 - Pre-Alpha',
          'Intended Audience :: Developers',
          'Intended Audience :: Education',
          'Intended Audience :: Science/Research',
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 3.8',
          'Programming Language :: Python :: 3.9',
          'Programming Language :: Python :: 3.10',
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
