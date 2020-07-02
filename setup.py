"""Setup.py
    python3 setup.py build
    python3 setup.py install
"""
# Authors: kun.bj@outlook.com
#
# License: xxx
import os

from setuptools import find_packages
from setuptools import setup


def read(readme_file):
    """Utility function to read the README file. Used for the long_description.

    Parameters
    ----------
    readme_file: str

    Returns
    -------

    """

    value = open(os.path.join(os.path.dirname(__file__), readme_file), 'r', encoding='utf-8').read()
    return str(value)


setup(name='odet',
      version='0.0.1',
      description='Novelty Detection',
      long_description=read('readme.md'),
      # long_description='Data representation for IoT traffic',
      long_description_content_type="text/markdown",
      author='Kun',
      author_email='kun.bj@outlook.com',
      url='https://github.com/Learn-Live/odet',
      download_url='https://github.com/Learn-Live/odet',
      license='xxx',
      python_requires='==3.7.3',
      install_requires=['numpy==1.18.3',
                        'scipy==1.4.1',
                        'pandas==0.25.1',
                        'scapy==2.4.3',
                        'scikit-learn==0.21.3'
                        ],
      extras_require={
          'visualize': ['matplotlib==3.2.1'],
          'tests': ['pytest==5.3.1',
                    'requests==2.22.0'
                    ],
      },
      classifiers=[
          'Development Status :: 5 - Production/Stable',
          'Intended Audience :: Developers',
          'Intended Audience :: Education',
          'Intended Audience :: Science/Research',
          'License :: OSI Approved :: Python Software Foundation License',
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 3.7',
          'Topic :: Software Development :: Libraries',
          'Topic :: Software Development :: Libraries :: Python Modules'
      ],
      # automatically find the packages with __init__.py file and start from the setup.py's directory
      packages=find_packages())
