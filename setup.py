"""setup.py

Due to scikit-learn, pip is required:

    pip install .

"""
import pathlib

from setuptools import find_packages, setup


README_PATH = pathlib.Path(__file__).parent / 'readme.md'

INSTALL_REQUIRES = (
    'numpy==1.18.3',
    'pandas==0.25.1',
    'scapy==2.4.3',
    'scikit-learn==0.23.1',
)

EXTRAS_REQUIRE = {
    # (as yet) unused:
    # 'visualize': ['matplotlib==3.2.1'],
    # 'tests': ['pytest==5.3.1', 'requests==2.22.0'],
}


setup(name='odet',
      version='0.0.1',
      description='Novelty Detection',
      long_description=README_PATH.read_text(),
      long_description_content_type="text/markdown",
      author='Kun',
      author_email='kun.bj@outlook.com',
      url='https://github.com/Learn-Live/odet',
      download_url='https://github.com/Learn-Live/odet',
      license='xxx',
      python_requires='>=3.7.3,<4',
      install_requires=INSTALL_REQUIRES,
      extras_require=EXTRAS_REQUIRE,
      classifiers=[
          'Development Status :: 2 - Pre-Alpha',
          'Intended Audience :: Developers',
          'Intended Audience :: Education',
          'Intended Audience :: Science/Research',
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 3.7',
          'Programming Language :: Python :: 3.8',
          'Topic :: Software Development :: Libraries',
          'Topic :: Software Development :: Libraries :: Python Modules'
          'Topic :: Scientific/Engineering :: Artificial Intelligence',
          'Topic :: System :: Networking :: Monitoring',
      ],
      packages=find_packages('src'),
      package_dir={'': 'src'},
)
