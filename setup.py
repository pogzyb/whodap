from setuptools import setup
import pathlib


base_dir = pathlib.Path(__file__).parent.resolve()
long_description = (base_dir / 'README.md').read_text(encoding='utf-8')


def get_version(location: str) -> str:
    with open((base_dir / location).absolute().resolve()) as file:
        for line in file.readlines():
            if line.startswith('__version__'):
                return line.split(' = ')[-1].strip().replace("\"", "")
        else:
            raise RuntimeError('Unable to find version string.')


setup(
    name='whodap',
    version=get_version('whodap/__init__.py'),
    description='Simple RDAP Utility for Python',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/pogzyb/whodap',
    author='Joseph Obarzanek',
    author_email='pogzyb@umich.edu',
    python_requires='>=3.6, <4',
    keywords='security, whois, rdap, research',
    install_requires=[
        'httpx>=0.20.0',
        'async_generator>=1.10; python_version < "3.7.0"'
    ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development',
        'Topic :: Security',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3 :: Only',
    ],
    packages=['whodap'],
    package_dir={'whodap': 'whodap'},
)
