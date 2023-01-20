import os
import io
import codecs
import re
from setuptools import setup


def read(*names):
    with io.open(
        os.path.join(os.path.dirname(__file__), *names),
        encoding='utf-8'
    ) as f:
        return f.read()


def find_version(*file_paths):
    version_file = read(*file_paths)
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]",
                              version_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError('Unable to find version string.')


with codecs.open('README.md', 'r', 'utf-8') as f:
    readme = f.read()
with codecs.open('HISTORY.md', 'r', 'utf-8') as f:
    history = f.read()


version = find_version('requests_aws4auth', '__init__.py')


setup(
    name='requests-aws4auth',
    version=version,
    description='AWS4 authentication for Requests',
    long_description=readme + '\n\n' + history,
    long_description_content_type='text/markdown',
    author='Ted Timmons',
    author_email='ted@tedder.dev',
    url='https://github.com/tedder/requests-aws4auth',
    download_url=('https://github.com/tedder/requests-aws4auth/tarball/' + version),
    license='MIT License',
    keywords='requests authentication amazon web services aws s3 REST',
    install_requires=['requests', 'six'],
    extras_require={
        'httpx': ['httpx',]
    },
    packages=['requests_aws4auth'],
    package_data={'requests_aws4auth': ['test/requests_aws4auth_test.py']},
    python_requires=">=3.3",
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Topic :: Internet :: WWW/HTTP'])
