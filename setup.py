from distutils.core import setup
from codecs import open

with open('README.rst', 'r', 'utf-8') as f:
    readme = f.read()

setup(
    name = 'requests-aws4auth',
    packages = ['requests-aws4auth'],
    version = '0.2',
    description = 'Amazon Web Services version 4 authentication for the Python requests module',
    long_description = readme,
    author = 'Sam Washington',
    author_email = 'samwashington@aethris.net',
    url = 'https://github.com/sam-washington/requests-aws4auth',
    download_url = 'https://github.com/sam-washington/requests-aws4auth/tarball/0.2',
    license = 'MIT License',
    keywords = ['requests', 'auth', 'authentication', 'amazon', 'amazon web services' 'aws' 's3', 'amazon s3', 'web', 'REST', 'REST API', 'HTTP'],
    classifiers = [
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Topic :: Internet :: WWW/HTTP'
  ],
)
