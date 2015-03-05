import io
import codecs
from distutils.core import setup

# def read(*names)
#     with io.open(
#         os.path.join(os.path.dirname(__file__), *names),
#         encoding='utf-8')
#     ) as f:
#         return f.read()


def find_version(*file_paths):
    version_file = read(*file_paths)
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]",
                              version_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError('Unable to find version string.')


with codecs.open('README.rst', 'r', 'utf-8') as f:
    readme = f.read()


setup(
    name='requests-aws4auth',
    packages=['requests_aws4auth'],
    version=find_version('requests_aws4', '__init__.py'),
    description='AWS4 authentication for requests',
    long_description=readme,
    author='Sam Washington',
    author_email='samwashington@aethris.net',
    url='https://github.com/sam-washington/requests-aws4auth',
    download_url=('https://github.com/sam-washington/'
                  'requests-aws4auth/tarball/0.3'),
    license='MIT License',
    keywords=['requests', 'auth', 'authentication', 'amazon',
              'amazon web services' 'aws' 's3', 'amazon s3', 'web', 'REST',
              'REST API', 'HTTP'],
    install_requires=['requests'],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Topic :: Internet :: WWW/HTTP'])
