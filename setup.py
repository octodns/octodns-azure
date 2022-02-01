from setuptools import find_packages, setup


def descriptions():
    with open('README.md') as fh:
        ret = fh.read()
        first = ret.split('\n', 1)[0].replace('#', '')
        return first, ret


def version():
    with open('octodns_azure/__init__.py') as fh:
        for line in fh:
            if line.startswith('__VERSION__'):
                return line.split("'")[1]


description, long_description = descriptions()

setup(
    author='Ross McFarland',
    author_email='rwmcfa1@gmail.com',
    description=description,
    license='MIT',
    long_description=long_description,
    long_description_content_type='text/markdown',
    name='octodns-azure',
    packages=find_packages(),
    python_requires='>=3.6',
    install_requires=(
        'azure-identity>=1.7.1',
        'azure-mgmt-dns>=8.0.0',
        'azure-mgmt-trafficmanager>=0.51.0',
        'msrestazure>=0.6.4',
        'octodns>=0.9.14',
    ),
    url='https://github.com/octodns/octodns-azure',
    version=version(),
    tests_require=[
        'pytest',
        'pytest-network',
    ],
)
