import os
from importlib.machinery import SourceFileLoader

from pkg_resources import parse_requirements
from setuptools import find_packages, setup


module_name = 'desentralised_voting'

module = SourceFileLoader(
    module_name, os.path.join(module_name, '__init__.py')
).load_module(module_name)


def load_requirements(fname: str) -> list:
    requirements = []
    with open(fname, 'r') as fp:
        for req in parse_requirements(fp.read()):
            extras = '[{}]'.format(','.join(req.extras)) if req.extras else ''
            requirements.append(
                '{}{}{}'.format(req.name, extras, req.specifier)
            )
    return requirements


setup(
    name=module_name,
    version=module.__version__,
    author=module.__author__,
    author_email=module.__email__,
    license=module.__license__,
    description=module.__doc__,
    python_requires='>=3.8',
    packages=find_packages(),
    install_requires=load_requirements(module_name + '/requirements.txt'),
    include_package_data=True
)
