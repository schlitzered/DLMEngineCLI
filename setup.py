from setuptools import setup, find_packages

setup(
    name='DlmEngineCli',
    version='0.0.4',
    description='DlmEngine, distributed lock implementation on top of MongoDB and Redis',
    long_description="""
DLMEngine implements a restful interface that can be used to implement distributed locks.

The main intention was to orchestrate automated system updates, so only one server at a time will do a update.

Copyright (c) 2019, Stephan Schultchen.

License: MIT (see LICENSE for details)
    """,
    packages=find_packages(),
    scripts=[
        'contrib/dlm_engine_cli',
    ],
    url='https://github.com/schlitzered/DlmEngineCli',
    license='MIT',
    author='schlitzer',
    author_email='stephan.schultchen@gmail.com',
    include_package_data=True,
    test_suite='test',
    platforms='posix',
    classifiers=[
            'License :: OSI Approved :: MIT License',
            'Programming Language :: Python :: 3'
    ],
    install_requires=[
        "requests",
        "texttable"
    ],
    keywords=[
        'dlm', 'distributes lock manager engine cli'
    ]
)
