# coraUtil
a Python module that allows the use of Campbell Scientific cora script

# Building PiPy package
Pure Python Wheels that are not “universal” are wheels that are pure python (i.e. contains no compiled extensions), but don’t natively support both Python 2 and 3.

To build the wheel:

`pipenv run python setup.py sdist bdist_wheel`
`pipenv run twine upload dist/*`

`https://packaging.python.org/distributing/#wheels`



# Installation
## From setup.py
## From package
