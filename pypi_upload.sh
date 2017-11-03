echo "Building sdist"
python setup.py sdist

echo "Uploading using Twine"
twine upload dist/* --skip-existing --username $PYPI_USER --password $PYPI_PASSWORD
