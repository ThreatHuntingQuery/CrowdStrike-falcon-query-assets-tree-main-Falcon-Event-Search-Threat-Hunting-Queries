set -e

VERSION=$(grep version manifest.yaml | grep -o "\d*\.\d*\.\d*")
PACKAGENAME=$(grep -o "^name: .*" manifest.yaml | awk -F": " '{print $2}' | sed 's/\//--/g')

# Figure out the archive name
ARCHIVE=$PACKAGENAME--${VERSION}.zip


# Create a new zip archive
(
  zip -r $ARCHIVE \
	manifest.yaml \
	actions \
	alerts \
	queries \
	parsers \
	dashboards \
	scheduled-searches \
	README.md
)

echo Created package $ARCHIVE
