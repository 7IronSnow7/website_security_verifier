#!/bin/bash
# build_files.sh

# Use python3 and pip3 explicitly with their full paths
/opt/vercel/python3/bin/pip3 install -r requirements.txt

# Make directory structure for templates
mkdir -p /var/app/templates
mkdir -p staticfiles

# Copy templates from the correct location to where Vercel looks for them
# Update this path to match your actual project structure
cp -r myproject/templates/* /var/app/templates/ || echo "Warning: Could not copy templates"

# Use the full path to python3
/opt/vercel/python3/bin/python3 manage.py collectstatic --noinput || echo "Warning: Could not collect static files"