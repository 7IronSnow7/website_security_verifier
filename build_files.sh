#!/bin/bash
# build_files.sh
pip install -r requirements.txt

# Make directory structure for templates
mkdir -p /var/app/templates
mkdir -p staticfiles

# Copy templates from your app directory to where Vercel looks for them
cp -r app/templates/* /var/app/templates/

python manage.py collectstatic --noinput