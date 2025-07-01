#!/bin/bash

sleep 2
# Apply database migrations
echo "Apply database migrations"
python manage.py migrate

# Initial CSS build
#echo "Building styles"
#bash ./scripts/sass.sh build

# Start server
echo "Starting web server"
python manage.py runserver 0.0.0.0:8000
