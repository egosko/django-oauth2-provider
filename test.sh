#!/bin/bash

python manage.py test provider provider.oauth2 --traceback --failfast
