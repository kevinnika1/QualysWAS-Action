#!/bin/sh -l

pip install urllib3
pip install requests
pip install xmltodict

python qualysdast-api.py --qualysuser $1 --qualyspass $2 --website $3 --project $4
