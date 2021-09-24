#!/bin/sh -l

pip install xmltodict
python qualysdast-api.py --qualysuser $1 --qualyspass $2 --website $3 --project $4
