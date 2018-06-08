#!/usr/bin/env bash
cd $(dirname $0)
users=$@
if [[ -z $users ]];then
        echo "$0 user"
        exit 1
fi
export DJANGO_SETTINGS_MODULE=vaultier.vaultier_settings
if [ -e venv/bin/activate ];then
    . venv/bin/activate
fi

cd vaultier/vaultier
dbsetting() {
    python -c "import $DJANGO_SETTINGS_MODULE;print($DJANGO_SETTINGS_MODULE.DATABASES['default']['$1'])"
}
export PGPASSWD=$(dbsetting PASSWORD)
export PGPASSWORD=$(dbsetting PASSWORD)
for user in $users;do
    echo "update vaultier_user set nickname ='old2$user', email='sysadmin+old2${user}@makina-corpus.com', public_key='' where nickname='${user}';" | ./manage.py dbshell
done 
# vim:set et sts=4 ts=4 tw=80:
