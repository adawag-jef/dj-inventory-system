web gunicorn core.wsgi
config:set DISABLE_COLLECTSTATIC=1
release: python manage.py makemigrations --noinput
release: python manage.py migrate --noinput