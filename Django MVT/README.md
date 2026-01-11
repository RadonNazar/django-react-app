# Simple MVT - PD421
```
py --version
py -m venv .venv
python3 -m venv .venv
```

## Activate venv
```
.venv\Scripts\activate.bat
source .venv/bin/activate
python.exe -m pip install --upgrade pip
python3 -m pip install --upgrade pip
py -m pip install Django
python3 -m pip install Django

py

>>>import django
>>>print(django.get_version())
>>>quit()

python -m django --version
mkdir djangomvt
django-admin startproject mysite djangomvt
cd djangomvt
py manage.py runserver 9581

py manage.py startapp categories
py manage.py migrate

py manage.py startapp users

deactivate
```

## Install Postgres
```
pip install psycopg2-binary
py manage.py migrate
python3 manage.py migrate
```

## Clone Project
```
.venv\Scripts\activate.bat
pip freeze
pip freeze > requirements.txt

git clone https://github.com/novakvova/Python-Django-PD421.git
cd Python-Django-PD421
cd Django MVT
py -m venv .venv
.venv\Scripts\activate.bat

python.exe -m pip install --upgrade pip
#py -m pip install Django
pip install -r requirements.txt
cd djangomvt
py manage.py runserver 4892
```

## Додаємо модель і робимо міграції
```
pip install Pillow
py manage.py makemigrations categories
py manage.py migrate
```

## Додаю superuser
```
python manage.py createsuperuser
py manage.py createsuperuser
admin
123456
py manage.py runserver 4892
```

## Додаємо продукти і фото до них
```
py manage.py startapp products
py manage.py makemigrations products
py manage.py migrate
```

# Install Unicode
```
pip install Unidecode
```
