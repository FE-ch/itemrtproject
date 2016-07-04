# Use virtualenv for this project
source virtualenvwrapper.sh

workon itemrtproject

# Shortcut script to run server using local ip address so it can be accessed by the host
python manage.py runserver 10.0.2.15:8000
#python manage.py runserver 192.168.1.144:8000

# clangkts@gmail.com Dr0wssap Jan 1 1988