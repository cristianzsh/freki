=========================
Step by step installation
=========================

1. Install packages
*******************

.. tabs::

    .. group-tab:: Ubuntu/Debian

        .. code:: bash

            $ sudo apt install -y \
            git python3 python3-dev python3-pip python3-mysqldb \
            python3-setuptools python3-virtualenv \
            mariadb-server libmariadbclient-dev \
            libfuzzy-dev libssl-dev ssdeep

    .. group-tab:: Arch Linux

        .. code:: bash

            $ sudo pacman -S --noconfirm \
            git python3 python-pip mysql-python \
            python-setuptools python-virtualenv \
            mariadb mariadb-libs ssdeep gcc automake

    .. group-tab:: Fedora/RHEL

        .. code:: bash

            $ sudo dnf install -y \
            git python3 python3-devel python3-pip \
            python3-mysql python3-setuptools python3-virtualenv \
            mariadb-server mariadb-devel ssdeep ssdeep-devel \
            ssdeep-libs

2. Create a database user for Freki
***********************************

.. code:: bash

    $ sudo mysql_secure_installation
    $ sudo mysql -u root -p

    mysql> CREATE USER 'freki'@'localhost' IDENTIFIED BY 'yourpassword';
    mysql> GRANT ALL PRIVILEGES ON * . * TO 'freki'@'localhost';
    mysql> FLUSH PRIVILEGES;
    mysql> exit

3. Create a folder to store the uploaded samples
************************************************

.. code:: bash

    $ sudo mkdir /opt/freki
    $ sudo chown -R youruser:usergroup /opt/freki

4. Clone Freki's latest version
*******************************

.. code:: bash

    $ git clone https://github.com/crhenr/freki.git

5. Create and start a new virtualenv
************************************

.. code:: bash

    $ cd freki/freki
    $ virtualenv venv
    $ source venv/bin/activate

6. Install the Python requirements
**********************************

.. code:: bash

    (venv) $ pip3 install -r requirements.txt

7. Export the required environment variables
********************************************

.. code:: bash

    (venv) $ export FREKI_MYSQL_HOST="localhost"
    (venv) $ export FREKI_MYSQL_PASSWORD="yourpassword"
    (venv) $ export FREKI_SECRET_KEY="yoursecretkey"

8. Run Freki!
*************

.. code:: bash

    (venv) $ python3 run.py

or

.. code:: bash

    (venv) $ gunicorn --bind 0.0.0.0:5000 run:app
