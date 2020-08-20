===================
Running with Docker
===================

1. Install Docker and Docker Compose
************************************

Follow these instructions:
    * `Docker <https://docs.docker.com/get-docker/>`_
    * `Docker Compose <https://docs.docker.com/compose/install/>`_

2. Clone Freki's latest version
*******************************

.. code:: bash

    $ git clone https://github.com/crhenr/freki.git

3. Edit the ``.env`` configuration file
***************************************

.. code:: bash

    $ cd freki
    $ vi .env
    # Instance secret key
    FREKI_SECRET_KEY=ChangeThis

    # VT master key, used in case the user did not provide his key
    VT_MASTER_KEY=VirusTotalMasterKey

    # MySQL password for the Freki and root users
    DB_PASSWORD=SecretPassword
    DB_ROOT_PASSWORD=AnotherSecretPassword

* **FREKI_SECRET_KEY**: The secret key is needed to keep the client-side sessions secure. You can use Python to generate a random key:

.. code:: python

    import os
    print(os.urandom(24).hex())

* **VT_MASTER_KEY**: When a file is submitted, Freki first tries to use the user's key. However, users may not have a VirusTotal (VT) API key. In this case, Freki tries to query VT with the administrator's key. You can leave this field blank, but you will depend exclusively on the goodwill of users.

NOTE: By default, Freki queries VT for non-analyzed samples every 5 minutes.

* **DB_PASSWORD**: The MySQL password for the freki user.

* **DB_ROOT_PASSWORD**: The MySQL root password.

You are encouraged to check the docker-compose.yml file for additional tweaks.

4. Enable HTTPS
***************

At this point, you should be able to start Freki. However, a good practice (especially if you are going to make your instance public) is to enable HTTPS.

You must move your certificate and private key to a ``nginx/certs`` folder so that Docker Compose can mount it inside the container at ``/etc/nginx/certs``.

After that, you need to edit the ``nginx/freki.conf`` to something like this:

.. code:: nginx

    server {
        listen 80;
        server_name 192.168.99.100;

        return 301 https://$host$request_uri;
    }

    server {
        listen 443 ssl;
        server_name 192.168.99.100;
        ssl_certificate /etc/nginx/certs/fullchain.pem;
        ssl_certificate_key /etc/nginx/certs/privkey.pem;

        location / {
            proxy_pass http://freki:8000;

            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }

5. Run Freki!
*************

.. code:: bash

    $ make build

or

.. code:: bash

    $ docker-compose up -d