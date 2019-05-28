
# Description

This is a project made for a Item Catalog Website.

# Requirements

1. Virtual machine - [Vagrant](https://www.vagrantup.com/)
2. [VirtualBox](https://www.virtualbox.org/)
3. [SQLAlchemy](https://www.sqlalchemy.org/) module
4. Flask module
5. Python3

# <span id="data">Data</span>

1. `python database_setup.py` to build the database.
2. `python lotsofitems.py` to write in the data samples.

# Setup

1. Fork the [fullstack-nanodegree-vm](https://github.com/udacity/fullstack-nanodegree-vm) .
2.  `git clone http://github.com/<username>/fullstack-nanodegree-vm fullstack`
3. `vagrant up`  to start up the virtual machine.
4. `vagrant ssh` to log into the virtual machine.
5. `cd /vagrant`, copy the project into the directory.
6. Prepare the data according to [Data](#data).
7. `python project.py` to start the server.

# <span id="view">Browse Instruction</span>

- See the home page the application:
http://localhost:5000/

- See the JSON endpoint:
http://localhost:5000/catalog.json

