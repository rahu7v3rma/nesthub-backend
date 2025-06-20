# NH Backend Service

## NH CMS
The NH CMS is the admin interface for NH data which manages all NH content.

## Launching the development environment

### Clone and install dependencies

```bash
$ git clone https://github.com/beehive-software/np-backend.git
$ cd np-backend
$ python3 -m venv venv
$ source venv/bin/activate
$ pip install -r requirements.txt
```

### Define environment variables

```bash
$ cp .env.dist .env
```

Update environment variables

### Setup a local database

SQLite is currently used as a database for development setups, so no action is needed to setup a new one.


### Run the service

```bash
$ python3 src/manage.py runserver
```

## Run tests

Install test dependencies
```bash
$ pip install -r test_requirements.txt
```

Make sure your .env file is set to use a privileged database user to run tests
```bash
$ python3 src/manage.py test
```

## Code linter and formatter

[ruff](https://github.com/astral-sh/ruff) is used for code linting and formatting in this project. It is installed together with the [test dependencies](#run-tests).

### Lint code

```bash
$ ruff format --check --diff src
$ ruff check src
```

### format code

```bash
$ ruff format src
```


