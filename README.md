# Jira Automation for Insights

## Instalation

(Optional virtual env):
```
python3 -m venv venv
. venv/bin/activate
```

```
pip3 install -r requirements.txt
```

## Configuration

Set `QUAY_IO_SESSION` environment variable to a value grabbed form the session cookie after logging in into [Quay.io](https://quay.io).  Note that it the session has a timeout.

Jira username can be set as a CLI argument, and the password is is prompted.

## Usage

### Reporting Quay vulerabilities to Jira

```
python3 quay2jira.py [-h] [-u JIRA_USERNAME] IMAGE_NAME JIRA_PROJECT
```

Example:

```
python3 quay2jira.py compliance-backend RHICOMPL
```
