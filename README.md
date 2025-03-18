# OSS-Security-Inspector
Open Source Software (OSS) Security Inspector Tool 

# Installation

Clone the repo and run the following commands.
```bash
git clone https://github.com/rajsoni03/OSS-Security-Inspector.git
cd OSS-Security-Inspector
```

Install Python packages.
```python
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt 
```

Install Linux packages.
```bash
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | /bin/sh -s
```

Verify the installation
```bash
./bin/grype --version
```

Update the vulnerability database of the grype db
```bash
./bin/grype db update
```


# Usage

Start the flask server
```bash
flask run
```

Open web browser and go to http://localhost:5000
