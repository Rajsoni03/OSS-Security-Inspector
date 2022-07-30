import os
import re

def scan_py(path):
	stream = os.popen(f'bandit -r {path}')
	output = stream.read()
	if output.find('>>') == -1:
		data = {
			'length'       : 0,
			'bySeverity'   : {'Undefined':0, 'Low':0, 'Medium':0, 'High':0 },
			'byConfidence' : {'Undefined':0, 'Low':0, 'Medium':0, 'High':0 },
			'issueList'    : []
		}
		return data

	report = output[output.find('>>'):].split('--------------------------------------------------')[-1]

	bySeverity =   {'Undefined':0, 'Low':0, 'Medium':0, 'High':0 }
	byConfidence = {'Undefined':0, 'Low':0, 'Medium':0, 'High':0 }

	report_severity = report[report.find('(by severity)'):report.find('(by confidence)')]
	report_confidence = report[report.find('(by confidence)'):]

	length = 0
	for i in bySeverity.keys():
	    bySeverity[i] = int(re.search(f"{i}.*", report_severity)[0].split('.')[-2].split(' ')[-1])
	    byConfidence[i] = int(re.search(f"{i}.*", report_confidence)[0].split('.')[-2].split(' ')[-1])
	    length += bySeverity[i]
	    
	issueList = []
	for i in output.split('--------------------------------------------------')[:-1]:
	    issue = {}
	    issue['Issue'] = re.search("Issue.*", i)[0][re.search("Issue.*", i)[0].find(']')+1:]
	    issue['Severity'] = re.search("Severity.*", i)[0].split(' ')[1]
	    issue['Confidence'] = re.search("Severity.*", i)[0].split(' ')[-1]
	    issue['Link'] = re.search("More Info:.*", i)[0][10:]
	    issue['Location'] = re.search("Location.*", i)[0][10:]
	    issue['Code'] = i[re.search("More Info.*", i).span()[1]+1:-1]
	    issueList.append(issue)

	data = {
		'length'       : length,
		'bySeverity'   : bySeverity,
		'byConfidence' : byConfidence,
		'issueList'    : issueList
	}
	return data

def scan_dependency(path):
	soft = "/home/jetson/Desktop/FlipKart/OSS-Security-Inspector/grype"
	stream = os.popen(f'{soft} {path}')
	output = stream.read()

	dependencyList = []
	length = 0

	for i in output.split('\n')[1:-1]:
	    string = [j for j in i.split(' ') if j!='']
	    dependency = {}
	    dependency['Name'] = string[0]
	    dependency['Installled'] = string[1]
	    if (string[2][0] in '0123456789'):
	    	dependency['Fixed-In'] = string[2]
	    	dependency['Type'] = string[3]
	    	dependency['Vulnerability'] = string[4]
	    	dependency['Severity'] = string[5]
	    else:
	    	dependency['Fixed-In'] = ''
	    	dependency['Type'] = string[2]
	    	dependency['Vulnerability'] = string[3]
	    	dependency['Severity'] = string[4]

	    dependencyList.append(dependency)
	    length+=1

	data = {
		'dependencyList' : dependencyList,
		'length' : length
	}
	return data


def download_pypi(name):
	path = os.path.join(os.path.join(os.getcwd(), './pyrepo'))
	stream = os.popen(f'pip install {name} --no-deps --target="{path}"')
	output = stream.read()
	msg = output.split('\n')[-2].split(' ')[0]
	if msg == 'Successfully':
	    return True
	return False

    	