import os
import re
import bandit

def scan_repo(path):
	stream = os.popen(f'bandit -r {path}')
	output = stream.read()
	report = output[output.find('>>'):].split('--------------------------------------------------')[-1]
	
	bySeverity =   {'Undefined':0, 'Low':0, 'Medium':0, 'High':0 }
	byConfidence = {'Undefined':0, 'Low':0, 'Medium':0, 'High':0 }

	report_severity = report[report.find('(by severity)'):report.find('(by confidence)')]
	report_confidence = report[report.find('(by confidence)'):]

	length = 0
	for i in bySeverity.keys():
	    bySeverity[i] = int(re.search(f"{i}.*", report_severity)[0].split(' ')[1])
	    byConfidence[i] = int(re.search(f"{i}.*", report_confidence)[0].split(' ')[1])
	    length += bySeverity[i]
	    
	issueList = []
	for i in output.split('--------------------------------------------------')[:-1]:
	    issue = {}
	    issue['Issue'] = re.search("Issue.*", i)[0][re.search("Issue.*", i)[0].find(']')+1:]
	    issue['Severity'] = re.search("Severity.*", i)[0].split(' ')[1]
	    issue['Confidence'] = re.search("Severity.*", i)[0].split(' ')[-1]
	    issue['CWE'] = re.search("CWE.*", i)[0][5:]
	    issue['Link'] = re.search("CWE.*", i)[0][re.search("CWE.*", i)[0].find('(')+1:-1]
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
