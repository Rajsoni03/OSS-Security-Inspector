from flask import Flask, render_template, jsonify, request, make_response, flash
import git
import os
import re
from werkzeug.utils import secure_filename
from scan import scan_dependency, download_pypi, scan_py
import glob
app = Flask(__name__) 

@app.route("/") 
def home_view():
	params = {'name':'Raj'}
	return render_template('index.html', params = params)

@app.route("/git-scan")
def git_scan():
	params = {'name':'Raj'}
	return render_template('git_scan.html', params = params)

@app.route('/git-scan-link', methods=['POST'])
def git_scan_link():
	params = {'status': False, 'report' : None}
	if (request.method == 'POST'):
		try:
			url = request.form.get('repolink')
			if (url != None) and (url.find("github.com") != -1):
				arr = url.split('/')
				username = arr[-2]
				reponame = arr[-1]
				url = f"https://github.com/{username}/{reponame}"
				git.Git('./repo').clone(url)

				path = os.path.join(os.path.join(os.getcwd(), 'repo'), reponame)
				# scan
				params['report'] = scan_py(path)
				
				# delete repo
				# os.system(f"rm -rf {path}")
			params['status'] = True
		except:
			params['status'] = False	
	return jsonify(params)

@app.route('/depend-scan', methods=['POST'])
def depend_scan():
	params = {'status': False, 'report' : None}
	if (request.method == 'POST'):
		try:
			url = request.form.get('repolink')
			if (url != None) and (url.find("github.com") != -1):
				arr = url.split('/')
				username = arr[-2]
				reponame = arr[-1]
				path = os.path.join(os.path.join(os.getcwd(), 'repo'), reponame)
				# scan
				params['depenency_report'] = scan_dependency(path)

				# delete repo
				os.system(f"rm -rf {path}")
				params['status'] = True
		except:
			params['status'] = False	
	return jsonify(params)

@app.route("/py-scan")
def py_scan():
	params = {'name':'Raj'}
	return render_template('py_scan.html', params = params)

@app.route('/py-scan-link', methods=['POST'])
def py_scan_link():
	params = {'status': False, 'report' : None}
	if (request.method == 'POST'):
		try:
			modulename = request.form.get('modulename')
			if modulename != None:
				if download_pypi(modulename):
					path = os.path.join(os.path.join(os.getcwd(), './pyrepo'))
					# scan
					params['report'] = scan_py(path)
					
					# delete pyrepo
					#os.system(f"rm -rf {path}")
					params['status'] = True
		except:
			params['status'] = False	
	return jsonify(params)

@app.route('/py_depend-scan', methods=['POST'])
def py_depend_scan():
	params = {'status': False, 'report' : None}
	if (request.method == 'POST'):
		try:
			modulename = request.form.get('modulename')
			if modulename != None:			
				path = os.path.join(os.path.join(os.getcwd(), './pyrepo'))
				filepath = glob.glob(f"{path}/*/METADATA")[0]
				
				# read dependency from metadata 
				f = open(filepath, 'r')
				meta = f.read()
				f.close()
				requires = re.findall("Requires-Dist.*", meta)
				
				# check dependency version 
				dependency_list = ''
				for i in requires:
				    row = i.split(' ') 
				    depd = row[1]
				    try:
				        depd += row[2][1:-1] + '\n'
				    except:
				        depd += '\n'
				    dependency_list+=depd

				# copy dependency to create requirements file
				f = open(f'{path}/requirements.txt', 'w')
				f.write(dependency_list)
				f.close()

				# scan
				params['depenency_report'] = scan_dependency(path)

				# delete repo
				os.system(f"rm -rf {path}")
				params['status'] = True
		except:
			params['status'] = False	
	return jsonify(params)


@app.route("/file-scan")
def file_scan():
	params = {'name': 'Raj'}
	return render_template('file_scan.html', params = params)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'zip', 'xz', '7z'}

@app.route("/file-scan-link", methods=['POST'])
def file_scan_link():
	params = {'status': False, 'report' : None}
	if 'formFile' not in request.files:
		return jsonify(params)    
	file = request.files['formFile']
	path = os.path.join(os.path.join(os.getcwd(), 'tempfiles'))

	if file.filename != '' and file and allowed_file(file.filename):
		os.system(f'mkdir {path}')
		filename = secure_filename(file.filename)
		filepath = os.path.join(path, filename)
		file.save(filepath)
		
		filextn = filename.rsplit('.', 1)[1].lower()
		if filextn == 'zip':
			os.system(f'unzip {filepath} -d {path}')
		elif filextn == 'xz':
			os.system(f'tar -xf {filepath} -C {path}')
		elif filextn == '7z':
			os.system(f'7z x {filepath} -o{path}')	
		os.system(f"rm -rf {filepath}")

		# scan
		params['report'] = scan_py(path)

		# os.system(f"rm -rf {path}")			
		params['status'] = True
	else:
		params['status'] = False
	return jsonify(params)


@app.route("/file-depend-scan", methods=['POST'])
def file_depend_scan():
	params = {'status': False, 'depenency_report' : None}
	if 'formFile' not in request.files:
		return jsonify(params)    
	file = request.files['formFile']
	path = os.path.join(os.path.join(os.getcwd(), 'tempfiles'))

	if file.filename != '' and file:
		os.system(f'mkdir {path}')
		filename = secure_filename(file.filename)
		filepath = os.path.join(path, filename)

		# scan
		params['depenency_report'] = scan_dependency(path)

		os.system(f"rm -rf {path}")			
		params['status'] = True
	else:
		params['status'] = False
	return jsonify(params)