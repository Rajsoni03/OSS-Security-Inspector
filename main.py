from flask import Flask, render_template, jsonify, request, make_response
import git
import os
import re
from scan import scan_repo
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
				params['report'] = scan_repo(path)
				# delete repo
				os.system(f"rm -rf {path}")
			params['status'] = True
		except:
			params['status'] = False	
	return jsonify(params)


@app.route('/upload', methods=['POST'])
def upload():
	params = {}
	return jsonify(params)