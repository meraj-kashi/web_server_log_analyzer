import io
import os
from datetime import datetime
import csv
from flask import Flask, request, make_response, render_template

from log_processor import LogProcessor
from request_parser import RequestParser
from search_form import SearchForm

application = Flask(__name__)
SECRET_KEY = os.urandom(32)
application.config['SECRET_KEY'] = SECRET_KEY


@application.route('/log_analysis', methods=['GET'])
def login():
    form = SearchForm()
    return render_template('log_analysis.html', title='Web Log Analyzer', form=form)


@application.route("/log_analysis", methods=['POST'])
def get_response():
    request_parser = RequestParser(request)
    analysis_config, analysis_request = request_parser.parse()

    content = request.files.get('content')
    file_name = content.filename
    date_time_str = str(datetime.now()).replace("-", "_").replace(" ", "_").replace(":", "_").replace(".", "_")
    file_path = "uploads/{}_{}".format(date_time_str, file_name)
    content.save(file_path)
    return_file_name , saved_file_path = log_processor.process(file_path, analysis_config, analysis_request)

    si = io.StringIO()
    cw = csv.writer(si)
    csv_rows = []
    i=0
    with open(saved_file_path, 'r', newline='') as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        for row in csv_reader:
            csv_rows.append(row)
            i+=1
    print(i)
    output='The result of your query :  '+str(i-1)+ ''' . The full report is downloaded automatically. 
    you can find the report in the project directory: '''+saved_file_path

    cw.writerows(csv_rows)
    response = make_response(si.getvalue())
    response.headers["Content-Disposition"] = f"attachment; filename={return_file_name}"
    response.headers["Content-type"] = "text/csv"
    
    return render_template('base.html',output=output)
    return response, 200
    



if __name__ == "__main__":
    log_processor = LogProcessor()
    application.run()
