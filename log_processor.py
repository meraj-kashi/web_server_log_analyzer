import csv
import re

from datetime import datetime
from dateutil.tz import tz

from analysis_request import AnalysisRequest, AnalysisConfig


class LogProcessor:

    def __init__(self):
        self.columns = ['index', 'datetime', 'ip_address', 'identity', 'user_id', 'request_type', 'url', 'protocol',
                        'status_code', 'content_length', 'requester', 'device']

    @staticmethod
    def __preprocess_data(value):
        if value:
            if isinstance(value, str):
                value = value.strip()

        return value

    def process(self, csv_file, analysis_config: AnalysisConfig, analysis_request: AnalysisRequest):
        """
        process the input data, generate the output csv and save the result file.
        :param csv_file: input log csv
        :param analysis_request: Analysis Request
        :return: file name and file path
        """
        log_line_list = []
        start_time_o = self.get_utc_datetime(analysis_request.start_time, analysis_config.log_time,
                                             analysis_config.date_time_format)
        end_time_o = self.get_utc_datetime(analysis_request.end_time, analysis_config.log_time,
                                           analysis_config.date_time_format)

        with open(csv_file) as reader:
            line = reader.readline()

            while line != '':
                time_in_utc = self.get_utc_datetime(line, analysis_config.log_time, analysis_config.date_time_format)
                if time_in_utc is not None:
                    if start_time_o <= time_in_utc <= end_time_o:
                        log_line_list.append(line)

                line = reader.readline()

        date_time_str = str(datetime.now()).replace("-", "_").replace(" ", "_").replace(":", "_").replace(".", "_")
        file_path = "uploads/{}_result.csv".format(date_time_str)
        with open(file_path, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(self.columns)
            index = 0
            for line in log_line_list:
                data = self.get_data_dictionary_for_line(line)
                ip_address = self.get_ip_address(line, analysis_config.ip)
                datetime_value = self.get_utc_datetime(line, analysis_config.log_time, analysis_config.date_time_format)
                os = self.get_defined_regex(line, analysis_config.os)
                browser = self.get_defined_regex(line, analysis_config.browser)
                status_code = self.get_defined_regex(line, analysis_config.status_code)

                data['datetime'] = self.__preprocess_data(datetime_value)
                data['status_code'] = self.__preprocess_data(status_code)
                data['ip_address'] = self.__preprocess_data(ip_address)
                data['os'] = self.__preprocess_data(os)
                data['browser'] = self.__preprocess_data(browser)

                source_ip_available = analysis_request.source_ip is not None and analysis_request.source_ip != ""
                source_ip_is_valid = data.get('ip_address') == analysis_request.source_ip
                source_ip_is_valid = (source_ip_available and source_ip_is_valid) or not source_ip_available

                os_available = analysis_request.os is not None and analysis_request.os != ""
                os_is_valid = data.get('os') is not None
                os_is_valid = (os_available and os_is_valid) or not os_available

                browser_available = analysis_request.browser is not None and analysis_request.browser != ""
                browser_is_valid = data.get('browser') is not None
                browser_is_valid = (browser_available and browser_is_valid) or not browser_available

                status_code_available = analysis_request.status_code is not None and analysis_request.status_code != ""
                status_code_is_valid = data.get('status_code') == str(analysis_request.status_code)
                status_code_is_valid = (status_code_available and status_code_is_valid) or not status_code_available

                user_regex_syntax = analysis_request.user_regex_syntax
                user_regex_syntax_available = user_regex_syntax is not None and user_regex_syntax != ""
                user_regex_syntax_valid = self.regex_availability(data.get('url'), user_regex_syntax) or \
                                          self.regex_availability(data.get('device'), user_regex_syntax) or \
                                          self.regex_availability(data.get('requester'), user_regex_syntax)

                user_regex_syntax_valid = (user_regex_syntax_available and user_regex_syntax_valid) \
                                          or not user_regex_syntax_available

                if source_ip_is_valid and os_is_valid and browser_is_valid and status_code_is_valid \
                        and user_regex_syntax_valid:
                    index += 1
                    row = self.get_data_row_from_dict(index, data)
                    writer.writerow(row)

        return_file_name = "{}_result.csv".format(date_time_str)
        return return_file_name, file_path

    def get_utc_datetime(self, line, regex, date_time_format):
        """
        From the given string retrieve the utc time
        :param line: string containing the time
        :return: utc datetime or None if no time found
        """
        date_time_regex = r"{}".format(regex)
        search_obj = re.search(date_time_regex, line, re.M | re.I)
        time_in_utc = line
        if search_obj:
            time_string = search_obj.group()
            utc_zone = tz.tzutc()
            dt_object = datetime.strptime(time_string, date_time_format)
            time_in_utc = dt_object.astimezone(tz=utc_zone)
        else:
            pass

        return time_in_utc

    def regex_availability(self, data_string, user_string):
        """
        Check the regex availability in the given data string
        :param data_string: data or log line
        :param user_string: user regex
        :return:
        """
        is_available = False
        regex_valid = self.check_regex_validity(user_string)
        if regex_valid:
            rex = re.compile(user_string)
            search_obj = rex.search(data_string)
            if search_obj:
                is_available = True
            else:
                is_available = False
        else:
            pass

        return is_available

    def get_ip_address(self, line, regex):
        """
        Retrieve IP address from the log line
        :param line: log line
        :return: ip address
        """
        ip_address_regex = r"{}".format(regex)
        search_obj = re.search(ip_address_regex, line, re.M | re.I)
        ip_address = None
        if search_obj:
            ip_address = search_obj.group()
        else:
            pass

        return ip_address

    def get_defined_regex(self, line, regex):
        """
        Retrieve defined regex data from the log line
        :param line: log line
        :return: data
        """
        if line is None:
            return None

        defined_regex = r"{}".format(regex)
        search_obj = re.search(defined_regex, line, re.M | re.I)
        data = None
        if search_obj:
            data = search_obj.group()
        else:
            pass

        return data

    def get_data_dictionary_for_line(self, line):
        """
        Get main data as a dictionary
        :param line: log line
        :return: data dictionary
        """
        sections = line.split(" ")
        data = dict()
        if len(sections) > 10:
            data['identity'] = sections[1]
            data['user_id'] = sections[2]
            data['request_type'] = sections[5].replace('"', '')
            data['url'] = sections[6]
            data['protocol'] = sections[7].replace('"', '')
            data['status_code'] = sections[8]
            data['content_length'] = sections[9]
            data['requester'] = sections[10].replace('"', '')
            data['device'] = " ".join(sections[11:]).replace('"', '').replace("\n", "")
        else:
            print(f"The log line can not be parsed. {line}")
        return data

    def check_regex_validity(self, regex_string):
        """
        Check regular expression availability
        :param regex_string:
        :return:
        """
        if regex_string is None or regex_string == "":
            is_valid = False
        else:
            try:
                re.compile(regex_string)
                is_valid = True
            except re.error:
                is_valid = False
        return is_valid

    def get_data_row_from_dict(self, index, data_dict: dict):
        """
        Get data as a row to write in the csv
        :param index: index of the row
        :param data_dict: data dictionary
        :return:
        """
        row = [index]
        for column in self.columns[1:]:
            row.append(data_dict.get(column))
        return row
