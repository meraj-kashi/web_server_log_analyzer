from analysis_request import AnalysisRequest, AnalysisConfig
import yaml


class RequestParser:

    def __init__(self, request):
        self.request = request

    def parse(self):
        content = self.request.files.get('config')
        if content is not None:
            file_path = "uploads/uploaded_config.yml"
            content.save(file_path)

            config_file = file_path

        else:
            config_file = "default_config.yml"

        with open(config_file) as f:
            config = yaml.safe_load(f)
            if config is not None:
                analysis_config = self.__parse_request_config(config)
            else:
                raise Exception("Config not found. Please upload a config file or contact system admin.")

        data = self.request.values
        analysis_request = self.__parse_request_data(data)
        return analysis_config, analysis_request

    def __parse_request_data(self, data):
        content = self.request.files.get('content')
        start_time = self.__preprocess_and_retrieve_value(data, 'start_time')
        end_time = self.__preprocess_and_retrieve_value(data, 'end_time')
        status_code = self.__preprocess_and_retrieve_value(data, 'status_code')
        source_ip = self.__preprocess_and_retrieve_value(data, 'source_ip')
        os = self.__preprocess_and_retrieve_value(data, 'os')
        browser = self.__preprocess_and_retrieve_value(data, 'browser')
        user_regex_syntax = self.__preprocess_and_retrieve_value(data, 'user_regex_syntax')

        return AnalysisRequest(content, start_time, end_time, status_code, source_ip, os, browser, user_regex_syntax)

    @staticmethod
    def __preprocess_and_retrieve_value(data, value_key):
        value = data.get(value_key)
        if value:
            value = value.strip()

        return value

    def __parse_request_config(self, config):
        ip = config.get('ip')
        log_time = config.get('log_time')
        date_time_format = config.get('date_time_format')
        status_code = config.get('status_code')
        os = config.get('os')
        browser = config.get('browser')

        date_time_format = date_time_format.replace("\\%", "%")

        return AnalysisConfig(ip, log_time, date_time_format, status_code, os, browser)
