class AnalysisRequest:

    def __init__(self, content, start_time, end_time, status_code, source_ip, os, browser, user_regex_syntax):
        self.content = content
        self.start_time = start_time
        self.end_time = end_time
        self.status_code = status_code
        self.source_ip = source_ip
        self.os = os
        self.browser = browser
        self.user_regex_syntax = user_regex_syntax


class AnalysisConfig:

    def __init__(self, ip, log_time, date_time_format, status_code, os, browser):
        self.ip = ip
        self.log_time = log_time
        self.date_time_format = date_time_format
        self.status_code = status_code
        self.os = os
        self.browser = browser
