from urllib.parse import urlparse
from bs4 import BeautifulSoup
import whois
import urllib
import urllib.request
from datetime import datetime
import requests
import re
import regex
from tldextract import extract
import ssl
import socket


def getDomain(url):
    domain = urlparse(url).netloc
    return domain

def readFile(fileName):
    src_data2 = open(fileName).read().strip().split('\n')
    return src_data2
class Features:
    def __init__(self,URL):
        self.URL = URL

    def getDomain(self):
        domain = urlparse(self.URL).netloc
        return domain

    def getFeatures(self):
        havingIP = self.get_havingIP_Feature()
        lenURL = self.get_URL_length_Feature()
        shortining_service = self.get_Shortining_Service_Feature()
        prefix_suffix = self.get_Prefix_Suffix_Feature()
        having_subdomain = self.get_having_subdomain_Feature()
        SSLfinal_State=self.get_SSLfinal_State_Feature()
        having_at_symbol = self.get_having_at_symbol_Feature()
        double_slash=self.get_double_slash_redirecting_Feature()
        https_token=self.get_HTTPS_token_Feature()
        favicon=self.get_Favicon_Feature()
        port=self.get_port_Feature()
        DNSRecord=self.get_DNSRecord_Feature()
        Iframe=self.get_Iframe_Feature()
        redirect=self.get_Redirect_Feature()
        on_mouseover=self.get_on_mouseover_Feature()
        rightClick=self.get_on_RightClick_Feature()
        age_of_domain=self.get_age_of_domain_Feature()
        registeration_length=self.get_Domain_registeration_length_Feature()
        web_traffic=0
        try:
            web_traffic=self.get_web_traffic_Feature()
        except:
            web_traffic=0
        request_URL=self.get_Request_URL_Feature()
        url_of_Anchor=self.get_URL_of_Anchor_Feature()
        links_in_tags=self.get_Links_in_tags_Feature()
        abnormal_URL_Featur = self.get_Abnormal_URL_Feature()
        Submitting_to_email=self.get_Submitting_to_email_Feature()
        statistical_report=self.get_Statistical_report_Feature()
        return [havingIP,lenURL,shortining_service,having_at_symbol,double_slash,prefix_suffix,having_subdomain,SSLfinal_State,registeration_length,favicon,port,https_token
                ,request_URL,url_of_Anchor,links_in_tags,Submitting_to_email,abnormal_URL_Featur,redirect,on_mouseover,rightClick,Iframe,age_of_domain,DNSRecord,web_traffic,
                statistical_report]

    def get_havingIP_Feature(self):
        domain = self.getDomain()
        data = domain.split('.')
        n = len(data)
        for i in range(0,n):
            if not data[i].isnumeric():
                return 1
        return -1
    def get_Shortining_Service_Feature(self):
        domain = self.getDomain()
        tinyURL_List = readFile('TinyURL.txt')
        if domain in tinyURL_List:
            return -1
        else:
            return +1
    def get_double_slash_redirecting_Feature(self):
        str1='//'
        position = self.URL.rfind(str1)
        if position > 7:
            return -1
        else:
            return +1
    def get_URL_length_Feature(self):
        if len(self.URL) < 54:
            return 1
        elif len(self.URL) >= 54 and len(self.URL) <= 75:
            return 0
        elif len(self.URL) > 75:
            return -1
    def get_Prefix_Suffix_Feature(self):
        domain = self.getDomain()
        number_of_dash = domain.count('-')
        if number_of_dash == 0: # if not '-' in domain
            return 1
        else:
            return -1
    def get_having_at_symbol_Feature(self):
        number_of_at_symbol=self.URL.count('@')
        if number_of_at_symbol==0: # if not '@' in self.URL:
            return 1
        else:
            return -1

    def get_SSLfinal_State_Feature(self):
        try:
            # check wheather contains https
            if (regex.search('^https', self.URL)):
                usehttps = 1
            else:
                usehttps = 0
            # getting the certificate issuer to later compare with trusted issuer
            # getting host name
            subDomain, domain, suffix = extract(self.URL)
            host_name = domain + "." + suffix
            context = ssl.create_default_context()
            sct = context.wrap_socket(socket.socket(), server_hostname=host_name)
            sct.connect((host_name, 443))
            certificate = sct.getpeercert()
            issuer = dict(x[0] for x in certificate['issuer'])
            certificate_Auth = str(issuer['commonName'])
            certificate_Auth = certificate_Auth.split()
            if (certificate_Auth[0] == "Network" or certificate_Auth[0] == "Deutsche"):
                certificate_Auth = certificate_Auth[0] + " " + certificate_Auth[1]
            else:
                certificate_Auth = certificate_Auth[0]
            trusted_Auth = ['Comodo', 'Symantec', 'GoDaddy', 'GlobalSign', 'DigiCert', 'StartCom', 'Entrust', 'Verizon',
                            'Trustwave', 'Unizeto', 'Buypass', 'QuoVadis', 'Deutsche Telekom', 'Network Solutions',
                            'SwissSign', 'IdenTrust', 'Secom', 'TWCA', 'GeoTrust', 'Thawte', 'Doster', 'VeriSign']
            # getting age of certificate
            startingDate = str(certificate['notBefore'])
            endingDate = str(certificate['notAfter'])
            startingYear = int(startingDate.split()[3])
            endingYear = int(endingDate.split()[3])
            Age_of_certificate = endingYear - startingYear

            # checking final conditions
            if ((usehttps == 1) and (certificate_Auth in trusted_Auth) and (Age_of_certificate >= 1)):
                return 1  # legitimate
            elif ((usehttps == 1) and (certificate_Auth not in trusted_Auth)):
                return 0  # suspicious
            else:
                return -1  # phishing
        except Exception as e:

            return -1

    def get_having_subdomain_Feature(self):
        domain = self.getDomain()
        domain = domain.replace("www.", "")
        number_of_dot= domain.count('.')
        if number_of_dot == 1:
            return 1
        elif number_of_dot == 2:
            return 0
        else:
            return -1

    def get_HTTPS_token_Feature(self):
        domain = self.getDomain()
        if 'http' in domain:
            return -1
        else:
            return 1

    def get_DNSRecord_Feature(self):
        domain = self.getDomain()
        try:
            domain_data = whois.whois(domain)
            return 1
        except:
            return -1

    def get_Redirect_Feature(self):
        try:
            response = requests.get(self.URL)
        except:
            response = ""
        if response == "":
            return 0
        else:
            #print(response.history)
            if len(response.history) <= 2:
                return 1
            else:
                return -1

    def get_on_mouseover_Feature(self):
        try:
            response = requests.get(self.URL)
        except:
            response = ""
        if response == "":
            return 0
        else:
            if re.findall("<script>.+onmouseover.+</script>", response.text):
                return -1
            else:
                return 1

    def get_on_RightClick_Feature(self):
        try:
            response = requests.get(self.URL)
        except:
            response = ""
        if response == "":
            return 0
        else:
            if re.findall(r"event.button ?== ?2", response.text):
                return -1
            else:
                return 1

    def get_Iframe_Feature(self):
        try:
            response = requests.get(self.URL)
        except:
            response = ""
        if response == "":
            return 0
        else:
            if response.text.find("<iframe>")==-1:# and response.text.find("<frameBorder>")==-1:
                return 1
            else:
                return -1

    def get_age_of_domain_Feature(self):
        domain = self.getDomain()
        try:
            domain_data=whois.whois(domain)
            creation_date = domain_data.creation_date
            current_date = datetime.now()
            age_by_days = (current_date - creation_date[0]).days
            if age_by_days >= 6*30:
                return 1
            else:
                return -1
        except:
            return 0

    def get_Favicon_Feature(self):
        try:
            page = requests.get(self.URL)
            soup = BeautifulSoup(page.text, features="lxml")
            icon_link = soup.find("link", rel="shortcut icon")
            if icon_link is None:
                icon_link2 = soup.find("link", rel="icon")
                if icon_link2 is None:
                    return -1
                else:
                    return +1
            else:
                return +1
        except:
            return 0

    def get_Domain_registeration_length_Feature(self):
        domain = self.getDomain()
        try:
            domain_data = whois.whois(domain)
            current_date = datetime.now()
            expiration_date = domain_data.expiration_date
            registeration_length = (expiration_date[0] - current_date).days
            if registeration_length <= 365:
                return -1
            else:
                return 1
        except:
            return 0

    def get_web_traffic_Feature(self):
        try:
            # Filling the whitespaces in the URL if any
            url = urllib.parse.quote(self.URL)
            rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(),
                                 "xml").find(
                "REACH")['RANK']
            rank = int(rank)
        except TypeError:
            return 0
        if rank < 100000:
            return 1
        elif rank >100000:
            return 0
        else:
            return -1

    def get_Submitting_to_email_Feature(self):
        try:
            opener = urllib.request.urlopen(self.URL).read()
            soup = BeautifulSoup(opener, 'lxml')
            if (soup.find('mailto:')):
                return -1
            else:
                return 1
        except:
            return 0

    def get_Links_in_tags_Feature(self):
        try:
            opener = urllib.request.urlopen(self.URL).read()
            soup = BeautifulSoup(opener, 'lxml')

            no_of_meta = 0
            no_of_link = 0
            no_of_script = 0
            anchors = 0
            avg = 0
            for meta in soup.find_all('meta'):
                no_of_meta = no_of_meta + 1
            for link in soup.find_all('link'):
                no_of_link = no_of_link + 1
            for script in soup.find_all('script'):
                no_of_script = no_of_script + 1
            for anchor in soup.find_all('a'):
                anchors = anchors + 1
            total = no_of_meta + no_of_link + no_of_script + anchors
            tags = no_of_meta + no_of_link + no_of_script
            if (total != 0):
                avg = tags / total

            if (avg < 0.25):
                return 1
            elif (0.25 <= avg <= 0.81):
                return 0
            else:
                return -1
        except:
            return 0
    def get_URL_of_Anchor_Feature(self):
        try:
            subDomain, domain, suffix = extract(self.URL)
            websiteDomain = domain

            opener = urllib.request.urlopen(self.URL).read()
            soup = BeautifulSoup(opener, 'lxml')
            anchors = soup.findAll('a', href=True)
            total = len(anchors)
            linked_to_same = 0
            avg = 0
            for anchor in anchors:
                subDomain, domain, suffix = extract(anchor['href'])
                anchorDomain = domain
                if (websiteDomain == anchorDomain or anchorDomain == ''):
                    linked_to_same = linked_to_same + 1
            linked_outside = total - linked_to_same
            if (total != 0):
                avg = linked_outside / total

            if (avg < 0.31):
                return 1
            elif (0.31 <= avg <= 0.67):
                return 0
            else:
                return -1
        except:
            return 0

    def get_Request_URL_Feature(self):
        try:
            subDomain, domain, suffix = extract(self.URL)
            websiteDomain = domain

            opener = urllib.request.urlopen(self.URL).read()
            soup = BeautifulSoup(opener, 'lxml')
            imgs = soup.findAll('img', src=True)
            total = len(imgs)

            linked_to_same = 0
            avg = 0
            for image in imgs:
                subDomain, domain, suffix = extract(image['src'])
                imageDomain = domain
                if (websiteDomain == imageDomain or imageDomain == ''):
                    linked_to_same = linked_to_same + 1
            vids = soup.findAll('video', src=True)
            total = total + len(vids)

            for video in vids:
                subDomain, domain, suffix = extract(video['src'])
                vidDomain = domain
                if (websiteDomain == vidDomain or vidDomain == ''):
                    linked_to_same = linked_to_same + 1
            linked_outside = total - linked_to_same
            if (total != 0):
                avg = linked_outside / total

            if (avg < 0.22):
                return 1
            elif (0.22 <= avg <= 0.61):
                return 0
            else:
                return -1
        except:
            return 0

    def get_Google_Index_Feature(self):
        """
        user_agent = 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.116 Safari/537.36'
        headers = { 'User-Agent' : user_agent}
        query = {'q': 'info:' + url}
        google = "https://www.google.com/search?" + urlencode(query)
        #data = requests.get(google, headers=headers,proxies=proxies)
        data = requests.get(google,headers=headers)
        data.encoding = 'ISO-8859-1'
        soup = BeautifulSoup(str(data.content), "html.parser")
        try:
            check = soup.find(id="rso").find("div").find("div").find("h3").find("a")
            if soup.find(id="rso").find("div").find("div").find("h3").find("a").find("href" != None):
                href = check['href']
                return 0 # indexed
            else:
                return 1
        except AttributeError:
            return 1 # indexed
        """
        return 0
    def get_port_Feature(self):
        domain = self.getDomain()
        if ':' in domain:
            port=domain.split(':')[1]
            if port.isnumeric():
                return -1
            else:
                return 0
        else:
            return 1

    def get_SFH_Feature(self):

        return 0

    def get_Abnormal_URL_Feature(self):
        domain_name = self.getDomain()
        try:
            domain_data = whois.whois(domain_name)
            hostname = domain_data.domain_name
            if hostname in self.URL:
                return 1  # legitimate
            else:
                return -1  # phishing
        except:
            return -1  # phishing or 0

    def get_popUpWidnow_Feature(self):

        return 0
    def get_Page_Rank_Feature(self):

        return 0
    def get_Links_pointing_to_page_Feature(self):

        return 0
    def get_Statistical_report_Feature(self):
        hostname = self.getDomain()
        url_match = re.search(
            'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly',
            hostname)
        try:
            ip_address = socket.gethostbyname(hostname)
            ip_match = re.search(
                '146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42',
                ip_address)
        except:
            return -1

        if url_match or ip_match:
            return -1
        else:
            return 1