import scrapy
import json
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
import time

class HuntrSpider(scrapy.Spider):
    name = "huntr"
    download_delay = 3
    dic={}

    def __init__(self):
        self.driver = webdriver.Firefox()

    def start_requests(self):
        # url = "https://huntr.com/bounties/hacktivity/"
        # self.driver.get(url)
        # time.sleep(5)
        # '''
        # <input id="filter-language" autocomplete="off" type="text" name="filter" placeholder="Filter by language" value="" class="bg-space mr-4 text-white border-0 placeholder-white placeholder-opacity-20 rounded w-full">'''
        # inputElement = self.driver.find_element_by_id("filter-language")
        # inputElement.send_keys('Python')
        # inputElement.send_keys(Keys.ENTER)
        # time.sleep(5)
        # cookie_accept_button = self.driver.find_element_by_xpath("/html/body/main/main/div[2]/div[2]/span/button")
        # cookie_accept_button.click()
        # '''
        # <button id="show-more-button" class="cursor-pointer mt-2 w-full h-10 bg-opacity-10 bg-white rounded-lg hover:bg-opacity-5"><p class="font-medium">Show more...</p></button>
        # '''
        # button = self.driver.find_element_by_id("show-more-button")
        # for i in range(100):
        #     try:
        #         button.click()
        #     except Exception as e:
        #         break
        #     time.sleep(5)
        #     '''
        #     <a href="/bounties/76737b3f-64f7-4212-a2e2-50bde28c1af0/" class="hover:text-blue-400" id="report-link">
        #               stored xss via malicious file name
        #             </a>
        #     '''
        # eles = self.driver.find_elements_by_id('report-link')
        # links = [ele.get_attribute('href') for ele in eles]
        # for link in links:
        #
        #     url = link
        #     if url:
        #         self.parse(url)
        with open("huntr_reports", "r") as f:
            dic = json.load(f)
        cwe_dic = {}
        for r, v in dic.items():
            cwe = v["cwe"]
            score_str = v["severity_score"]
            # print(score_str)
            ind1 = score_str.find("(")
            ind2 = score_str.find(")")
            # print(ind)
            score = score_str[ind1 + 1:ind2]
            if len(score) > 4:
                continue
            score = float(score)
            # print(score)
            if cwe not in cwe_dic:
                cwe_dic[cwe] = []
            cwe_dic[cwe].append(r)

        count = 0
        for k, v in sorted(cwe_dic.items(), key=lambda x: len(x[1]), reverse=True):
            count+=1
            # if count>10:
            #     break
            for link in v:

                url = link
                if url:
                    self.parse(url)
        # link = self.driver.find_element_by_xpath('//a[@id="dlink"]').get_attribute('href')
        # print(link)
        # self.dic[apk][v] = link
        # for apk in apk_dic:
        #     versions = apk_dic[apk]
        #     for v in versions:
        #         link = apk_dic[apk][v]
        #         url = 'https://www.apkmonk.com'+link
        #         yield scrapy.Request(url=url, meta={'app':apk,'version':v},callback=self.parse, headers={
        #             'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:66.0) Gecko/20100101 Firefox/66.0'})

    def parse(self, url):

        print(url)
        try:
            self.driver.get(url)
        except Exception as e:
            return
        # time.sleep(2)
        self.driver.implicitly_wait(10)
        '''
        <a data-v-688c6286="" href="https://nvd.nist.gov/vuln/detail/CVE-2024-0521" target="_blank" class="text-white text-opacity-50 hover:text-opacity-100 hover:text-blue-400 inline-block">CVE-2024-0521</a>
        '''

        try:
            description = self.driver.find_element_by_css_selector('div.markdown-body').text
            print(description)
        except Exception as e:
            description = ""
        try:
            cve = self.driver.find_element_by_css_selector('a.text-opacity-50.inline-block').text
            cve_link = self.driver.find_element_by_css_selector('a.text-opacity-50.inline-block').get_attribute('href')
        except Exception as e:
            cve = ""
            cve_link = ""
        '''
        <a data-v-688c6286="" href="https://cwe.mitre.org/data/definitions/94.html" class="text-white text-opacity-50 hover:text-opacity-100 hover:text-blue-400 mt-1">
                  CWE-94:
                   Code Injection
                </a>
        '''
        try:
            cwe = self.driver.find_element_by_css_selector('a.text-opacity-50.mt-1').text
            cwe_link = self.driver.find_element_by_css_selector('a.text-opacity-50.mt-1').get_attribute('href')
            severity_score = self.driver.find_element_by_css_selector('div.text-opacity-50.pt-0\.5').text
            repo_link = self.driver.find_element_by_css_selector('#title > a:nth-child(1)').get_attribute('href')

            fix_commit = self.driver.find_element_by_xpath(
                "//span[contains(text(), 'with commit')]/following-sibling::a[1]").get_attribute('href')
        except Exception as e:
            cwe = "Unknown"
            cwe_link = "None"
            print("error")
            print(url)
            return
        print(fix_commit)
        # self.driver.get(response.request.url)
        # time.sleep(5)
        # link = self.driver.find_element_by_xpath('//a[@id="dlink"]').get_attribute('href')
        print(cve)
        print(cve_link)
        print(cwe)
        print(cwe_link)
        print(severity_score)
        print(repo_link)
        self.dic[url]={
            "cve":cve,
            "cve_link":cve_link,
            "cwe":cwe,
            "cwe_link":cwe_link,
            "severity_score":severity_score,
            "repo_link":repo_link,
            "fix_commit":fix_commit,
            "description":description
        }
        with open("huntr_reports_with_src_latest", 'w') as f:
            json.dump(self.dic, f)



    def closed(self,reason):
        self.driver.close()
        with open("huntr_reports_with_src_latest", 'w') as f:
            json.dump(self.dic, f)

