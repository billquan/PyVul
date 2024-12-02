import scrapy
import json
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
import time
import csv

class SnykSpider(scrapy.Spider):
    name = "snyk_src"
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
        with open("synk_930.csv", "r") as f:
            dic = csv.reader(f)
            dic = [row for row in dic][1:]

        cwe_dic = {}
        for r in dic:
            cwe = r[0]
            id = r[2]
            if cwe not in cwe_dic:
                cwe_dic[cwe] = []
            cwe_dic[cwe].append(id)

        print(len(cwe_dic))

        count = 0
        for k, v in sorted(cwe_dic.items(), key=lambda x: len(x[1]), reverse=True):
            count+=1
            if count == 1:
                print(k)
                continue
            # print(v)
            for link in v:
                url = link
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
        self.driver.get(url)
        # time.sleep(2)
        self.driver.implicitly_wait(10)
        refs = []
        '''
        <a data-v-688c6286="" href="https://nvd.nist.gov/vuln/detail/CVE-2024-0521" target="_blank" class="text-white text-opacity-50 hover:text-opacity-100 hover:text-blue-400 inline-block">CVE-2024-0521</a>
        '''
        try:
            description = self.driver.find_element_by_xpath(
                "//h2[contains(text(), 'Overview')]/following-sibling::*").text
            print(description)
        except Exception as e:
            description = ""
        cwe = self.driver.find_element_by_xpath(
            "//a[contains(text(), 'CWE')]").text.split("\n")[0]
        print(cwe)
        try:
            cve = self.driver.find_element_by_xpath(
                "//a[contains(text(), 'CVE')]").text.split("\n")[0]
            print(cve)
        except Exception as e:
            print(Exception)
            cve = ""
        try:
            fix_commits = self.driver.find_elements_by_xpath(
                "//a[contains(text(), 'GitHub Commit')]")
            print(fix_commits)
            if len(fix_commits)>0:
                print(">0")
                for ele in fix_commits:
                    ref = ele.get_attribute('href')
                    # print(ref)
                    refs.append(ref)
            if len(refs)>0:
                self.dic[url] = {"refs":refs,"cve":cve, "cwe":cwe,"description":description}

        except Exception as e:
            print("wrong with fixes")
            pass


        with open("snyk_reports_with_src2", 'w') as f:
            json.dump(self.dic, f)



    def closed(self,reason):
        self.driver.close()
        with open("snyk_reports_with_src2", 'w') as f:
            print(len(self.dic))
            json.dump(self.dic, f)

