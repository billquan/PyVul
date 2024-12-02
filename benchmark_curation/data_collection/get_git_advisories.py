import csv
import requests
import json
from time import sleep
from collections import OrderedDict
import argparse
import os

error_log = f'error_log.txt'
header = ['mark', 'repo', 'issue_header', 'issue_url']
username = 'billquan'
token = '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'

def get_repos():
    collect =[]
    number = 0
    count = 0
    cwe = {}
    url = "https://api.github.com/advisories?type=reviewed&ecosystem=pip&per_page=100"
    for i in range(0, 30):
        print(i)
        tmp = {}
        print(url)
        r = requests.get(url, auth=(username, token))
        if "next" in r.links:
            next_url = r.links["next"]["url"]
            print(r.links["next"]["url"])
        else:
            break
        url = next_url
        data = json.loads(r.text)
        # all_issues.extend(x for x in data['items'] if x not in all_issues)
        for x in data:
            count += 1

            collect.append(x)
            if len(x["cwes"]) > 0:
                for c in x["cwes"]:
                    if c["cwe_id"] not in cwe:
                        cwe[c["cwe_id"]] = []
                    if x not in cwe[c["cwe_id"]]:
                        cwe[c["cwe_id"]].append(x)
        print(count)
        # print(cwe)
        sleep(5)
        # print(urls)
    cwe_count = {}
    print(len(cwe))
    # for k,v in cwe.items():
    #     print(k)
    #     print(len(v))
    #     ids = []
    #     for item in v:
    #         ids.append(item["ghsa_id"])
    #     print(ids)
    for k,v in sorted(cwe.items(), key=lambda x: len(x[1]), reverse=True):
        print(k)
        print(len(v))
        ids = []
        for item in v:
            ids.append(item["ghsa_id"])
        print(ids)
    with open('github_advisories_pip.json', 'w') as f:
        json.dump(collect, f)



def main():
    # parser = argparse.ArgumentParser(
    #     description="search for github repos")
    # parser.add_argument('lib_name', metavar='lib_name', type=str,
    #                     help='The name of the lib')
    # parser.add_argument('output_path', metavar='output_json_directory', type=str,
    #                     help='The path for json output')
    #
    #
    # args = parser.parse_args()
    # lib_name = args.lib_name
    # output_dir = args.output_path
    get_repos()

if __name__ == '__main__':
    main()
