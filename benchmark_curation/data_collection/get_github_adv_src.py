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
    src_link_dic={}
    count_none_zero = 0
    with open("github_advisories.json", "r") as f:
        cwe = json.load(f)
    count = 0
    cwe_count = 0
    for k, v in sorted(cwe.items(), key=lambda x: len(x[1]), reverse=True):
        cwe_count+=1
        # if cwe_count>10:
        #     break
        if k not in src_link_dic:
            src_link_dic[k] = []
        for report in v:
            count+=1
            url = report["html_url"]
            # print(url)
            id = report["ghsa_id"]
            repo_link = report["source_code_location"]
            refs = report["references"]
            commits = []
            for link in refs:
                if repo_link+"/commit" in link:
                    commits.append(link)
            # print(commits)
            # if len(commits)==0:
            #     for link in refs:
            #         if repo_link + "/blob" in link or repo_link + "/file" in link:
            #             commits.append(link)
            # print(commits)
            if len(commits)>0:
                count_none_zero+=1
            if len(commits)>1:
                print(url)
                print(commits)
            src_link_dic[k].append({"id":id,"src_links":commits,"repo_link":repo_link})
    print(count_none_zero)
    print(count)
    with open("github_adv_src_links.json", 'w') as f:
        json.dump(src_link_dic, f)



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
