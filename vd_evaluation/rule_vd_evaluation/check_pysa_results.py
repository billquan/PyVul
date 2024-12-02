import glob
import os

s = '''5005 - CWE-74, CWE-89, CWE-707, CWE-943
5007 - CWE-610, CWE-611, CWE-664, CWE-669, CWE-706, CWE-827, CWE-829
5008 - CWE-74, CWE-79, CWE-116, CWE-707
5011 - CWE-22, CWE-23, CWE-36, CWE-73, CWE-74, CWE-99, CWE-610, CWE-642, CWE-664, CWE-668, CWE-706, CWE-707
5012 - CWE-441, CWE-610, CWE-664, CWE-918
5018 - CWE-601, CWE-610, CWE-664
5027 - CWE-200, CWE-284, CWE-287, CWE-664, CWE-693
5029 - CWE-287, CWE-74, CWE-79, CWE-116, CWE-707, CWE-300
5034 - CWE-200
5036 - CWE-74, CWE-79, CWE-116, CWE-707
5041 - CWE-74, CWE-94, CWE-95, CWE-116, CWE-664, CWE-691, CWE-707, CWE-913
5045 - CWE-74, CWE-89, CWE-707, CWE-943
5046 - CWE-74, CWE-79, CWE-116, CWE-707
5015 - CWE-74, CWE-79, CWE-116, CWE-707
6462 - CWE-441, CWE-610, CWE-664, CWE-918
5067 - CWE-74, CWE-94, CWE-95, CWE-116, CWE-664, CWE-691, CWE-707, CWE-913
6060 - CWE-22, CWE-23, CWE-36, CWE-73, CWE-74, CWE-99, CWE-610, CWE-642, CWE-664, CWE-668, CWE-706, CWE-707
6064 - CWE-74, CWE-94, CWE-95, CWE-116, CWE-664, CWE-691, CWE-707, CWE-913
6065 - CWE-74, CWE-94, CWE-95, CWE-116, CWE-664, CWE-691, CWE-707, CWE-913
6066 - CWE-74, CWE-94, CWE-95, CWE-116, CWE-664, CWE-691, CWE-707, CWE-913
6073 - CWE-74, CWE-94, CWE-707, CWE-1336
6074 - CWE-259, CWE-284, CWE-287, CWE-321, CWE-330, CWE-344, CWE-657, CWE-664, CWE-671, CWE-693, CWE-710, CWE-798
6302 - CWE-200
6303 - CWE-74, CWE-90, CWE-707, CWE-943
6306 - CWE-285, CWE-287
5301 - CWE-74, CWE-94, CWE-95, CWE-116, CWE-664, CWE-691, CWE-707, CWE-913
5305 - CWE-74, CWE-89, CWE-707, CWE-943
5307 - CWE-610, CWE-611, CWE-664, CWE-669, CWE-706, CWE-827, CWE-829
5308 - CWE-74, CWE-79, CWE-116, CWE-707
5311 - CWE-22, CWE-23, CWE-36, CWE-73, CWE-74, CWE-99, CWE-610, CWE-642, CWE-664, CWE-668, CWE-706, CWE-707
5360 - CWE-22, CWE-23, CWE-36, CWE-73, CWE-74, CWE-99, CWE-610, CWE-642, CWE-664, CWE-668, CWE-706, CWE-707
5364 - CWE-74, CWE-94, CWE-95, CWE-116, CWE-664, CWE-691, CWE-707, CWE-913
5365 - CWE-74, CWE-94, CWE-95, CWE-116, CWE-664, CWE-691, CWE-707, CWE-913
5366 - CWE-74, CWE-94, CWE-95, CWE-116, CWE-664, CWE-691, CWE-707, CWE-913
5367 - CWE-74, CWE-94, CWE-95, CWE-116, CWE-664, CWE-691, CWE-707, CWE-913
5373 - CWE-74, CWE-94, CWE-707, CWE-1336
6108 - CWE-74, CWE-79, CWE-116, CWE-707
6809 - CWE-74, CWE-94, CWE-95, CWE-116, CWE-664, CWE-691, CWE-707, CWE-913'''
import json

codeql_dic = {}
for line in s.splitlines():
    #print(line)
    line_split = line.split(" - ",maxsplit=3)
    code = line_split[0]
    cwes = line_split[1]
    if code not in codeql_dic:
        codeql_dic[code] = []
    for cwe in cwes.split(", "):
        codeql_dic[code].append(cwe)

import json
positive_out = "gptfiltered/positive_out.out"
err = "gptfiltered/err.out"
with open(positive_out, "r") as f:
    lst = [json.loads(line) for line in f.read().splitlines()]

with open(err, "r") as f:
    err_lst = [json.loads(line) for line in f.read().splitlines()]

import random
import csv

with open("commits_cwe_dic_all.json","r") as f:
    commit_cwe_dic = json.load(f)
with open("all_vul_all.json","r") as f:
    existing_commit_rows = json.load(f)

existing_dic = {}
for row in existing_commit_rows:
    hash = row["hash"]
    repo_url = row["repo_url"][:-4]
    c = repo_url + "/commit/" + hash
    if c not in existing_dic:
        existing_dic[c] = row

for line in err_lst:
    commit = line["commit"]
    if commit in existing_dic:
        existing_dic.pop(commit)




count = 0
py_lst = []
commit_dic = {}
cwe_dic = {}
cwe_dic_lines = {}
for line in lst:
    commit = line["commit"]
    if commit not in existing_dic:
        continue
    if line["programming_language"]!="Python":
        continue

    if commit not in commit_cwe_dic:
        print(commit)
        print(commit in existing_dic)
        raise Exception()
    cwe = commit_cwe_dic[commit]
    if commit not in commit_dic:
        commit_dic[commit]=[]
    commit_dic[commit].append(line)

import json
# interpret results
csv_file_dic = {}
mark_dic = {}
count_report_dic = {}
cwe_match_list = []
for csv_file in glob.glob("/home/sdb/haowei/vul/pysa_runs_latest/*/taint-output.json"):
    file_name = csv_file.split("/")[-2]
    ns = file_name.rsplit("_", 1)
    if ns[0].count("_")>1:
        print("warning")
        print(ns[0])

    repo = "https://github.com/" + ns[0].replace("_", "/") + "/"
    commit = ns[1]
    commit_link = repo + "commit/" + commit
    if commit_link not in commit_dic:
        print(commit_link)
        print("remove broken")
        continue
    report_cwe = commit_cwe_dic[commit_link]
    count_dic={}
    with open(csv_file,"r") as f:
        lines = f.read().splitlines()
        results = []
        for line in lines:
            each = json.loads(line)
            results.append(each)
        for result in results:
            if "kind" in result and result["kind"] == "issue":
                code = str(result["data"]["code"])
                if code not in codeql_dic:
                    print(f"wtf{code}")
                    continue
                cwe = codeql_dic[code]
                print(cwe)
                for i in cwe:
                    if i not in count_dic:
                        count_dic[i] = []
                    count_dic[i].append(result)
    # print(csv_file)
    # print(count_dic)
    # print(report_dic[id])
    file_dict = {}
    file_dict["report_cwe"] = report_cwe
    file_dict["commit_link"] = commit_link
    file_dict["report"] = commit_dic[commit_link][0]["report_link"]
    file_dict["results"] = count_dic
    if report_cwe in count_dic:
        file_dict["cwe_match"] = True
        file_dict["relevant_results"] = count_dic[report_cwe]
        cwe_match_list.append(file_dict)
    else:
        file_dict["cwe_match"] = False
        file_dict["relevant_results"] = []
    csv_file_dic[csv_file] = file_dict
    if report_cwe not in count_report_dic:
        count_report_dic[report_cwe] = []
    count_report_dic[report_cwe].append(file_dict)

count_cwe_match = {}
for file in cwe_match_list:
    target_cwe = file["report_cwe"]
    if target_cwe not in count_cwe_match:
        count_cwe_match[target_cwe]=[]
    count_cwe_match[target_cwe].append(file)
for cwe, files in sorted(count_cwe_match.items(), key=lambda item: len(item[1])):
    print(cwe)
    print(len(files))
with open(f"new_review/pysa_samples.out", "w")as f:
    for file in cwe_match_list:
        file.pop("results")
        f.write(json.dumps(file))
        f.write("\n")