cwe_list = ['CWE-79', 'CWE-20', 'CWE-125', 'CWE-200', 'CWE-476', 'CWE-400', 'CWE-787', 'CWE-22', 'CWE-369', 'CWE-352']
mp = {"B101":["CWE-400",'CWE-20'],
"B102":["CWE-20"],
       "B113":["CWE-400",'CWE-20'],
"B202":["CWE-22",'CWE-200'],
"B506":["CWE-20"],
"B602":["CWE-20"],"B603":["CWE-20"],"B604":["CWE-20"],"B605":["CWE-20"],"B606":["CWE-20"],"B607":["CWE-20"],
"B701":["CWE-79",'CWE-200'],
"B702":["CWE-79",'CWE-200'],
"B703":["CWE-79",'CWE-200'],
       }
import json
import os
# with open("./github_advisories.json","r")as f:
#     link_dic = json.load(f)

# cwe_count = 0
# report_dic = {}
# cwe_dic = {}
# for cwe,reports in sorted(link_dic.items(), key=lambda x: len(x[1]), reverse=True):
#     cwe_count+=1
#     print(f"CWE - {cwe}")
#     print(f"CWE_count {cwe_count}")
#     if cwe_count>10:
#         break
#     for report in reports:
#         id = report["ghsa_id"]
#         report_dic[id]=cwe
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



import glob
csv_file_dic = {}
mark_dic = {}
count_report_dic = {}
cwe_match = 0
cwe_match_list = []
by_commit = {}
for csv_file in glob.glob("/home/sdb/haowei/vul/bandit_runs_latest/*.out"):
    file_name = os.path.basename(csv_file)
    file_name = file_name[:-4]
    ns = file_name.rsplit("_", 1)
    if ns[0].count("_") > 1:
        print("warning")
        print(ns[0])

    repo = "https://github.com/" + ns[0].replace("_", "/") + "/"
    commit = ns[1]
    commit_link = repo + "commit/" + commit
    if commit_link not in commit_dic:
        print("remove broken")
        continue
    # print(commit_link)

    report_cwe = commit_cwe_dic[commit_link]

    file_dict = {}
    file_dict["report_cwe"] = report_cwe
    file_dict["commit_link"] = commit_link
    file_dict["report"] = commit_dic[commit_link][0]["report_link"]

    with open(csv_file,"r") as f:
        warnings = f.read().split("--------------------------------------------------")
        count_dic = {}
        mark = False
        relavant_results = []
        for warning in warnings:
            for k in mp.keys():
                if k in warning:
                    if report_cwe in mp[k]:
                        print(k)
                        relavant_results.append(warning)


    if len(relavant_results)>0:
        file_dict["cwe_match"] = True
        file_dict["relevant_results"] = relavant_results
        cwe_match_list.append(file_dict)
        by_commit[commit_link]=file_dict
    else:
        file_dict["cwe_match"] = False
        file_dict["relevant_results"] = []
    csv_file_dic[csv_file] = file_dict

    # if report_cwe not in count_report_dic:
    #     count_report_dic[report_cwe] = []
    # count_report_dic[report_cwe].append(file_dict)

print(f"cwe_match {cwe_match}")

count_cwe_match = {}
for file in cwe_match_list:
    target_cwe = file["report_cwe"]
    if target_cwe not in count_cwe_match:
        count_cwe_match[target_cwe]=[]
    count_cwe_match[target_cwe].append(file)
for cwe, files in sorted(count_cwe_match.items(), key=lambda item: len(item[1])):
    print(cwe)
    print(len(files))



count_cwe_match2 = {}

# exit()

with open("/home/sdb/haowei/vul/bandit_samples.out","r")as f:
    js = [json.loads(line) for line in f.read().splitlines()]

count = 0
sample_dic = []
for line in js:
    commit = line["commit_link"]
    if commit in by_commit:
        # count+=1
        file = by_commit[commit]
        target_cwe = line["report_cwe"]
        if target_cwe not in count_cwe_match2:
            count_cwe_match2[target_cwe] = []
        count_cwe_match2[target_cwe].append(file)
        # print(commit)
print(count)
with open(f"new_review/bandit_samples23.out", "r")as f:
    js = [json.loads(line) for line in f.read().splitlines()]
for line in js:
    commit = line["commit_link"]
    if commit in by_commit:
        # count+=1
        file = by_commit[commit]
        target_cwe = line["report_cwe"]
        if target_cwe not in count_cwe_match2:
            count_cwe_match2[target_cwe] = []
        count_cwe_match2[target_cwe].append(file)
for cwe, files in sorted(count_cwe_match2.items(), key=lambda item: len(item[1])):
    print(cwe)
    print(len(files))
