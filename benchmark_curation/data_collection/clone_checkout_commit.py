import git
import json
import os
import shutil

with open("./github_adv_src_links.json","r")as f:
    link_dic = json.load(f)

cwe_count = 0
for cwe,reports in sorted(link_dic.items(), key=lambda x: len(x[1]), reverse=True):
    cwe_count+=1
    print(f"CWE - {cwe}")
    print(f"CWE_count {cwe_count}")
    if cwe_count>10:
        break
    for report in reports:
        src_links = report["src_links"]
        if len(src_links)==0:
            continue
        src_link = src_links[0]
        ghsa_id = report["id"]
        if "/commit/" in src_link:
            print("/commit/")
            sp = src_link.split("/commit/")
            repo_url = sp[0]
            commit = sp[1]
            print(repo_url)
            folder_name = repo_url[19:].replace("/","_")
            print(folder_name)
            print(commit)
            repo_clone_url = repo_url+".git"
            print(repo_clone_url)
            # if os.path.exists(os.path.join("/home/sdb/haowei/vul/codeql_dbs",folder_name+"_"+ghsa_id)):
            #     shutil.move(os.path.join("/home/sdb/haowei/vul/codeql_dbs",folder_name+"_"+ghsa_id),
            #               os.path.join("/home/sdb/haowei/vul/codeql_dbs", folder_name + "_" + commit))
            # if os.path.exists(os.path.join("/home/sdb/haowei/vul/codeql_results",folder_name+"_"+ghsa_id+".csv")):
            #     shutil.move(os.path.join("/home/sdb/haowei/vul/codeql_results",folder_name+"_"+ghsa_id+".csv"),
            #               os.path.join("/home/sdb/haowei/vul/codeql_results", folder_name + "_" + commit+".csv"))

            try:
                repo = git.Repo.clone_from(repo_clone_url, os.path.join("/data/haowei/vul/github_adv_repos",folder_name+"_"+ghsa_id))
                repo.git.checkout(commit)
                parent_commit = list(repo.iter_commits(repo.head.commit))[1]
                repo.git.checkout(parent_commit)
            except Exception as e:
                print(f"error {repo_url}")
                continue

