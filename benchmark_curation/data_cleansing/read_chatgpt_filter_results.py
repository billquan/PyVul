from openai import OpenAI

import json


# file_response = client.files.content("file-X7mQhAH5bDuNXfXJduLgduam")
# print(file_response.text)
# with open("gpt_output_0_50.out", "w") as f:
#     f.write(file_response.text)
#
# file_response = client.files.content("file-oq6heiODF3qYm7IDmSdUwQVQ")
# print(file_response.text)
# with open("gpt_output_0_50.err", "w") as f:
#     f.write(file_response.text)



with open("all_vul_tmpf2.json", "r") as f:
    commit_rows = json.load(f)

# with open("all_vul7.json", "r") as f:
#     commit_rows2 = json.load(f)
#code_snippets = []

with open("commits_cwe_dic_all.json","r") as f:
    commit_cwe_dic = json.load(f)

order_dic = {}

for commit_row in commit_rows:
    hash = commit_row["hash"]
    # if hash == "0b995602e6e5894ee31625a4dd0e6aa255d2a651":
    #     print("?????")
    repo_url = commit_row["repo_url"]
    if repo_url.endswith(".git"):
        # print("imrgiht")
        repo_url = repo_url[:-4]

    c = repo_url+"/commit/"+hash
    order_dic[c] = None

# for commit_row in commit_rows2:
#     hash = commit_row["hash"]
#     # if hash == "0b995602e6e5894ee31625a4dd0e6aa255d2a651":
#     #     print("?????")
#     repo_url = commit_row["repo_url"]
#     if repo_url.endswith(".git"):
#         # print("imrgiht")
#         repo_url = repo_url[:-4]
#
#     c = repo_url+"/commit/"+hash
#     order_dic[c] = commit_row
#
# print(len(order_dic))
# print(len(commit_rows))
# print(len(commit_rows2))
# for c,content in order_dic.items():
#     if not content:
#         print(c)
#         print("no content")
#     if not "description" in content:
#         print(c)
#         print("no des")

# exit()
cwe_code_snipets = {}
hash_dic = {}
new_dic = []
redo_commits = []
for commit_row in commit_rows:
    hash = commit_row["hash"]
    # if hash == "0b995602e6e5894ee31625a4dd0e6aa255d2a651":
    #     print("?????")
    repo_url = commit_row["repo_url"]
    if repo_url.endswith(".git"):
        # print("imrgiht")
        repo_url = repo_url[:-4]

    c = repo_url+"/commit/"+hash
    # if c == "https://github.com/apache/airflow/commit/0b995602e6e5894ee31625a4dd0e6aa255d2a651":
    #     for md in commit_row[
    #         "commit_methods"]:
    #         print(md)
    if c not in commit_cwe_dic:
        print(commit_cwe_dic)
        print(c)
        raise Exception
    cwe = commit_cwe_dic[c]
    if cwe not in cwe_code_snipets:
        cwe_code_snipets[cwe]=[]
    # print(commit_row["hash"])
    # print(commit_row["repo_url"])
    commit_files = commit_row["commit_files"]
    commit_methods = commit_row["commit_methods"]
    file_dic = {}
    for file in commit_files:
        file_change_id = file['file_change_id']
        filename = file['filename']
        programming_language = file['programming_language']
        if programming_language=="Python" :
            if hash not in hash_dic:
                hash_dic[hash] = commit_row
        # print(filename)
        # print(file_change_id)
        # print(programming_language)
        file_dic[file_change_id] = file
    if commit_methods:
        new_commit_methods = []
        true = []
        false = []
        for md in commit_methods:
            if c == "https://github.com/yt-dlp/yt-dlp/commit/1ceb657bdd254ad961489e5060f2ccc7d556b729":
                print("_______----------------------------------_______________--")
                print(md)
                print("pair" in md)
                if "pair" in md:
                    print(md["pair"])
                print("_______----------------------------------_______________--")
            name = md['name']
            code = md['code']
            file_change_id = md['file_change_id']
            vuln = md['before_change']
            if file_dic[file_change_id]["old_path"] and "test" in file_dic[file_change_id]["old_path"]:
                continue
            new_commit_methods.append(md)
            if vuln == "True":
                true.append(md)
            else:
                false.append(md)

        if len(true) > 20 or len(false) > 20:
            continue

        for md in new_commit_methods:
            name = md['name']
            code = md['code']
            file_change_id = md['file_change_id']
            vuln = md['before_change']

            # print(name)
            # print(code[:100])
            # print(file_change_id)
            #code_snippets.append({"code":code,"vulnerable":vuln,"programming_language":file_dic[file_change_id]['programming_language']})
            cwe_code_snipets[cwe].append({"code":code,"vulnerable":vuln,"programming_language":file_dic[file_change_id]['programming_language']})
            if file_dic[file_change_id]["old_path"] and "test" in file_dic[file_change_id]["old_path"]:
                continue
            if vuln=="True":

                method_after = None
                if "pair" in md:
                    paired_id = md["pair"]
                    for m2 in new_commit_methods:
                        if not m2['before_change'] == "True" and m2['file_change_id'] == file_change_id:
                            if m2['method_change_id'] == paired_id:
                                method_after = m2
                                # print("any????")
                else:
                    for m2 in new_commit_methods:
                        if not m2['before_change']=="True" and m2['file_change_id'] ==file_change_id:
                            if m2['name']==name and m2['signature']==md['signature']:
                                method_after = m2
                if not method_after:
                    method_after= {"name":name,"code":""}
                # if c == "https://github.com/apache/airflow/commit/0b995602e6e5894ee31625a4dd0e6aa255d2a651":
                #     print({"name":name,"code":code,"commit":c,"commit_message":commit_row["msg"],"m2":method_after,
                #                 "description":commit_row["description"], "file_change_id": file_change_id})
                if method_after["name"]!=md["name"]:
                    print("here______________________________")
                    print(md["name"])
                    print(method_after["name"])
                    if c not in redo_commits:
                        redo_commits.append(c)
                new_dic.append({"name":name,"code":code,"commit":c,"commit_message":commit_row["msg"],"m2":method_after,
                                "description":commit_row["description"], "file_change_id": file_change_id,"report_link":commit_row["report_link"],
                                "programming_language":file_dic[file_change_id]['programming_language']})

# for md in hash_dic["https://github.com/apache/airflow/commit/0b995602e6e5894ee31625a4dd0e6aa255d2a651"]["commit_methods"]:
#     print(md)
# exit()
print(len(redo_commits))
print("After clean")
print(len(new_dic))
find_pair = 0
paired = []
for commit_line in new_dic:
    if commit_line["m2"]:
        find_pair+=1
        ca = commit_line["m2"]

        paired.append({"function_name":commit_line["name"],"code_before":commit_line["code"],
                       "code_after":ca["code"],"commit_message":commit_line["commit_message"],"commit":commit_line["commit"],
                       "description":commit_line["description"], "file_change_id": commit_line["file_change_id"],
                       "report_link": commit_line["report_link"],"programming_language":commit_line["programming_language"]})
print(f"find pair {find_pair}")

new_pair = []
for func in paired:
    file_change_id = func['file_change_id']
    func["other_changed_function_in_the_commit"] = []
    for f2 in paired:
        if f2['commit']==func['commit'] and f2['file_change_id']==file_change_id and not f2["function_name"]==func["function_name"]:
            # print("heereeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
            new_other_func = {"function_name":f2["function_name"],"code_before":f2["code_before"],
                       "code_after":f2["code_after"]}
            func["other_changed_function_in_the_commit"].append(new_other_func)
    # print(func)
    # if func["commit"] == "https://github.com/yt-dlp/yt-dlp/commit/1ceb657bdd254ad961489e5060f2ccc7d556b729":
    #     print("_______----------------------------------_______________--")
    #     print(func)
    #     print("_______----------------------------------_______________--")
    new_pair.append(func)


import json
json_list = []
i = 0
# exit()


with open("test_without_des.out","r")as f:
    gpt_output_without_des = [line for line in f]
with open("test_with_des.out","r")as f:
    gpt_output_with_des = [line for line in f]

# with open("try_gpt_test_case6.out","r")as f:
#     gpt_output6 = [line for line in f]
# with open("try_gpt_test_case5.out","r")as f:
#     gpt_output5 = [line for line in f]
# with open("try_gpt_test_case4.out","r")as f:
#     gpt_output4 = [line for line in f]

#
# with open("try_gpt_test_case2.out","r")as f:
#     gpt_output1 = [line for line in f]
#
#
# with open("try_gpt_test_case3.out","r")as f:
#     gpt_output2 = [line for line in f]
#
# err_pairs = [2488, 167, 1164, 1102, 488, 1327, 76, 1401, 1223, 1052, 2527, 238, 1681, 88, 1628, 60, 459, 2421, 543, 2521, 2494, 380, 371, 2115, 1242, 67, 1583, 567, 1503, 1350, 305, 53, 1054, 2178, 1010, 1295, 840, 1088, 2540, 2536, 660, 1869, 243, 447, 1012, 1141, 1821, 365, 2231, 738]
#
for i in range(51):
    print("---------------------------------------------")
    print(i)
    line = new_pair[i]
    print(line["commit"])
    print(line)
    for gpt_output_i in gpt_output_without_des:
        dic = json.loads(gpt_output_i)
        id = int(dic["custom_id"])
        if id-1 == i:
            content = dic["response"]["body"]["choices"][0]["message"]["content"]
            print("case 6 -------------------------------------------------")
            print(content)
#     # for gpt_output_i in gpt_output5:
#     #     dic = json.loads(gpt_output_i)
#     #     id = int(dic["custom_id"])
#     #     if id-1 == i:
#     #         content = dic["response"]["body"]["choices"][0]["message"]["content"]
#     #         print("case 5 -------------------------------------------------")
#     #         print(content)
#     # for gpt_output_i in gpt_output4:
#     #     dic = json.loads(gpt_output_i)
#     #     id = int(dic["custom_id"])
#     #     if id-1 == i:
#     #         content = dic["response"]["body"]["choices"][0]["message"]["content"]
#     #         print("case 4 -------------------------------------------------")
#     #         print(content)
    for gpt_output_i in gpt_output_with_des:
        dic = json.loads(gpt_output_i)
        id = int(dic["custom_id"])
        if id-1 == i:
            content = dic["response"]["body"]["choices"][0]["message"]["content"]
            print("case 1 -------------------------------------------------")
            print(content)
#     # for gpt_output_i in gpt_output1:
#     #     dic = json.loads(gpt_output_i)
#     #     id = int(dic["custom_id"])
#     #     if id-1 == i:
#     #         content = dic["response"]["body"]["choices"][0]["message"]["content"]
#     #         print(content)
#     # for gpt_output_i in gpt_output2:
#     #     dic = json.loads(gpt_output_i)
#     #     id = int(dic["custom_id"])
#     #     if id-1 == i:
#     #         content = dic["response"]["body"]["choices"][0]["message"]["content"]
#     #         print("case 3 -------------------------------------------------")
#     #         print(content)
#     print("---------------------------------------------")
#
exit()
t = "v2_sec1_3_err"
with open("gptout/"+t,"r")as f:
    gpt_output = [line for line in f]

# for gpt_output_i in gpt_output:
#     dic = json.loads(gpt_output_i)
#     id = int(dic["custom_id"])
#     print("id")
#     print(id)
#     line = new_pair[id - 1]
#     with open("gptfiltered/err/invalid_out.out", "a") as f:
#         f.write(json.dumps(line))
#         f.write("\n")
# exit()
invalid_out = "gptfiltered/"+t+"/invalid_out.out"
positive_out = "gptfiltered/"+t+"/positive_out.out"
two_out = "gptfiltered/"+t+"/2_out.out"
three_out = "gptfiltered/"+t+"/3_out.out"
four_out = "gptfiltered/"+t+"/4_out.out"
for gpt_output_i in gpt_output:
    # i+=1
    # print(i)
    # target_function = line["function_name"]
    # commit = line["commit"]
    dic = json.loads(gpt_output_i)
    id = int(dic["custom_id"])
    print("id")
    print(id)
    line = new_pair[id-1]
    content = dic["response"]["body"]["choices"][0]["message"]["content"]

    line["gpt_answer"] = content

    start_index = gpt_output_i.find("answer\\\"")
    # print(start_index)
    if start_index==-1:
        start_index = gpt_output_i.find("answer\'")
        if start_index == -1:
            print("here???????")
            with open(invalid_out, "a") as f:
                f.write(json.dumps(line))
                f.write("\n")
            continue
        answer = gpt_output_i[start_index + 9:start_index + 10]

    else:
        end_index = start_index+20
        print(id)
        answer = gpt_output_i[start_index+10:start_index+11]
        print(gpt_output_i)
        print(answer)
    try:
        answer = int(answer)
    except Exception as e:
        with open(invalid_out,"a") as f:
            f.write(json.dumps(line))
            f.write("\n")
        continue
    if answer==1:
        with open(positive_out,"a") as f:
            f.write(json.dumps(line))
            f.write("\n")
    elif answer==2:
        with open(two_out,"a") as f:
            f.write(json.dumps(line))
            f.write("\n")
    elif answer==3:
        with open(three_out,"a") as f:
            f.write(json.dumps(line))
            f.write("\n")
    elif answer==4:
        with open(four_out,"a") as f:
            f.write(json.dumps(line))
            f.write("\n")

    # print(line["description"])
    # line.pop("description")
    # line.pop("commit_message")
    # json_str = json.dumps({"commit":line["commit"],"report_link":line["report_link"]})
    # if "file_change_id" in line:
    #     line.pop("file_change_id")
    # json_str = json.dumps(line)
