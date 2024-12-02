import json

import json
positive_out = "gptfiltered/positive_out.out"
negative_out = "gptfiltered/negative_out.out"
only_addition_out = "gptfiltered/addition_only.out"
err = "gptfiltered/err.out"
with open(positive_out, "r") as f:
    lst = [json.loads(line) for line in f.read().splitlines()]

with open(err, "r") as f:
    err_lst = [json.loads(line) for line in f.read().splitlines()]


with open(negative_out, "r") as f:
    neg_lst = [json.loads(line) for line in f.read().splitlines()]

with open(only_addition_out, "r") as f:
    only_add_lst = [json.loads(line) for line in f.read().splitlines()]

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

benign_sample_by_pl = {}
neg_lst.extend(only_add_lst)
print("neg")
print(len(neg_lst))
for line in neg_lst:
    pl = line["programming_language"]
    if pl not in benign_sample_by_pl:
        benign_sample_by_pl[pl]=[]
    benign_sample_by_pl[pl].append(line)

for pl in benign_sample_by_pl:
    print(pl)
    print(len(benign_sample_by_pl[pl]))
count = 0
py_lst = []
commit_dic = {}
cwe_dic = {}
cwe_dic_lines = {}
cwe_commits = {}
cwe_mbu_dic = {}
for line in lst:
    commit = line["commit"]
    if commit not in existing_dic:
        continue
    # if line["programming_language"]!="Python":
    #     continue

    if commit not in commit_cwe_dic:
        print(commit)
        print(commit in existing_dic)
        raise Exception()
    cwe = commit_cwe_dic[commit]
    if cwe not in cwe_dic:
        cwe_dic[cwe]=[]
    if cwe not in cwe_commits:
        cwe_commits[cwe] = {}
    if commit not in cwe_commits[cwe]:
        cwe_commits[cwe][commit]=[]
    cwe_commits[cwe][commit].append(line)
    cwe_dic[cwe].append(line)
    if commit not in commit_dic:
        commit_dic[commit]=[]
    commit_dic[commit].append(line)

for cwe,commit_dic in cwe_commits.items():
    if cwe not in cwe_mbu_dic:
        cwe_mbu_dic[cwe]={"mbu":{},"sbu":{}}
    for commit, lines in commit_dic.items():
        if len(lines)>1:
            cwe_mbu_dic[cwe]["mbu"][commit] = lines
        else:
            cwe_mbu_dic[cwe]["sbu"][commit] = lines

for cwe,group_dic in cwe_mbu_dic.items():
    print(cwe)
    for i, commits in group_dic.items():
        print(i)
        print(len(commits))


print(f"commit {len(commit_dic)}")
count_func = 0
for c,l in commit_dic.items():
    count_func+=len(l)
print(f"func {count_func}")
exit()

cwe_code_snipets = {}



# with open("code_snippets","w") as f:
#     json.dump(code_snippets,f)

from sklearn.model_selection import train_test_split

def write_to_jsonl(data, file_path):
    with open(file_path, 'w') as file:
        for entry in data:
            json.dump(entry, file)
            file.write('\n')

# import openai
from openai import OpenAI

client = OpenAI(api_key = "xxxxxx")
coconut = 0
err_count = 0
for cwe,lines in cwe_dic.items():
    # if cwe not in ['CWE-79', 'CWE-22', 'CWE-476', 'CWE-20', 'CWE-400']:
    #     continue
    if cwe not in [ 'CWE-22','CWE-476','CWE-400']:
        continue
    coconut+=1
    # if cwe!="CWE-125":
    #     continue
    # if cwe in ['CWE-79', 'CWE-22','CWE-20']:
    #     continue
    print(f"now process {cwe}")
    print(len(lines))
    dataset_for_davinci_true = []
    dataset_for_davinci_false = []
    dataset_for_davinci = {"True": [], "False": []}
    for line in lines:
        code = line["code_before"]
        code_after = line["code_after"]
        if len(code_after) == 0:
            print("no code after")
            continue
        completion = "True"
        datapoint = {
            "messages": [
                {"role": "system", "content": "You are a security expert that is good at static program analysis"},
                {"role": "user", "content": f"{code}"},
                {"role": "assistant", "content": f"{completion}"}]}
        # datapoint = {"prompt": cs["code"], "completion": completion}
        dataset_for_davinci[completion].append(datapoint)
        pl =line["programming_language"]
        # try:
        #     sample = random.sample(benign_sample_by_pl[pl],k=1)[0]
        #     benign_sample_by_pl[pl].remove(sample)
        # except Exception as e:
        #     err_count+=1
        #     print(err_count)
        #     sample = random.sample(benign_sample_by_pl["Python"], k=1)[0]
        #     benign_sample_by_pl["Python"].remove(sample)

        if code_after:
            sample_code = code_after

        else:
            sample = random.sample(benign_sample_by_pl[pl], k=1)[0]
            sample_code = sample["code_after"]
        completion = "False"
        datapoint = {
            "messages": [
                {"role": "system", "content": "You are a security expert that is good at static program analysis"},
                {"role": "user", "content": f"{sample_code}"},
                {"role": "assistant", "content": f"{completion}"}]}
        # datapoint = {"prompt": cs["code"], "completion": completion}
        dataset_for_davinci[completion].append(datapoint)


        # completion = "False"
        #
        # datapoint = {
        #     "messages": [
        #         {"role": "system", "content": "You are a security expert that is good at static program analysis"},
        #         {"role": "user", "content": f"{code_after}"},
        #         {"role": "assistant", "content": f"{completion}"}]}
        # # datapoint = {"prompt": cs["code"], "completion": completion}
        # dataset_for_davinci[completion].append(datapoint)




    # train_data, val_data = train_test_split(
    #     dataset_for_davinci,
    #     train_size = 240,
    #     test_size=60,
    #     random_state=42
    # )
    # if len(dataset_for_davinci_true)<150 or len(dataset_for_davinci_false)<150:
    #     print(f"{cwe}has less than 150 samples for True/False")
    #     continue

    tv_data_true, test_data_true = train_test_split(
        dataset_for_davinci["True"],
        train_size = 0.8,
        test_size=0.2,
        random_state=42
    )

    train_data_true, val_data_true = train_test_split(
        tv_data_true,
        train_size=0.8,
        test_size=0.2,
        random_state=42
    )

    tv_data_false, test_data_false = train_test_split(
        dataset_for_davinci["False"],
        train_size=len(tv_data_true),
        test_size=len(test_data_true),
        random_state=42
    )

    train_data_false, val_data_false = train_test_split(
        tv_data_false,
        train_size=0.8,
        test_size=0.2,
        random_state=42
    )

    train_data = train_data_true+train_data_false
    val_data =  val_data_true+val_data_false
    test_data = test_data_true+test_data_false

    tmp_dir = "new/cwe_paired"
    training_file_name = tmp_dir+"/"+cwe + "_davinci_train.jsonl"
    validation_file_name = tmp_dir+"/"+ cwe + "_davinci_valid.jsonl"
    test_file_name = tmp_dir+"/"+ cwe + "_davinci_test.jsonl"

    write_to_jsonl(train_data, training_file_name)
    write_to_jsonl(val_data, validation_file_name)
    write_to_jsonl(test_data, test_file_name)



    # with open(cwe+"_dataset_davinci.jsonl","w") as f:
    #     for datapoint in dataset_for_davinci:
    #         f.write(json.dumps(datapoint))
    #         f.write("\n")
    print("upload datasets")

    training_file = client.files.create(
        file=open(training_file_name, "rb"),
        purpose="fine-tune"
    )

    validation_file = client.files.create(
      file=open(validation_file_name, "rb"),
      purpose="fine-tune"
    )

    print(f"creating finetune job for {cwe}")
    client.fine_tuning.jobs.create(
      training_file=training_file.id,
        validation_file = validation_file.id,
      model="gpt-3.5-turbo",
        suffix=cwe+"_150n"
    )


