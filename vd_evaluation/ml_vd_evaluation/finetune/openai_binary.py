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


count = 0
py_lst = []
commit_dic = {}
cwe_dic = {}
cwe_dic_lines = {}
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
    if commit not in commit_dic:
        commit_dic[commit]=[]
    commit_dic[commit].append(line)


print(f"commit {len(commit_dic)}")
count_func = 0
for c,l in commit_dic.items():
    count_func+=len(l)
print(f"func {count_func}")
mu = []
su = []
for commit,lines in commit_dic.items():
    if len(lines)>1:
        mu.extend(lines)
    else:
        su.extend(lines)
print(f"su{len(su)}")
print(f"mu{len(mu)}")
#code_snippets = []
# exit()


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
client = OpenAI(api_key = "xxxxxxxxxxxxxxxxxx")

cwe_count = {}
dataset_for_davinci={"True":[],"False":[]}
for line in lst:
    commit = line["commit"]
    if commit not in existing_dic:
        continue
    # if line["programming_language"] != "Python":
    #     continue

    if commit not in commit_cwe_dic:
        print(commit)
        print(commit in existing_dic)
        raise Exception()

    # if len(cs["code"]) > 16378:
    #     continue

    code = line["code_before"]
    code_after = line["code_after"]
    if len(code_after)==0:
        print("no code after")
        continue
    completion = "True"
    datapoint = {
        "messages": [{"role": "system", "content": "You are a security expert that is good at static program analysis"},
                     {"role": "user", "content": f"{code}"},
                     {"role": "assistant", "content": f"{completion}"}]}
    # datapoint = {"prompt": cs["code"], "completion": completion}
    dataset_for_davinci[completion].append(datapoint)

    # completion = "False"
    #
    # datapoint = {
    #     "messages": [{"role": "system", "content": "You are a security expert that is good at static program analysis"},
    #                  {"role": "user", "content": f"{code_after}"},
    #                  {"role": "assistant", "content": f"{completion}"}]}
    # # datapoint = {"prompt": cs["code"], "completion": completion}
    # dataset_for_davinci[completion].append(datapoint)
        #     dataset_for_davinci_false.append(datapoint)

    # train_data, val_data = train_test_split(
    #     dataset_for_davinci,
    #     train_size = 240,
    #     test_size=60,
    #     random_state=42
    # )
    # if len(dataset_for_davinci_true)<300 or len(dataset_for_davinci_false)<300:
    #     print(f"{cwe}has less than 300 samples for True/False")
    #     continue


for line in neg_lst:
    commit = line["commit"]
    if commit not in existing_dic:
        continue
    # if line["programming_language"] != "Python":
    #     continue

    if commit not in commit_cwe_dic:
        print(commit)
        print(commit in existing_dic)
        raise Exception()

    # if len(cs["code"]) > 16378:
    #     continue

    code = line["code_before"]
    code_after = line["code_after"]
    if len(code_after)==0:
        print("no code after")
        continue
    completion = "False"
    datapoint = {
        "messages": [{"role": "system", "content": "You are a security expert that is good at static program analysis"},
                     {"role": "user", "content": f"{code_after}"},
                     {"role": "assistant", "content": f"{completion}"}]}
    # datapoint = {"prompt": cs["code"], "completion": completion}
    dataset_for_davinci[completion].append(datapoint)


for line in only_add_lst:
    commit = line["commit"]
    if commit not in existing_dic:
        continue
    # if line["programming_language"] != "Python":
    #     continue

    if commit not in commit_cwe_dic:
        print(commit)
        print(commit in existing_dic)
        raise Exception()

    # if len(cs["code"]) > 16378:
    #     continue

    code = line["code"]
    completion = "False"
    datapoint = {
        "messages": [{"role": "system", "content": "You are a security expert that is good at static program analysis"},
                     {"role": "user", "content": f"{code}"},
                     {"role": "assistant", "content": f"{completion}"}]}
    # datapoint = {"prompt": cs["code"], "completion": completion}
    dataset_for_davinci[completion].append(datapoint)

# print(cwe_count)
print("len")
print(len(dataset_for_davinci["True"]))
print(len(dataset_for_davinci["False"]))
tv_data_true, test_data_true = train_test_split(
    dataset_for_davinci["True"],
    train_size = 150,
    test_size = 150,
    random_state=42
)


train_data_true, val_data_true = train_test_split(
    tv_data_true,
    train_size=120,
    test_size=30,
    random_state=42
)

tv_data_false, test_data_false = train_test_split(
    dataset_for_davinci["False"],
    train_size = 150,
    test_size = 150,
    random_state=42
)

train_data_false, val_data_false = train_test_split(
    tv_data_false,
    train_size=120,
    test_size=30,
    random_state=42
)

train_data = train_data_true+train_data_false
test_data = test_data_true+test_data_false
val_data = val_data_true+val_data_false

tmp_dir = "new"

training_file_name = tmp_dir+"/"+"binary_train_simple_balanced_300n_use_addition.jsonl"
validation_file_name = tmp_dir+"/"+"binary_valid_simple_balanced_300n_use_addition.jsonl"
test_file_name = tmp_dir+"/"+"binary_test_simple_balanced_300n_use_addition.jsonl"

write_to_jsonl(train_data, training_file_name)
write_to_jsonl(val_data, validation_file_name)
write_to_jsonl(test_data, test_file_name)



# with open("two_labelled_dataset_davinci_simple2.jsonl","w") as f:
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
    suffix="new_binary_bl_300n_use_addition"
)


