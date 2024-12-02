from openai import OpenAI
import json

client = OpenAI(api_key = "xxxxxxxxxxxxxxxxxxxxxx")

# CWE_model_name = {"CWE-79":"ft:davinci-002:personal:cwe-79:9CAzxG1S", "CWE-125":"ft:davinci-002:personal:cwe-125:9CCQRsEH", "CWE-787":"ft:davinci-002:personal:cwe-787:9CB81wU9"}


cwe = "CWE-476"
test = f"new/cwe_paired/{cwe}_davinci_test.jsonl"
train = f"new/cwe_paired/{cwe}_davinci_train.jsonl"
valid = f"new/cwe_paired/{cwe}_davinci_valid.jsonl"
with open(test, "r") as f:
    test_dataset = [json.loads(line) for line in f.read().splitlines()]

with open(train, "r") as f:
    train_dataset = [json.loads(line) for line in f.read().splitlines()]

with open(valid, "r") as f:
    valid_dataset = [json.loads(line) for line in f.read().splitlines()]


print("train size")
print(len(train_dataset)+len(valid_dataset))
print("test size")
print(len(test_dataset))
c = 0

TP = 0
FP = 0
TN = 0
FN = 0
invalid = 0
import random
for dp in test_dataset:
    c+=1
    # if c>20:
    #     break
    v = dp["messages"][2]["content"]
    # print(f"This data point should be {v}")
    completion = client.chat.completions.create(
        model="ft:gpt-3.5-turbo-0125:monash-university:cwe-476-150n:AQ6t8TBj",
        messages=[{"role": "system", "content": "You are a security expert that is good at static program analysis"},
                  dp["messages"][1]],
        max_tokens=1,
        temperature=0
    )
    prediction = completion.choices[0].message.content
    print(prediction)
    print(v)
    if v == "True" and prediction == "True":
        TP += 1
    elif v == "False" and prediction == "True":
        FP += 1
    elif v == "False" and prediction == "False":
        TN += 1
    elif v == "True" and prediction == "False":
        FN += 1
    else:
        invalid += 1

print(f"TP {TP}")
print(f"FP {FP}")
print(f"TN {TN}")
print(f"FN {FN}")

accuracy = (TP+TN)/(TP+TN+FP+FN)
precision = (TP)/(TP+FP)
recall = (TP)/(TP+FN)

print(f"accuracy {accuracy}")
print(f"precision {precision}")
print(f"recall {recall}")

f1 = 2*precision*recall/(precision+recall)
print(f"f1 {f1}")



