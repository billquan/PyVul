import json
import requests

# import openai
from openai import OpenAI


with open(f"new/binary_test_simple_balanced_300n_use_addition.jsonl", "r") as f:
    test_dataset = [json.loads(line) for line in f.read().splitlines()]

c = 0

TP = 0
FP = 0
TN = 0
FN = 0
invalid = 0
for dp in test_dataset:
    c+=1
    # if c>20:
    #     break
    code = dp["messages"][1]["content"]
    v1 = dp["messages"][2]["content"]
    if v1=="True":
        v = "YES"
    else:
        v = "NO"
    question = {"role": "user", "content": f"Is the following code vulnerable?\n```\n{code}\n```\n"
                                                             f"Please answer in only one word, either YES or NO."}
    if c==1:
        print(question)
    # print(f"This data point should be {v}")
    # completion = client.chat.completions.create(
    #     model="gpt-3.5-turbo",
    #     messages=[{"role": "system", "content": "You are a security expert that is good at static program analysis"},
    #               question],
    #     max_tokens=1,
    #     temperature=0
    # )
    send_data = {
        "model": "codeqwen:chat",
        "messages": [question],
        "stream": False
    }
    r = requests.post('http://localhost:11434/api/chat', json=send_data)
    # print(r)
    # print(r.json())
    prediction = r.json()["message"]["content"]

    # prediction = completion.choices[0].message.content
    print(prediction)
    print(v)
    if v == "YES" and prediction == "YES":
        TP += 1
    elif v == "NO" and prediction == "YES":
        FP += 1
    elif v == "NO" and prediction == "NO":
        TN += 1
    elif v == "YES" and prediction == "NO":
        FN += 1
    else:
        invalid += 1

accuracy = (TP+TN)/(TP+TN+FP+FN)
precision = (TP)/(TP+FP)
recall = (TP)/(TP+FN)
f1 = 2*precision*recall/(precision+recall)

print(f"TP {TP}")
print(f"FP {FP}")
print(f"TN {TN}")
print(f"FN {FN}")
print(f"invalid {invalid}")
print(f"accuracy {accuracy}")
print(f"precision {precision}")
print(f"recall {recall}")
print(f"f1{f1}")


