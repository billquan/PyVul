import json

with open("all_vul_tmpf_sec2_2.json", "r") as f:
    commit_rows = json.load(f)

print(len(commit_rows))
#code_snippets = []

with open("commits_cwe_dic_all.json","r") as f:
    commit_cwe_dic = json.load(f)

cwe_code_snipets = {}
hash_dic = {}
new_dic = []
count_d = 0
for commit_row in commit_rows:
    hash = commit_row["hash"]
    if hash == "4f6789b035610e0552738cdc4b35ca809a592d48":
        print("?????")
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
    if c == "https://github.com/Pylons/waitress/commit/4f6789b035610e0552738cdc4b35ca809a592d48":
        print("here")
        if commit_methods:
            for md in commit_methods:
                print(md)
    for file in commit_files:
        file_change_id = file['file_change_id']
        filename = file['filename']
        programming_language = file['programming_language']
        # if programming_language=="Python" :
        #     if c not in hash_dic:
        #         hash_dic[c] = commit_row
        # print(filename)
        # print(file_change_id)
        # print(programming_language)
        file_dic[file_change_id] = file
    if commit_methods:
        new_commit_methods = []
        true = []
        false = []
        for md in commit_methods:
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
                new_dic.append({"name":name,"code":code,"commit":c,"commit_message":commit_row["msg"],"m2":method_after,
                                "description":commit_row["description"], "file_change_id": file_change_id})
                if c not in hash_dic:
                    hash_dic[c] = []
                hash_dic[c].append({"name":name,"code":code,"commit":c,"commit_message":commit_row["msg"],"m2":method_after,
                                "description":commit_row["description"], "file_change_id": file_change_id})

# for md in hash_dic["https://github.com/apache/airflow/commit/0b995602e6e5894ee31625a4dd0e6aa255d2a651"]["commit_methods"]:
#     print(md)
# exit()

if "https://github.com/Pylons/waitress/commit/4f6789b035610e0552738cdc4b35ca809a592d48" in hash_dic:
    print("in hash dic")
    for md in hash_dic["https://github.com/Pylons/waitress/commit/4f6789b035610e0552738cdc4b35ca809a592d48"]:
        print(md)

print(f"count_d{count_d}")
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
                       "description":commit_line["description"], "file_change_id": commit_line["file_change_id"]})
        if commit_line["code"] == ca["code"]:
            print("wrf/?????")
print(f"find pair {find_pair}")
# exit()
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
    new_pair.append(func)

with open("test1.txt", "w")as f:
    for func in new_pair:
        f.write(func["function_name"]+"\n")


import openpyxl

wb = openpyxl.load_workbook("output2.xlsx")
ws = wb.active
c = 0
new_results = []
new_lines = {}



# for row in ws.iter_rows(values_only=True):
#     c+=1
#     if c<4 or c>70:
#         continue
#     code = row[1]
#     github_link = row[2]
#     report = row[3]
#     for line in paired:
#         if code in line["code_before"] and github_link == line["commit"]:
#             new_line = line
#             new_line["report_link"] = report
#             print(report)
#             if "advisories" in report:
#                 description = g_report_dic[report]["description"]
#                 new_line["description"]=description
#             elif "snyk" in report:
#                 description = snyk_dic[report]["description"]
#                 new_line["description"] = description
#             elif "huntr" in report:
#                 description = huntr_dic[report]["description"]
#                 new_line["description"] = description
#             else:
#                 new_line["description"] = ""
#             new_lines[c] = new_line

print(len(new_lines))
from openai import OpenAI
client = OpenAI(api_key = "xxxxxxxxxxxxx")
answer_list = {}
exceed=0
des_lens = []
of_lens = []
json_list = []
i = 0
overall_lens = []
for line in new_pair:
    i+=1
    # print(i)
    # if i <1001:
    #     continue
    # if i >50:
    #     break
    # print(line["description"])
    # line.pop("description")
    # line.pop("commit_message")
    # json_str = json.dumps({"commit":line["commit"],"report_link":line["report_link"]})
    if "file_change_id" in line:
        line.pop("file_change_id")
    # line.pop("other_changed_function_in_the_commit")
    # line.pop("description")
    if "https://github.com/Pylons/waitress/commit/4f6789b035610e0552738cdc4b35ca809a592d48" in line["commit"]:
        print(True)
    json_str = json.dumps(line)
    target_function = line["function_name"]
    example_1='''
    Given the following related information, can you tell if the changed function is relevant to the vulnerability that the commit is trying to fix? Please answer 1 if the function is vulnerable, 2 if the function is changed to ensure consistency of the fix (but not vulnerable), 3 if the function is totally irrelevant, and 4 if you are unsure. Please reason before you answer. But in the end, answer in json format like {'answer':1}
    ```
    {"function_name": "render_POST", "code_before": "    def render_POST(self, request):\n        \"\"\"\n        Register with the Identity Server\n        \"\"\"\n        send_cors(request)\n\n        args = get_args(request, ('matrix_server_name', 'access_token'))\n\n        result = yield self.client.get_json(\n            \"matrix://%s/_matrix/federation/v1/openid/userinfo?access_token=%s\" % (\n                args['matrix_server_name'], urllib.parse.quote(args['access_token']),\n            ),\n            1024 * 5,\n        )\n        if 'sub' not in result:\n            raise Exception(\"Invalid response from homeserver\")\n\n        user_id = result['sub']\n        tok = yield issueToken(self.sydent, user_id)\n\n        # XXX: `token` is correct for the spec, but we released with `access_token`\n        # for a substantial amount of time. Serve both to make spec-compliant clients\n        # happy.\n        defer.returnValue({\n            \"access_token\": tok,\n            \"token\": tok,\n        })", "code_after": "    def render_POST(self, request):\n        \"\"\"\n        Register with the Identity Server\n        \"\"\"\n        send_cors(request)\n\n        args = get_args(request, ('matrix_server_name', 'access_token'))\n\n        hostname = args['matrix_server_name'].lower()\n\n        if not is_valid_hostname(hostname):\n            request.setResponseCode(400)\n            return {\n                'errcode': 'M_INVALID_PARAM',\n                'error': 'matrix_server_name must be a valid hostname'\n            }\n\n        result = yield self.client.get_json(\n            \"matrix://%s/_matrix/federation/v1/openid/userinfo?access_token=%s\"\n            % (\n                hostname,\n                urllib.parse.quote(args['access_token']),\n            ),\n            1024 * 5,\n        )\n        if 'sub' not in result:\n            raise Exception(\"Invalid response from homeserver\")\n\n        user_id = result['sub']\n        tok = yield issueToken(self.sydent, user_id)\n\n        # XXX: `token` is correct for the spec, but we released with `access_token`\n        # for a substantial amount of time. Serve both to make spec-compliant clients\n        # happy.\n        defer.returnValue({\n            \"access_token\": tok,\n            \"token\": tok,\n        })", "commit_message": "Rework hostname validation to make port checking stricter.\n\nInstead of using a regex to validate the entire hostname + port\ncombination, we now split the hostname into components and check each\ncomponent separately. This makes the regex a bit simpler and allows us\nto validate the port number better, including that it belongs to the\nvalid range.", "commit": "https://github.com/matrix-org/sydent/commit/9e573348d81df8191bbe8c266c01999c9d57cd5f", "report_link": "https://github.com/advisories/GHSA-9jhm-8m8c-c3f4", "description": "### Impact\n\nSydent can be induced to send HTTP GET requests to internal systems, due to lack of parameter validation or IP address blacklisting.\n\nIt is not possible to exfiltrate data or control request headers, but it might be possible to use the attack to perform an internal port enumeration.\n\n### Patches\n\nFixed in 9e57334, 8936925, 3d531ed, 0f00412\n\n### Workarounds\n\nA potential workaround would be to use a firewall to ensure that Sydent cannot reach internal HTTP resources.\n\n### For more information\n\nIf you have any questions or comments about this advisory, email us at security@matrix.org."}
    ```
    '''
    example_1_answer = '''
    Looking carefully at the presented information, it can be observed that the code is changed to include stricter validation of the 'matrix_server_name' parameter. This appears to be in response to a vulnerability where "Sydent can be induced to send HTTP GET requests to internal systems, due to lack of parameter validation or IP address blacklisting.".

More specifically, the change is seen to introduce an `is_valid_hostname()` function to check whether the provided 'matrix_server_name' is a valid hostname or not. Should it be invalid, an error message is returned with an HTTP 400 response code.

This adjustment matches the commit message which declares a rework of the hostname validation to make port checking stricter. The addition of validations on 'matrix_server_name' suggests a response to the reported vulnerability, by adding a protection measure against ill-formed hostname inputs that could potentially be utilized for reaching internal HTTP resources.

Thus, the conclusion here is that this function appears to be vulnerable as indicated, and it has been changed in response to this vulnerability.

{'answer': 1}

    '''

    example_2 = '''
    Given the following related information, can you tell if the changed function is relevant to the vulnerability that the commit is trying to fix? Please answer 1 if the function is vulnerable, 2 if the function is changed to ensure consistency of the fix (but not vulnerable), 3 if the function is totally irrelevant, and 4 if you are unsure. Please reason before you answer. But in the end, answer in json format like {'answer':1}
    ```
    {"function_name": "on_header_field", "code_before": "    def on_header_field(self, data: bytes, start: int, end: int) -> None:\n        message = (MultiPartMessage.HEADER_FIELD, data[start:end])\n        self.messages.append(message)", "code_after": "    def on_header_field(self, data: bytes, start: int, end: int) -> None:\n        self._current_partial_header_name += data[start:end]", "commit_message": "Merge pull request from GHSA-74m5-2c7w-9w3x\n\n* \u267b\ufe0f Refactor multipart parser logic to support limiting max fields and files\n\n* \u2728 Add support for new request.form() parameters max_files and max_fields\n\n* \u2705 Add tests for limiting max fields and files in form data\n\n* \ud83d\udcdd Add docs about request.form() with new parameters max_files and max_fields\n\n* \ud83d\udcdd Update `docs/requests.md`\n\nCo-authored-by: Marcelo Trylesinski <marcelotryle@gmail.com>\n\n* \ud83d\udcdd Tweak docs for request.form()\n\n* \u270f Fix typo in `starlette/formparsers.py`\n\nCo-authored-by: Adrian Garcia Badaracco <1755071+adriangb@users.noreply.github.com>\n\n---------\n\nCo-authored-by: Marcelo Trylesinski <marcelotryle@gmail.com>\nCo-authored-by: Adrian Garcia Badaracco <1755071+adriangb@users.noreply.github.com>", "commit": "https://github.com/encode/starlette/commit/8c74c2c8dba7030154f8af18e016136bea1938fa", "report_link": "https://github.com/advisories/GHSA-3qj8-93xh-pwh2", "description": "There MultipartParser usage in Encode's Starlette python framework before versions 0.25.0 allows an unauthenticated and remote attacker to specify any number of form fields or files which can cause excessive memory usage resulting in denial of service of the HTTP service."}
    ```
    '''
    example_2_answer = '''
    Analyzing the provided data, the commit aims at refactoring the multipart parser logic to support limiting max fields and files and adding support for new parameters in the form request, this is further supported by the vulnerability description which states that an attacker could specify an unlimited number of form fields or files causing excessive memory usage leading to Denial of Service of the HTTP Service.

Looking at the function "on_header_field", the change has been from appending a message to a list called "self.messages" to appending data to a string called "self._current_partial_header_name".

Assuming "_current_partial_header_name" is used as a part of the new multipart parser limit enforcement logic, the function "on_header_field" itself does not contribute to fixing the vulnerability. "on_header_field" just appends messages to a new list, which is a change for ensuring consistency (but not vulnerable).
As a result, I would choose 2.
```json
{
"answer": 2
}
    '''

    example_3 = '''
    Given the following related information, can you tell if the changed function is relevant to the vulnerability that the commit is trying to fix? Please answer 1 if the function is vulnerable, 2 if the function is changed to ensure consistency of the fix (but not vulnerable), 3 if the function is totally irrelevant, and 4 if you are unsure. Please reason before you answer. But in the end, answer in json format like {'answer':1}
    ```
    {"function_name": "load_jupyter_server_extension", "code_before": "def load_jupyter_server_extension(nbapp):\n    \"\"\"create a LanguageServerManager and add handlers\"\"\"\n    nbapp.add_traits(language_server_manager=traitlets.Instance(LanguageServerManager))\n    manager = nbapp.language_server_manager = LanguageServerManager(parent=nbapp)\n\n    contents = nbapp.contents_manager\n    page_config = nbapp.web_app.settings.setdefault(\"page_config_data\", {})\n\n    root_uri = \"\"\n    virtual_documents_uri = \"\"\n\n    # try to set the rootUri from the contents manager path\n    if hasattr(contents, \"root_dir\"):\n        root_uri = normalized_uri(contents.root_dir)\n        nbapp.log.debug(\"[lsp] rootUri will be %s\", root_uri)\n        virtual_documents_uri = normalized_uri(\n            Path(contents.root_dir) / manager.virtual_documents_dir\n        )\n        nbapp.log.debug(\"[lsp] virtualDocumentsUri will be %s\", virtual_documents_uri)\n    else:  # pragma: no cover\n        nbapp.log.warn(\n            \"[lsp] %s did not appear to have a root_dir, could not set rootUri\",\n            contents,\n        )\n    page_config.update(rootUri=root_uri, virtualDocumentsUri=virtual_documents_uri)\n\n    add_handlers(nbapp)\n    nbapp.io_loop.call_later(0, initialize, nbapp, virtual_documents_uri)", "code_after": "def load_jupyter_server_extension(nbapp):\n    \"\"\"create a LanguageServerManager and add handlers\"\"\"\n    nbapp.add_traits(language_server_manager=traitlets.Instance(LanguageServerManager))\n    manager = nbapp.language_server_manager = LanguageServerManager(parent=nbapp)\n\n    contents = nbapp.contents_manager\n    page_config = nbapp.web_app.settings.setdefault(\"page_config_data\", {})\n\n    root_uri = \"\"\n    virtual_documents_uri = \"\"\n\n    # try to set the rootUri from the contents manager path\n    if hasattr(contents, \"root_dir\"):\n        root_uri = normalized_uri(contents.root_dir)\n        nbapp.log.debug(\"[lsp] rootUri will be %s\", root_uri)\n        virtual_documents_uri = normalized_uri(\n            Path(contents.root_dir) / manager.virtual_documents_dir\n        )\n        nbapp.log.debug(\"[lsp] virtualDocumentsUri will be %s\", virtual_documents_uri)\n    else:  # pragma: no cover\n        nbapp.log.warn(\n            \"[lsp] %s did not appear to have a root_dir, could not set rootUri\",\n            contents,\n        )\n    page_config.update(rootUri=root_uri, virtualDocumentsUri=virtual_documents_uri)\n\n    add_handlers(nbapp)\n\n    if hasattr(nbapp, \"io_loop\"):\n        io_loop = nbapp.io_loop\n    else:\n        # handle jupyter_server 1.x\n        io_loop = ioloop.IOLoop.current()\n\n    io_loop.call_later(0, initialize, nbapp, virtual_documents_uri)", "commit_message": "Merge pull request from GHSA-4qhp-652w-c22x\n\n* Add auth decorators, add traversal guard\n\n* Fix mocks resolving most test failures;\n\n`test_listeners` still fails not sure how to fix it\n\n* Address review comments\n\n* add tests for (un)authn'd REST and WebSocket handlers\n\n* Restore old import for 1.x compat, remove a log\n\n* handle advertised jupyter-server 1.x version\n\n* Lint (isort any mypy)\n\n* More tests for paths\n\n---------\n\nCo-authored-by: Nicholas Bollweg <nick.bollweg@gmail.com>", "commit": "https://github.com/jupyter-lsp/jupyterlab-lsp/commit/4ad12f204ad0b85580fc32137c647baaff044e95", "report_link": "https://github.com/advisories/GHSA-4qhp-652w-c22x", "description": "### Impact\nInstallations of jupyter-lsp running in environments without configured file system access control (on the operating system level), and with jupyter-server instances exposed to non-trusted network are vulnerable to unauthorised access and modification of file system beyond the jupyter root directory.\n\n### Patches\nVersion 2.2.2 has been patched.\n\n### Workarounds\nUsers of jupyterlab who do not use jupyterlab-lsp can uninstall jupyter-lsp.\n\n### Credits\nWe would like to credit Bary Levy, researcher of pillar.security research team, for the discovery and responsible disclosure of this vulnerability.\n\nEdit: based on advice from pillar.security the Confidentiality/Integrity/Availability were increased to High to reflect potential for critical impact on publicly hosted jupyter-server instances lacking isolation of user privileges on operating system level (for best practices please consult https://jupyterhub.readthedocs.io/en/stable/explanation/websecurity.html#protect-users-from-each-other) and CWE-94 was added due to a potential vulnerability chaining in specific environments."}
    ```
    '''
    example_3_answer = '''
    Based on the details provided, it is clear that the "load_jupyter_server_extension" function is being altered in a patch designed to mitigate a security vulnerability within the "jupyterlab-lsp" project. From the notes and the code, this vulnerability pertained to unauthorized access and modification of the file system beyond the Jupyter root directory.

The function changes present are only dealing with how the system gets the current `io_loop`. In the after code, a conditional block has been added to ensure compatibility with different versions of the jupyter server system.

From the commit message and the other details provided, it can be inferred that this function is an irrelevant refactoring change.

So, based on the evidence, it appears that the changed function is not vulnerable and is not relevant to this specific vulnerability.

```
{'answer': 3}
```
    '''


    # assistant = client.beta.assistants.create(
    #     name="Math Tutor",
    #     instructions="You are a personal math tutor. Write and run code to answer math questions.",
    #     tools=[{"type": "code_interpreter"}],
    #     model="gpt-4o",
    # )
    # content = f"Given the following related information, can you tell the changed function is relevant " \
    #           f"to the vulnerability that the commit is trying to fix? " \
    #           f"Please answer YES if the function is vulnerable, and NO if the function " \
    #           f"is just changed to ensure consistency of the fix (but not vulnerable) or " \
    #           f"is a totally irrelevant update. " \
    #           f"An example of 'NO' is:\n```\n{json_str}\n```\n" \
    #           f"Answer only in YES/NO.\n```\n{json_str}\n```\n"
    # content = f"Given the following related information, can you tell the changed function is relevant " \
    #           f"to the vulnerability that the commit is trying to fix? " \
    #           f"Please answer YES if the function is vulnerable, and NO if the function " \
    #           f"is just changed to ensure consistency of the fix (but not vulnerable) or " \
    #           f"is a totally irrelevant update. " \
    #           f"An example of 'NO' is:\n```\n{json_str}\n```\n" \
    #           f"Answer only in YES/NO.\n```\n{json_str}\n```\n"
    content = f"Given the following related information, can you tell if the changed function is relevant " \
              f"to the vulnerability that the commit is trying to fix?" \
              f"Please answer 1 if the function is vulnerable, 2 if the function " + \
              f"is changed to ensure consistency of the fix (but not vulnerable), " + \
              f"3 if the function is totally irrelevant, and 4 if you are unsure. " +\
              "Please reason before you answer. But in the end, answer in json format like {'answer':1}" +\
              f"\n```\n{json_str}\n```\n"
    # content = f"Given the following GitHub commit link and related vulnerability report (use the browser tool to visit the links provided), " \
    #           f"can you tell if the changed function {target_function} is relevant to the vulnerability that the commit is trying to fix? " \
    #           f"Please answer 1 if the function is vulnerable, 2 if the function is changed to ensure consistency of the fix (but not vulnerable)" \
    #           f" and 3 if the function is totally irrelevant, 4 if you are unsure." \
    #           f"to the vulnerability that the commit is trying to fix? Please only give me answer after you have visited the links and take your time." \
    #           f"\n```\n{json_str}\n```\n"

    # content = f"Can you open and summarize the following GitHub commit link and related vulnerability report? " \
    #           f"(use the browser tool open_url())" \
    #           f"\n```{json_str}"
    prepared_messages = [{"role": "system", "content": '''
        You are a GPT GPT-4 architecture, based on the GPT-4 architecture.
Knowledge cutoff: 2023-09
Current date: 2024-09-05

Image input capabilities: Enabled
        '''},
                         {"role": "user", "content": example_1},
                         {"role": "assistant", "content": example_1_answer},
                         {"role": "user", "content": example_2},
                         {"role": "assistant", "content": example_2_answer},
                         {"role": "user", "content": example_3},
                         {"role": "assistant", "content": example_3_answer},
                  {"role": "user", "content": content}]
    # print("len desciprtion")
    # description_len = len(line["description"])
    # print(description_len)
    # print("len other function")
    # of_len = len(str(line["other_changed_function_in_the_commit"]))
    # print(of_len)
    # des_lens.append(description_len)
    # of_lens.append(of_len)
    # overall_len = len(content)
    # overall_lens.append(overall_len)

    one_line = {"custom_id": str(i), "method": "POST", "url": "/v1/chat/completions", "body": {
        "model": "gpt-4",
        "messages": prepared_messages,
        "temperature": 0
    }}
    json_list.append(one_line)
    # try:
    #     completion = client.chat.completions.create(
    #         model="gpt-4",
    #         messages=prepared_messages,
    #         temperature=0
    #     )
    #
    #     prediction = completion.choices[0].message.content
    #     answer_list[i]=prediction
    #     print(content)
    #     print(prediction)
    #     with open("gpt_filtered.out", "a") as f:
    #         f.write(str(i) + "\n")
    #         f.write("---------------------------" + "\n")
    #         f.write(line["commit"]+ "\n")
    #         f.write(target_function + "\n")
    #         f.write("---------------------------" + "\n")
    #         f.write(content + "\n")
    #         f.write("---------------------------" + "\n")
    #         f.write(prediction + "\n")
    #         f.write("+++++++++++++++++++++++++++" + "\n")
    # except Exception as e:
    #     print("exceed")
    #     exceed+=1
    #     with open("exceed_cases.out", "a") as f:
    #         f.write(str(i) + "\n")
    #         f.write("---------------------------" + "\n")
    #         f.write(line["commit"] + "\n")
    #         f.write(target_function + "\n")
    #         f.write("---------------------------" + "\n")
    #         f.write(content + "\n")
    #         f.write("+++++++++++++++++++++++++++" + "\n")
    # prepared_messages.append(completion.choices[0].message)
    # prepared_messages.append({"role": "user", "content": "Continue and give me an answer"})
    # completion = client.chat.completions.create(
    #     model="gpt-4",
    #     messages=prepared_messages
    # )
    # prediction = completion.choices[0].message.content
    # print(prediction)

# print(f"max des lens{max(des_lens)}")
# print(f"max of lens{max(of_lens)}")
# print(f"max overall lens{max(overall_lens)}")

print(len(json_list))
#
# print(exceed)

batch_file_name = "batch_v2_new.jsonl"
with open(batch_file_name,"w") as f:
    for l in json_list:
        f.write(json.dumps(l)+"\n")
#
# batch_input_file = client.files.create(
#   file=open(batch_file_name, "rb"),
#   purpose="batch"
# )
#
# batch_input_file_id = batch_input_file.id
#
# batch_info = client.batches.create(
#     input_file_id=batch_input_file_id,
#     endpoint="/v1/chat/completions",
#     completion_window="24h",
#     metadata={
#       "description": "test3"
#     }
# )
#
# print(batch_info)


# file_response = client.files.content("file-WEc9DsGjZP9jIzoOS70EtLMw")
# print(file_response.text)
# with open("test_without_des.out", "w") as f:
#     f.write(file_response.text)
#
#
# file_response = client.files.content("file-qlyj7k1TK6s677qqFp401y0s")
# print(file_response.text)
# with open("test_with_des.out", "w") as f:
#     f.write(file_response.text)

exit()
print(len(hash_dic))
import random


with open("commits_id_dic.json", "r") as f:
    commit_cwe_dict = json.load(f)



c_lvl = "label_dataset/our(py)_commit_lv.out"

lines = []
for commit_row in random.choices(list(hash_dic.values()),k=250):
    hash = commit_row["hash"]

    repo_url = commit_row["repo_url"][:-4]
    c = repo_url + "/commit/" + hash
    if c in commit_cwe_dict:
        report = commit_cwe_dict[c]
    else:
        continue
    lines.append(json.dumps({"commit":c,"report":report}))
    # print(c)
print(1)
print(len(lines))
# with open(c_lvl,"w") as f:
#     for line in lines[:218]:
#         f.write(line+"\n")

f_lvl = "label_dataset/our(py)_function_lv.out"
new_lines = []
# for line in random.choices(new_dic,k=320):
for line in new_dic:
    c = line["commit"]
    if c in commit_cwe_dict:
        report = commit_cwe_dict[c]
    else:
        continue
    line["report"] = report
    new_lines.append(json.dumps(line))
print(2)
# print(len(new_lines))
# with open(f_lvl,"w") as f:
#     for line in new_lines[:269]:
#         f.write(line+"\n")
