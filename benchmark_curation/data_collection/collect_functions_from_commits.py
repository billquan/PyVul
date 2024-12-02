import ast
import os
import re
import uuid

# import pandas as pd
# import configuration as cf
from guesslang import Guess
from pydriller import Repository

'''
Part of the script comes from CVEFixes (https://github.com/secureIT-project/CVEfixes)
'''


os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

fixes_columns = [
    'cve_id',
    'hash',
    'repo_url',
]

commit_columns = [
    'hash',
    'repo_url',
    'author',
    'author_date',
    'author_timezone',
    'committer',
    'committer_date',
    'committer_timezone',
    'msg',
    'merge',
    'parents',
    'num_lines_added',
    'num_lines_deleted',
    'dmm_unit_complexity',
    'dmm_unit_interfacing',
    'dmm_unit_size'
]

file_columns = [
    'file_change_id',
    'hash',
    'filename',
    'old_path',
    'new_path',
    'change_type',
    'diff',
    'diff_parsed',
    'num_lines_added',
    'num_lines_deleted',
    'code_after',
    'code_before',
    'nloc',
    'complexity',
    'token_count',
    'programming_language'
]

method_columns = [
    'method_change_id',
    'file_change_id',
    'name',
    'signature',
    'parameters',
    'start_line',
    'end_line',
    'code',
    'nloc',
    'complexity',
    'token_count',
    'top_nesting_level',
    'before_change',
]


# def extract_project_links(df_master):
#     """
#     extracts all the reference urls from CVE records that match to the repo commit urls
#     """
#     # df_fixes = pd.DataFrame(columns=fixes_columns)
#     git_url = r'(((?P<repo>(https|http):\/\/(bitbucket|github|gitlab)\.(org|com)\/(?P<owner>[^\/]+)\/(?P<project>[^\/]*))\/(commit|commits)\/(?P<hash>\w+)#?)+)'
#     print('-' * 70)
#     print('Extracting all reference URLs from CVEs...')
#     for i in range(len(df_master)):
#         ref_list = ast.literal_eval(df_master['reference_json'].iloc[i])
#         if len(ref_list) > 0:
#             for ref in ref_list:
#                 url = dict(ref)['url']
#                 link = re.search(git_url, url)
#                 if link:
#                     row = {
#                         'cve_id': df_master['cve_id'][i],
#                         'hash': link.group('hash'),
#                         'repo_url': link.group('repo').replace(r'http:', r'https:')
#                     }
#                     df_fixes = df_fixes.append(pd.Series(row), ignore_index=True)
#
#     # df_fixes = df_fixes.drop_duplicates().reset_index(drop=True)
#     # print(f'Found {len(df_fixes)} references to vulnerability fixing commits')
#     return df_fixes


def guess_pl(code):
    """
    :returns guessed programming language of the code
    """
    if code:
        return Guess().language_name(code.strip())
    else:
        return 'unknown'


def clean_string(signature):
    return signature.strip().replace(' ', '')


def get_method_code(source_code, start_line, end_line):
    try:
        if source_code is not None:
            code = ('\n'.join(source_code.split('\n')[int(start_line) - 1: int(end_line)+1]))
            return code
        else:
            return None
    except Exception as e:
        print(f'Problem while extracting method code from the changed file contents: {e}')
        pass
from difflib import SequenceMatcher

def changed_methods_both(file):
    """
    Return the list of methods that were changed.
    :return: list of methods
    """
    new_methods = file.methods
    old_methods = file.methods_before
    # print(new_methods)
    # print(old_methods)
    added = file.diff_parsed["added"]
    # print(added)
    deleted = file.diff_parsed["deleted"]
    # print(deleted)

    methods_changed_new = {
        y
        for x in added
        for y in new_methods
        if y.start_line <= x[0] <= y.end_line
    }
    methods_changed_old = {
        y
        for x in deleted
        for y in old_methods
        if y.start_line <= x[0] <= y.end_line
    }
    coun = {}
    for md in methods_changed_old:
        # print(md.start_line)
        # print(md.end_line)
        for i in range(md.start_line,md.end_line+1,1):
            coun[i] = md
    for x in deleted:
        if x[0] in coun:
            coun.pop(x[0])
    rest = [] # apart from totally removed, rest not totally removed
    for i,v in coun.items():
        if v not in rest:
            rest.append(v)
    mcn_names = []
    for m in methods_changed_new:
        mcn_names.append(m.name)
    for md in rest:
        rest_lines = []
        md_code = get_method_code(file.source_code_before, md.start_line, md.end_line)
        md_lines = md_code.splitlines()
        for i,v in coun.items():
            if id(v) == id(md):
                # if md.name == "run":
                #     print("run")
                #     print(coun)
                #     print(len(md_lines))
                #     print(md.start_line)
                #     print("________-")
                rest_lines.append(md_lines[i-md.start_line])
        if mcn_names.count(md.name)>0:
            choose = None
            for md2 in methods_changed_new:
                if md2.name == md.name:
                    md2_code = get_method_code(file.source_code, md2.start_line, md2.end_line)
                    is_the_one = True
                    for line in rest_lines:
                        if line not in md2_code:
                            is_the_one = False
                    if not len(rest_lines)>0:
                        print("?????")
                    if is_the_one:
                        choose = md2
                        break
            if choose:
                md.pair = choose

        if md.name not in mcn_names:
            high_similar = 0
            choose = None
            for md2 in new_methods:
                if md2.name == md.name:
                    md2_code = get_method_code(file.source_code,md2.start_line,md2.end_line)
                    is_the_one = True
                    for line in rest_lines:
                        if line not in md2_code:
                            is_the_one = False
                    if not len(rest_lines) > 0:
                        print("?????")
                    if is_the_one:
                        choose = md2
                        break
            if choose:
                md.pair = choose
                methods_changed_new = list(methods_changed_new)
                methods_changed_new.append(choose)
                methods_changed_new = set(methods_changed_new)

    coun = {}
    for md in methods_changed_new:
        # print(md.start_line)
        # print(md.end_line)
        for i in range(md.start_line, md.end_line + 1, 1):
            coun[i] = md
    for x in added:
        if x[0] in coun:
            coun.pop(x[0])
    rest = []  # apart from totally removed, rest not totally removed
    for i, v in coun.items():
        if v not in rest:
            rest.append(v)
    mcn_names = []
    for m in methods_changed_old:
        mcn_names.append(m.name)
    for md in rest:
        rest_lines = []
        md_code = get_method_code(file.source_code, md.start_line, md.end_line)
        md_lines = md_code.splitlines()
        for i, v in coun.items():
            if id(v) == id(md):
                # print("run")
                # print(md.name)
                # print(coun)
                # print(len(md_lines))
                # print(md.start_line)
                # print(md_lines[-2])
                # print(md_lines[-1])
                # print("________-")
                # print(md.start_line)
                # print(md.end_line)
                # print(len(md_lines))
                # print(i- md.start_line)
                # for line in md_lines:
                #     print(line)
                rest_lines.append(md_lines[i - md.start_line])
        if md.name not in mcn_names:
            high_similar = 0
            choose = None
            md_code = get_method_code(file.source_code, md.start_line, md.end_line)
            for md2 in old_methods:
                if md2.name == md.name:
                    md2_code = get_method_code(file.source_code_before, md2.start_line, md2.end_line)
                    is_the_one = True
                    for line in rest_lines:
                        if line not in md2_code:
                            is_the_one = False
                    if not len(rest_lines) > 0:
                        print("?????")
                    if is_the_one:
                        choose = md2
            if choose:
                choose.pair = md
                methods_changed_old=list(methods_changed_old)
                methods_changed_old.append(choose)
                methods_changed_old = set(methods_changed_old)




    # print(methods_changed_new)
    # for m in methods_changed_new:
    #     for m2 in old_methods:
    #         if m2.name == m.name and m2 not in methods_changed_old:
    #             methods_changed_old.append(m2)
    #
    # for m in methods_changed_old:
    #     for m2 in new_methods:
    #         if m2.name == m.name and m2 not in methods_changed_new:
    #             methods_changed_new.append(m2)

    return methods_changed_new,methods_changed_old

# --------------------------------------------------------------------------------------------------------
# extracting method_change data
def get_methods(file, file_change_id):
    """
    returns the list of methods in the file.
    """
    file_methods = []
    # try:
    # for mb in file.methods_before:
    #     for mc in file.changed_methods:
    #         #if mc.name == mb.name and mc.name != '(anonymous)':
    #         if clean_string(mc.long_name) == clean_string(mb.long_name) and mc.name != '(anonymous)':



    if file.changed_methods:
        print(file.changed_methods)
        methods_after, methods_before = changed_methods_both(file)  # in source_code_after/_before
        formated_after = {}
        formated_before = {}
        if methods_after:
            for mc in methods_after:
                if file.source_code is not None and mc.name != '(anonymous)':
                    print(mc.name)
                    # changed_method_code = ('\n'.join(file.source_code.split('\n')[int(mc.start_line) - 1: int(mc.end_line)]))
                    changed_method_code = get_method_code(file.source_code, mc.start_line, mc.end_line)
                    changed_method_row = {
                        'method_change_id': uuid.uuid4().fields[-1],
                        'file_change_id': file_change_id,
                        'name': mc.name,
                        'signature': mc.long_name,
                        'parameters': mc.parameters,
                        'start_line': mc.start_line,
                        'end_line': mc.end_line,
                        'code': changed_method_code,
                        'nloc': mc.nloc,
                        'complexity': mc.complexity,
                        'token_count': mc.token_count,
                        'top_nesting_level': mc.top_nesting_level,
                        'before_change': 'False',
                    }
                    file_methods.append(changed_method_row)
                    formated_after[id(mc)]=changed_method_row['method_change_id']

        if methods_before:
            for mb in methods_before:
                print(mb.name)
                # filtering out code not existing, and (anonymous)
                # because lizard API classifies the code part not as a correct function.
                # Since, we did some manual test, (anonymous) function are not function code.
                # They are also not listed in the changed functions.
                if file.source_code_before is not None and mb.name != '(anonymous)':

                    method_before_code = get_method_code(file.source_code_before, mb.start_line, mb.end_line)
                    method_before_row = {
                        'method_change_id': uuid.uuid4().fields[-1],
                        'file_change_id': file_change_id,
                        'name': mb.name,
                        'signature': mb.long_name,
                        'parameters': mb.parameters,
                        'start_line': mb.start_line,
                        'end_line': mb.end_line,
                        'code': method_before_code,
                        'nloc': mb.nloc,
                        'complexity': mb.complexity,
                        'token_count': mb.token_count,
                        'top_nesting_level': mb.top_nesting_level,
                        'before_change': 'True',
                    }
                    if hasattr(mb,"pair"):
                        paird = mb.pair
                        if id(paird) not in formated_after:
                            print("here")
                            print(paird)
                            print(paird.name)
                            print(paird.start_line)
                            print(paird.end_line)
                            for md_line in formated_after:
                                print(md_line)
                                print(md_line.name)
                                print(md_line.start_line)
                                print(md_line.end_line)
                        method_before_row['pair']=formated_after[id(paird)]
                    file_methods.append(method_before_row)



    if file_methods:
        print(len(file_methods))
        for md in file_methods:
            print(md)
        return file_methods
    else:
        return None




# ---------------------------------------------------------------------------------------------------------
# extracting file_change data of each commit
def get_files(commit):
    """
    returns the list of files of the commit.
    """
    commit_files = []
    commit_methods = []

    print(f'Extracting files for {commit.hash}')
    if commit.modified_files:
        for file in commit.modified_files:
            print(f'Processing file {file.filename} in {commit.hash}')
            # programming_language = (file.filename.rsplit(".')[-1] if '.' in file.filename else None)
            programming_language = guess_pl(file.source_code)  # guessing the programming language of fixed code
            file_change_id = uuid.uuid4().fields[-1]

            file_row = {
                'file_change_id': file_change_id,       # filename: primary key
                'hash': commit.hash,                    # hash: foreign key
                'filename': file.filename,
                'old_path': file.old_path,
                'new_path': file.new_path,
                'change_type': str(file.change_type),        # i.e. added, deleted, modified or renamed
                'diff': file.diff,                      # diff of the file as git presents it (e.g. @@xx.. @@)
                'diff_parsed': file.diff_parsed,        # diff parsed in a dict containing added and deleted lines lines
                'num_lines_added': file.added_lines,        # number of lines added
                'num_lines_deleted': file.deleted_lines,    # number of lines removed
                "added":file.diff_parsed["added"],
                "deleted":file.diff_parsed["deleted"],
                'code_after': file.source_code,
                'code_before': file.source_code_before,
                'nloc': file.nloc,
                'complexity': file.complexity,
                'token_count': file.token_count,
                'programming_language': programming_language,
            }
            commit_files.append(file_row)
            file_methods = get_methods(file, file_change_id)

            if file_methods is not None:
                commit_methods.extend(file_methods)
    else:
        print('The list of modified_files is empty')
        with open("merge_commits.txt","a") as f:
            f.write(commit.hash+"\n")

    return commit_files, commit_methods


def extract_commits(repo_url, hash):
    """This function extract git commit information of only the hashes list that were specified in the
    commit URL. All the commit_fields of the corresponding commit have been obtained.
    Every git commit hash can be associated with one or more modified/manipulated files.
    One vulnerability with same hash can be fixed in multiple files so we have created a dataset of modified files
    as 'df_file' of a project.
    :param repo_url: list of url links of all the projects.
    :param hashes: list of hashes of the commits to collect
    :return dataframes: at commit level and file level.
    """
    repo_commits = []
    repo_files = []
    repo_methods = []

    # ----------------------------------------------------------------------------------------------------------------
    # extracting commit-level data
    if 'github' in repo_url:
        repo_url = repo_url + '.git'

    print(f'Extracting commits for {repo_url} with 4 worker(s) looking for the following hashes:{hash}')
    # log_commit_urls(repo_url, hashes)

    # giving first priority to 'single' parameter for single hash because
    # it has been tested that 'single' gets commit information in some cases where 'only_commits' does not,
    # for example: https://github.com/hedgedoc/hedgedoc.git/35b0d39a12aa35f27fba8c1f50b1886706e7efef
    single_hash = hash
    commit_row = None
    try:
        for commit in Repository(path_to_repo=repo_url,
                             only_commits=[hash],
                             single=single_hash,
                             num_workers=4).traverse_commits():
            print(f'Processing {commit.hash}')

            commit_files, commit_methods = get_files(commit)
            commit_row = {
                'hash': commit.hash,
                'repo_url': repo_url,
                'author': commit.author.name,
                'committer': commit.committer.name,
                'msg': commit.msg,
                'merge': commit.merge,
                'parents': commit.parents,
                'num_lines_added': commit.insertions,
                'num_lines_deleted': commit.deletions,
                'commit_files':commit_files,
                'commit_methods':commit_methods
            }

    except Exception as e:
        print(f'Problem while fetching the commits: {e}')
        with open("cvefix_collect1.err","a") as f:
            f.write(repo_url+"/commit/"+hash+"\n")

        pass



    return commit_row

output = "all_vul.json"
# output2 = "all_vul6.json"
#
import json
#

with open("./github_adv_src_links.json","r") as f:
    gh_adv_dic = json.load(f)
# # exit()
commit_rows = []
re_scanned = {}
existing_dic = {}
# for c, row in same_name_dic.items():
#     repo_url = c.split("/commit/")[0]
#     hash = c.split("/commit/")[-1]
#     if c not in re_scanned:
#         commit_row = extract_commits(repo_url, hash)
#         if commit_row:
#             re_scanned[c] = commit_row
#             commit_rows.append(commit_row)
#             with open(output1, "w") as f:
#                 json.dump(commit_rows, f)
#
# for c, row in re_scan_dic.items():
#     repo_url = c.split("/commit/")[0]
#     hash = c.split("/commit/")[-1]
#     if c not in re_scanned:
#         commit_row = extract_commits(repo_url, hash)
#         if commit_row:
#             re_scanned[c] = commit_row
#             commit_rows.append(commit_row)
#             with open(output1, "w") as f:
#                 json.dump(commit_rows, f)

# count = 0
# for c, row in existing_dic.items():
#     if c in re_scan_dic or c in same_name_dic:
#         continue
#     count+=1
#     repo_url = c.split("/commit/")[0]
#     hash = c.split("/commit/")[-1]
#     re_scanned[c] = 1
#
# print(len(re_scanned))


# exit()
# for c, row in re_scanned.items():
#     existing_dic[c] = row
#
# with open(output2, "w") as f:
#     json.dump(list(existing_dic.values()), f)
import json
report_cve_dict = {}

with open("github_advisories.json","r") as f:
    github_cwe_dic = json.load(f)
g_report_dic = {}
for cwe, reports in github_cwe_dic.items():
    for report_v in reports:
        g_report_dic[report_v["html_url"]]=report_v
        report_cve_dict[report_v["html_url"]]=report_v["cve_id"]
max_des_gh = max([len(v["description"]) for i,v in g_report_dic.items()])


commit_cwe_dict = {}
# commit_cwe_dict = existing_dic
for cwe, reports in gh_adv_dic.items():
    for report in reports:
        repo_url = report["repo_link"]
        src_links = report["src_links"]
        id = report["id"]
        for link in src_links:
            hash = link.split("/commit/")[-1]
            repo_url = link.split("/commit/")[0]
            if link in existing_dic:
                print("exist")
                commit_row = existing_dic[link]
            else:
                print("not exist")
                commit_row = extract_commits(repo_url,hash)
            if commit_row:
                report_link = "https://github.com/advisories/"+id
                if report_link in g_report_dic:
                    description = g_report_dic[report_link]["description"]
                else:
                    description = ""
                commit_row["report_link"] = report_link
                if not "description" in commit_row:
                    commit_row["description"] = description
                commit_rows.append(commit_row)
                with open(output, "w") as f:
                    json.dump(commit_rows, f)
            commit_cwe_dict[repo_url+"/commit/"+hash] = cwe


# huntr data
with open("huntr_reports_with_src","r") as f:
    huntr_dic = json.load(f)

for report_link, v in huntr_dic.items():
    report_cve_dict[report_link] = v["cve"]

max_des_huntr = max([len(v["description"]) for i,v in huntr_dic.items()])

with open("huntr_reports2","r") as f:
    dic = json.load(f)

print(len(dic))
cwe_dic = {}
for k,v in dic.items():
    cwe = v["cwe"].split(":")[0]
    # if cwe not in gh_adv_dic:
    #     print(cwe)
    #     continue
    fix_commit = v["fix_commit"]
    repo_url = v["repo_link"]
    hash = fix_commit.split("/commit/")[-1]

    if fix_commit in existing_dic:
        print("exist")
        commit_row = existing_dic[fix_commit]
    else:
        print("not exist")
        commit_row = extract_commits(repo_url, hash)
    if commit_row:
        if k in huntr_dic:
            description = huntr_dic[k]["description"]
        else:
            description = ""
        commit_row["report_link"] = k
        if not "description" in commit_row:
            commit_row["description"] = description
        commit_rows.append(commit_row)
        with open(output, "w") as f:
            json.dump(commit_rows, f)
    commit_cwe_dict[repo_url + "/commit/" + hash] = cwe


with open("snyk_reports_with_src","r") as f:
    dic = json.load(f)

for report_link, v in dic.items():
    report_cve_dict[report_link] = v["cve"]


# print(len(dic))
for id,v in dic.items():
    cwe = v["cwe"].split(":")[0]
    # if cwe not in gh_adv_dic:
    #     print(cwe)
    #     continue
    refs = v["refs"]
    description = v["description"]
    for ref in refs:
        repo_url = ref.split("/commit/")[0]
        hash = ref.split("/commit/")[-1]
        if ref in existing_dic:
            print("exist")
            commit_row = existing_dic[ref]
        else:
            print("not exist")
            commit_row = extract_commits(repo_url, hash)
        if commit_row:
            commit_row["report_link"] = id
            if not "description" in commit_row:
                commit_row["description"] = description
            commit_rows.append(commit_row)
            with open(output, "w") as f:
                json.dump(commit_rows, f)
        commit_cwe_dict[repo_url + "/commit/" + hash] = cwe


# for commit in commit_cwe_dict:
#     print(commit)
# print(len(commit_cwe_dict))
with open("report_cve_dic_all.json", "w") as f:
    json.dump(report_cve_dict, f)