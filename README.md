# "An Empirical Study of Vulnerabilities in Python Packages and Their Detection"


## Organization
Below is the detailed content of this repository
```
.
├── dataset................................ PyVul benchmark
│   ├── finetune_data...................... the data used for finetuning in RQ4.
│   ├── commit_level_dataset.out........... the commit level PyVul, use the reproduction script to download the repo snapshots
│   └── function_level_dataset.out......... the function level PyVul
│   
├── benchmark_curation..................... how is PyVul created
│   ├── data_collection.................... used to collect data
│       ├── clone_checkout_commit.py....... scripts used to reproduce vulnerable repo snapshots, i.e. the commit-level PyVul.
│       ├── collect_functions_from_commits.py. scripts used to extract functions from the fixing commits.
│       ├── get_git_advisories.py.......... scripts used to get GitHub Adviosry reports.
│       ├── huntr_spider.py................ scripts used to get Huntr reports.
│       └── snyk_spider_for_src.py......... scripts used to get Snyk reports.
│   └── data_cleansing..................... used to collect importance scores from the models.
│       ├── gpt_cleansing.py............... use GPT to cleanse the function-level PyVul.
│       └── read_chatgpt_filter_results.py. process GPT results.
│
├── vd_evaluation.......................... evaluation of SOTA vuln detectors
│   ├── ml_vd_evaluation................... scripts used to evaluate ml-based detectors
│       ├── finetune....................... scripts used to finetune LLMs and evaluate them
│          ├── openai_binary.py............ finetune OpenAI models, Table 6
│          ├── openai_bycwe_binary.py...... finetune OpenAI models, Table 7
│          └── eval_openai.py.............. Evaluate the fine-tuned models
│       └── zeroshot....................... scripts used to evaluate LLMs under zero-shot setting.
│          ├── zero_shot.py................ Evaluate OpenAI models in zero-shot setting.
│          └── zero_shot_codeqwen.py....... Evaluate CodeQwen in zero-shot setting.
│   └── rule_vd_evaluation................. scripts used to run rule-based detectors and evaluate them
│       ├── run_codeql.sh.................. run CodeQL
│       ├── run_pysa.sh.................... run PySA
│       ├── run_bandit.sh.................. run Bandit
│       ├── check_codeql_results.py........ evaluate CodeQL
│       ├── check_pysa_results.py.......... evaluate PySA
│       └── check_bandit_results.py........ evaluate Bandit
```
