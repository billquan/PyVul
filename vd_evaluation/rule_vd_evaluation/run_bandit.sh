#!/usr/bin/env bash

task(){
    echo "$1"
    counter=0
    if [ -f "/home/sdb/haowei/vul/bandit_runs_latest/$2.out" ]; then
        echo "Existed"
    elif [ -z "$(ls -A $1)" ]; then
        echo "Empty"
    else

        bandit -r "$1" > "./bandit_runs_latest/$2.out" || true
    fi


}

# initialize a semaphore with a given number of tokens
open_sem(){
    mkfifo pipe-$$
    exec 3<>pipe-$$
    rm pipe-$$
    local i=$1
    for((;i>0;i--)); do
        printf %s 000 >&3
    done
}

# run the given command asynchronously and pop/push tokens
run_with_lock(){
    local x
    # this read waits until there is something to read
    read -u 3 -n 3 x && ((0==x)) || exit $x
    (
     ( "$@"; )
    # push the return code of the command to the semaphore
    printf '%.3d' $? >&3
    )&
}

echo "hey"
N=1
open_sem $N
counter_tot=0
source ~/.venvs/pysa/bin/activate
for d in /home/sdb/haowei/vul/repo_snapshots_latest/*/; do
    full_name="$d"
    echo "$d"
    name=$(basename $d)
    echo "$name"
    counter_tot=$((counter_tot+1))
    echo "repo $counter_tot"
    if [[ $counter_tot -ge 0 ]];then
        run_with_lock task "/home/sdb/haowei/vul/repo_snapshots_latest/$name" $name
    fi
    if [[ $counter_tot -ge 1000 ]];then
            break
    fi
done

