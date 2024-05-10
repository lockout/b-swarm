#!/bin/bash

image_name=`cat ../secrets/imagename.var`
service_account=`cat ../secrets/serviceaccount.var`
project_name=`cat ../secrets/projectname.var`
label=`cat ../secrets/label.var`
max_retries="1" 
task_timeout="18h"
env_secrets="../secrets/secrets.yml"
cpu="1"
ram="2Gi"
job_counter=0
sleep_time=30

while read region
do
    job_rnd=`head -c 500 /dev/urandom | tr -dc 'a-z0-9' | fold -w 4 | head -n 1`
    job_name="bb-harvester-job-${job_counter}-${job_rnd}"
    echo -e "\n$(tput setaf 10)[*] $(tput setaf 6)${job_name}@${region}\n"
    jq --arg value ${region} '.connector.ip_region = $value' profile.json | sponge profile.json
    echo -en "\033[0;90m"
    gcloud run jobs create ${job_name} \
        --service-account=${service_account} \
	--project=${project_name} \
        --image=${image_name} \
        --labels=${label} \
        --max-retries=${max_retries} \
        --task-timeout=${task_timeout} \
        --region=${region} \
        --env-vars-file=${env_secrets} \
        --execute-now \
        --cpu=${cpu} --memory=${ram} \
        --command="/harvester/harvester.py"
    echo -en "\033[0m"
    ((job_counter = job_counter +1))
    sleep ${sleep_time}
done < gcloud.global
