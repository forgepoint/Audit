# GhostBusters Cyber Risk Assessment 
## Copyright (c)2020, All Rights Reserved 

The Cyber Risk Assessment leverages native Operating System capabilities to collect information that represents exigent and hygiene risks in the configuration and use of servers, workstations, and laptops/tablets that organizational processes depend upon.

By collecting simple information with precise articulation of requisite metadata from active and scheduled processes, network configuration and activity, services build details, and user activity history and rights - from a representative population of the managed estate, statistical analysis of the results can be performed.  Comparing findings by organizational function or groupings (endpoint, user, geography, subnet, or etc.) enables impact analysis of identified (exigent and hygiene) risks.

Unlike traditional assessments that are based on executive questionnaires, or vulnerability assessments that focus upon "risk vectors" (of network, identity, or endpoint), the Cyber Risk Assessment produces evidence from the collected information that can be used to substantiate security posture & program status - and plan for improvement of factors that relate to the dependency of organizational processes upon related systems.

The Cyber Risk Assessment is intended to produce a baseline from evidence, of operational risk in context (exigent/hygiene factor(s) x impact).

The process is simple:

1) Copy the requisite script to each endpoint (server, desktop, laptop) to be evaluated and execute with administrative rights.  

2) Collect the resulting zip file output from each endpoint.

3) Provide the zip files for analysis.


  Note1: The AD script needs only to run from one endpoint against the domain controller, if the domain has several DC's then each should be addressed by the script for complete results.

  Note2: AD GPO logon scripts with scheduled tasks to execute the collection script and to retrieve the results are often best in flexible work hours environments.


### Updated by Shane D. Shook @07/28/2020
