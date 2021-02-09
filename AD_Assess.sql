--# Active Directory Audit (ADA) ETL SCHEMA - Copyright @2018 All Rights Reserved
--# Updated by Shane D. Shook 
--# version="20210209"

-- The Process of Creation should be as follows:
-- 1. Import the "AD_Usersview.csv", "AD_Groupmembersview.csv", and "AD_Computersview.csv" files into sqlitedb
-- 2. Execute the following to produce AD_Statistics from those tables

-- Create Analytical Results
-- ACTIVE DIRECTORY STATISTICS
CREATE TABLE if not exists ad_stats ("AuditDate" text, "Description" text, "Result" text, "Stat" text);
INSERT INTO ad_stats select date('now') as AuditDate, "User Accounts", (select count(distinct(samaccountname)) from ad_usersview where enabled like 'True'), " ";
INSERT INTO ad_stats select date('now') as AuditDate, "Groups", (select count(distinct(groupname)) from ad_groupmembersview), " ";
INSERT INTO ad_stats select date('now') as AuditDate, "Accounts with Expired Passwords", (select count(distinct(samaccountname)) from ad_usersview where ((passwordexpired like 'true') and (enabled like 'true'))), " ";
INSERT INTO ad_stats select date('now') as AuditDate, "Accounts with no Group Membership", (select count(distinct(samaccountname)) from ad_usersview where ((enabled like 'true') and (distinguishedname not like '%ou=%'))), " ";
INSERT INTO ad_stats select date('now') as AuditDate, "Number of Admin Groups", (select count(distinct(groupname)) from ad_groupmembersview where groupname like '%admin%'), " ";
INSERT INTO ad_stats select date('now') as AuditDate, "Accounts Belonging to Admin Groups", (select count(distinct(u.samaccountname)) from ad_usersview u, ad_groupmembersview g where ((u.enabled like 'true') and (u.samaccountname = g.username) and (g.groupname like '%admin%'))), " ";
INSERT INTO ad_stats select date('now') as AuditDate, "Admin Accounts with Old Passwords", (select count(distinct(u.samaccountname)) from ad_usersview u, ad_groupmembersview g where ((u.enabled like 'true') and (u.samaccountname = g.username) and (g.groupname like '%admin%') and (datetime(substr(u.passwordlastset,1,11),'unixepoch') < date('now','-90 days')) and (u.passwordlastset not like ''))), " ";
INSERT INTO ad_stats select date('now') as AuditDate, "Stale User Accounts", (select count(distinct(samaccountname)) from ad_usersview where ((enabled like 'true') and (datetime(substr(lastlogontimestamp,1,11),'unixepoch','-369 years') < date('now','-90 days')))), " "; 
INSERT INTO ad_stats select date('now') as AuditDate, "Accounts with Passwords that Never Expire", (select count(distinct(samaccountname)) from ad_usersview where ((enabled like 'true') and (passwordneverexpires like "True"))), " ";
update ad_stats set stat = (select round(sum(((select result from ad_stats where description = 'Accounts with Expired Passwords')*1.00/(select result from ad_stats where description = 'User Accounts'))*100),2)) where description = 'Accounts with Expired Passwords';
update ad_stats set stat = (select round(sum(((select result from ad_stats where description = 'Accounts with no Group Membership')*1.00/(select result from ad_stats where description = 'User Accounts'))*100),2)) where description = 'Accounts with no Group Membership';
update ad_stats set stat = (select round(sum(((select result from ad_stats where description = 'Number of Admin Groups')*1.00/(select result from ad_stats where description = 'Groups'))*100),2)) where description = 'Number of Admin Groups';
update ad_stats set stat = (select round(sum(((select result from ad_stats where description = 'Accounts Belonging to Admin Groups')*1.00/(select result from ad_stats where description = 'User Accounts'))*100),2)) where description = 'Accounts Belonging to Admin Groups';
update ad_stats set stat = (select round(sum(((select result from ad_stats where description = 'Admin Accounts with Old Passwords')*1.00/(select result from ad_stats where description = 'User Accounts'))*100),2)) where description = 'Admin Accounts with Old Passwords';
update ad_stats set stat = (select round(sum(((select result from ad_stats where description = 'Stale User Accounts')*1.00/(select result from ad_stats where description = 'User Accounts'))*100),2)) where description = 'Stale User Accounts';
update ad_stats set stat = (select round(sum(((select result from ad_stats where description = 'Accounts with Passwords that Never Expire')*1.00/(select result from ad_stats where description = 'User Accounts'))*100),2)) where description = 'Accounts with Passwords that Never Expire';



