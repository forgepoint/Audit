--# Audit Cyber Compromise Audit (CCA) ETL SCHEMA - Copyright @2018 All Rights Reserved
--# Updated by Shane D. Shook 
--# version="20200507"

-- The Process of Creation should be as follows:
-- 1. Setup the database for ETL and Load data into Primary tables
-- 2. Create Secondary tables from the Primaries
-- 3. Extract meaning from the Secondary and Primary tables
-- 4. Transform the meaning into context by joining with AMDB and Threat Intel sources for risk reporting

-- SECTION 1 Load Data
CREATE TABLE IF NOT EXISTS osinfo ("Computername" text, "AuditDate" text, "ProductName" text, "CSDVersion" text, "CurrentVersion" text, "CurrentBuild" text, "BuildLabEx" text);
CREATE TABLE IF NOT EXISTS allprofiles ("Computername" text,"AuditDate" text,"Name" text,"Length" text,"DirectoryName" text,"CreationTime" text,"LastWriteTime" text,"ProductVersion" text,"FileVersion" text,"Description" text);
CREATE TABLE IF NOT EXISTS allusers ("Computername" text,"AuditDate" text, "UserName" text, "LastLogin" text, "Enabled" text, "Groups" text);
CREATE TABLE IF NOT EXISTS amcache ("Computername" text,"AuditDate" text,"Command" text,"Path" text,"LastMod" text);
CREATE TABLE IF NOT EXISTS dnscache ("Computername" text,"AuditDate" text,"dns" text);
CREATE TABLE IF NOT EXISTS netstat ("Computername" text,"AuditDate" text,"Protocol" text,"LocalAddress" text,"Localport" text,"RemoteAddress" text,"Remoteport" text,"State" text,"PID" text,"ProcessName" text);
CREATE TABLE IF NOT EXISTS nic ("ComputerName" text,"AuditDate" text,"description" text,"macaddress" text,"IPaddress" text,"IPsubnet" text,"DefaultIPGateway" text,"dhcpenabled" text,"DHCPserver" text,"DNS Server" text);
CREATE TABLE IF NOT EXISTS prefetch ("Computername" text,"AuditDate" text,"Name" text,"Length" text,"DirectoryName" text,"CreationTime" text,"LastWriteTime" text,"ProductVersion" text,"FileVersion" text,"Description" text);
CREATE TABLE IF NOT EXISTS processes ("Computername" text,"AuditDate" text,"name" text,"processid" text,"Path" text,"commandline" text);
CREATE TABLE IF NOT EXISTS secsvcstart ("Computername" text,"AuditDate" text,"EventID" text,"TimeGenerated" text,"UserName" text,"UserDomain" text,"ServiceName" text,"FileName" text,"StartType" text,"ServiceAccount" text);
CREATE TABLE IF NOT EXISTS servicedlls ("Computername" text,"AuditDate" text,"ServiceName" text,"ControlSet" text,"ServiceDll" text);
CREATE TABLE IF NOT EXISTS services ("Computername" text,"AuditDate" text,"ControlSet" text,"ServiceName" text,"ImagePath" text);
CREATE TABLE IF NOT EXISTS startups ("Computername" text,"AuditDate" text,"Name" text,"Command" text,"Location" text,"User" text);
CREATE TABLE IF NOT EXISTS syssvcstart ("ComputerName" text,"AuditDate" text,"EventID" text,"TimeGenerated" text,"UserName" text,"ServiceName" text,"FileName" text,"ServiceType" text,"ServiceStartType" text);
CREATE TABLE IF NOT EXISTS tasks ("ComputerName" text,"AuditDate" text,"Name" text,"Status" text,"LastRunTime" text,"NextRunTime" text,"Actions" text,"Enabled" text,"Author" text,"Description" text,"RunAs" text,"Created" text);
CREATE TABLE IF NOT EXISTS usbdev ("Computername" text,"AuditDate" text,"HardwareiD" text,"SerialNo" text,"Class" text,"Service" text);
CREATE TABLE IF NOT EXISTS usbsn ("Computername" text,"AuditDate" text,"FriendlyName" text,"ProductName" text,"SerialNo" text);
CREATE TABLE IF NOT EXISTS usbstorage ("Computername" text,"AuditDate" text,"FileNme" text,"FSName" text,"FileSize" text,"Name" text,"Target" text,"creationdate" text,"lastaccessed" text,"lastmodified" text);
CREATE TABLE IF NOT EXISTS remotelogons ("Computername" text,"AuditDate" text,"EventID" text,"EventTime" text,"UserName" text,"Domain" text,"WorkstationName" text,"IpAddress" text,"SourcePort" text,"LogonType" text,"LoginProcessName" text,"ProcessName" text);
CREATE TABLE IF NOT EXISTS allfiles ("Computername" text,"AuditDate" text,"Name" text,"Length" text,"DirectoryName" text,"CreationTime" text,"LastWriteTime" text,"ProductVersion" text,"FileVersion" text,"Description" text);
CREATE TABLE IF NOT EXISTS geoip ("ip" text, "cc" text, "country" text, "sc" text, "state" text, "city" text, "zip" text, "timezone" text, "lat" real, "long" real, "metro" text);
CREATE TABLE IF NOT EXISTS allusersreg ("Computername" text, "AuditDate" text, "AccountType" text, "Caption" text, "Domain" text, "SID" text, "FullName" text, "Name" text);
CREATE TABLE IF NOT EXISTS allprofilesreg ("Computername" text, "AuditDate" text, "SID" text, "PSChildName" text, "ProfileImagePath" text);
CREATE TABLE IF NOT EXISTS asn ("ip" text, "asn" text, "class" text, "owner" text);
-- Import Data into Tables 
.separator ","
.bail off
.import allfiles.csv allfiles
.import allprofiles.csv allprofiles
.import allusers.csv allusers
.import allusers_reg.csv allusersreg
.import amcache.csv amcache
.import dnscache.csv dnscache
.import geoip.csv geoip
.import netstat.csv netstat
.import nic.csv nic
.import osinfo.csv osinfo
.import prefetch.csv prefetch
.import processes.csv processes
.import remotelogons.csv remotelogons
.import secsvcstart.csv secsvcstart
.import servicedlls.csv servicedlls
.import services.csv services
.import startups.csv startups
.import syssvcstart.csv syssvcstart
.import tasks.csv tasks
.import usbdev.csv usbdev
.import usbsn.csv usbsn
.import usbstorage.csv usbstorage
.import allprofiles_reg.csv allprofilesreg
.import asn.csv asn
 -- Delete unused space from tables to avoid miscounts
delete from osinfo where computername like '%computername%';
delete from allprofiles where computername like '%computername%';
delete from allusers where computername like '%computername%';
delete from amcache where computername like '%computername%';
delete from dnscache where computername like '%computername%';
delete from netstat where computername like '%computername%';
delete from nic where computername like '%computer name%';
delete from prefetch where computername like '%computername%';
delete from processes where computername like '%computername%';
delete from secsvcstart where computername like '%computername%';
delete from servicedlls where computername like '%computername%';
delete from services where computername like '%computername%';
delete from startups where computername like '%computername%';
delete from syssvcstart where computername like '%computername%';
delete from tasks where computername like '%computername%';
delete from usbdev where computername like '%computername%';
delete from usbsn where computername like '%computername%';
delete from allprofilesreg where computername like '%computername%';
delete from usbstorage where computername like '%computername%';
delete from nic where macaddress like '';
delete FROM amcache WHERE command not GLOB '*[0-9,a-z,A-Z]*';
delete from amcache where path not GLOB '*[0-9,a-z,A-Z]*';
delete from remotelogons where computername like '%computername%';
delete from allfiles where computername like '%computername%';
delete from allusersreg where computername like '%computername%';
delete from geoip where ip like '%ip%';
delete from asn where ip like '%error%';

-- SECTION 2 Analyze data
---Inventory
create table inventory as select computername, data from 
(select distinct computername, 'allfiles' as data from allfiles
 union 
select distinct computername, 'allprofiles' as data from allprofiles
 union 
select distinct computername, 'allusers' as data from allusers
 union 
select distinct computername, 'allusersreg' as data from allusersreg
 union 
select distinct computername, 'amcache' as data from amcache
 union 
select distinct computername, 'dnscache' as data from dnscache
 union 
select distinct computername, 'netstat' as data from netstat
 union 
select distinct computername, 'nic' as data from nic
 union 
select distinct computername, 'osinfo' as data from osinfo
 union 
select distinct computername, 'prefetch' as data from prefetch
 union 
select distinct computername, 'processes' as data from processes
 union 
select distinct computername, 'remotelogons' as data from remotelogons
 union 
select distinct computername, 'secsvcstart' as data from secsvcstart
 union 
select distinct computername, 'servicedlls' as data from servicedlls
 union 
select distinct computername, 'services' as data from services
 union 
select distinct computername, 'startups' as data from startups
 union 
select distinct computername, 'syssvcstart' as data from syssvcstart
 union 
select distinct computername, 'tasks' as data from tasks
 union 
select distinct computername, 'usbdev' as data from usbdev
 union 
select distinct computername, 'usbsn' as data from usbsn
 union 
select distinct computername, 'usbstorage' as data from usbstorage);
--Data Quality for Analysis
create table dataquality as 
select data, count(distinct computername) as computers 
from inventory
group by data 
order by computers;
---Assets
create table assets as select distinct computername from inventory;
---AMDB

--Programs Data
create table exe as select * from allfiles where name like '%.exe';
create table sam as select * from exe where directoryname like '%:\program%' and directoryname not like '%programdata%';
delete from sam where ((name like '%install%' or name like '%setup%') or (directoryname like '%install%' or directoryname like '%setup%') 
or (description like '%install%' or description like '%setup%'));

---OS Build Details
create table kernels as select * from allfiles where directoryname like '%\windows\system32' and name like 'kernel32.dll';
create table osversions as
select distinct o.computername, o.productname, o.csdversion, o.currentversion, o.currentbuild, o.buildlabex, k.fileversion
 from osinfo o
left join kernels k 
on o.computername = k.computername;
create table osinventory as 
select distinct productname || " " || csdversion as os, currentversion || "." || currentbuild as version, fileversion as builds, count(distinct(computername)) as hosts
from osversions
group by os collate nocase, version collate nocase, builds collate nocase
order by os, version, builds, hosts;

---Antivirus Details
create table av as select distinct s.computername, Upper(name) as name, Upper(directoryname) as directoryname, productversion, fileversion, 
Upper(description) as description, '' as type, productname as os
from sam s
join osinfo o on s.computername = o.computername
where (name like 'sedservice.exe' or name like 'cylancesvc%exe' or name like 'CSFalconService.exe' or name like 'AVGSvc.exe' 
or name like 'MsMpEng.exe' or name like 'avp.exe' or name like 'McCHSvc.exe' or name like 'mbam%exe' or name like 'avastsvc.exe'
or name like 'LDservices.exe');
update av set type = "Sophos" where name like 'sedservice.exe';
update av set type = "Cylance" where name like 'cylancesvc%.exe';
update av set type = "Crowdstrike" where name like 'CSFalconService.exe';
update av set type = "AVG" where name like 'AVGSvc.exe';
update av set type = "WinDefender" where name like 'MsMpEng.exe';
update av set type = "Kaspersky" where name like 'avp.exe';
update av set type = "Mcafee" where name like 'McCHSvc.exe';
update av set type = "MalwareBytes" where (name like 'mbam%exe' and directoryname not like '%microsoft%');
update av set type = "Avast" where name like 'avastsvc.exe';
update av set type = "LanDesk" where name like 'LDservices.exe';
create table avinventory as select distinct os, type, count(distinct(computername)) as hosts from av group by os, type order by os, type, hosts desc;

---Browsers Details
create table browsers as select distinct s.computername, Upper(name) as name, Upper(directoryname) as directoryname, productversion, fileversion, 
Upper(description) as description, '' as type, productname as os
from sam s
join osinfo o on s.computername = o.computername
where ((name like 'iexplore.exe' or name like 'chrome.exe' or name like 'firefox.exe' or name like 'midori.exe' 
or name like 'microsoftedge.exe') and directoryname not like '%chameleon%');
update browsers set type = "IExplorer" where name like 'iexplore.exe';
update browsers set type = "Edge" where name like 'MicrosoftEdge.exe';
update browsers set type = "Chrome" where name like 'Chrome.exe';
update browsers set type = "Firefox" where name like 'Firefox.exe';
update browsers set type = "Midori" where name like 'midori.exe';
delete from browsers where (name like '%instal%' or name like '%setup%' or name like '%upd%' or name like '%upgr%' 
or name like '%msi%' or name like '%patch%' or name like '%driver%' or name like '%handler%' or name like '%app%' 
or name like '%help%' or name like '%launch%' or name like '%setup%' or name like '%recover%' or name like '%stand%'
or name like '%portable%' or name like '%export%');
create table browsersinventory as select distinct os, type, count(distinct(computername)) as hosts from browsers group by os, type order by os, type, hosts desc;

create table browserbuilds as 
select distinct o.productname, b.type, count(distinct(b.fileversion)) as versions
 from browsers b left join osinfo o
 on (o.computername = b.computername)
group by o.productname collate nocase, b.type
order by o.productname, b.type, versions;

---Active Remote Connections with Process Details
create table netremotes as select distinct n.computername, n.protocol, n.localaddress, cast(n.localport as int) as lport, 
n.remoteaddress, cast(n.remoteport as int) as rport, n.state, n.pid, n.processname,
p.commandline, g.cc, g.country, g.city, g.lat, g.long
 from netstat n, processes p, geoip g
where ((g.ip = n.remoteaddress) 
and ((n.computername = p.computername)
and (n.pid = p.processid)))
order by lport asc;

---SMB Details
create table smbdrivers as select * from allfiles where directoryname like '_:\windows\system32\drivers' and name like 'srv.sys';
create table smbinventory as select distinct o.productname, s.fileversion, count(distinct(s.computername)) as hosts
from osinfo o, smbdrivers s
where o.computername = s.computername
group by o.productname collate nocase, s.fileversion collate nocase
order by o.productname, s.fileversion, hosts;

--interconnects with lhost from rhost(s)
create table interconnects as 
select a.computername as lhost, a.productname as os, a.protocol, a.localaddress, a.localport, b.computername as rhost, a.remoteaddress, a.remoteport, a.pid, a.processname, a.commandline from 
(select distinct
	n.computername,
	o.productname,
	n.protocol,
	n.localaddress,
	n.localport,
	n.remoteaddress,
	n.remoteport, 
	n.pid,
	n.processname,
	p.commandline
from netstat n, osinfo o, processes p
where (((n.computername = p.computername) and (n.pid = p.processid))
and cast(n.localport as int) < 10000
and (remoteaddress not like '0.0.%' 
and remoteaddress not like '127.%' 
and remoteaddress not like '169.%' 
and remoteaddress not like '%:%' 
and remoteaddress not like '%*%')
and (n.computername = o.computername)
and (p.computername = o.computername))) a
left join nic b
on (a.remoteaddress = b.ipaddress)
where (a.localaddress != a.remoteaddress)
order by lhost, rhost, a.remoteaddress;
update interconnects set rhost = "unknown" where (rhost like '' or rhost like ' ' or rhost is null);

---local and remote intranet services connections 
create table netstats as 
select distinct net, computername, connections from 
(select distinct "local" as net, computername, count(localport) as connections from netstat
where ((localaddress like '10.%' or localaddress like '192.%' or localaddress like '172.%') 
and (cast(localport as int) < 20000 and cast(localport as int) > 18)
and (remoteaddress not like '0.0.%' and remoteaddress not like '%:%' and remoteaddress not like '%*%'))
group by net, computername
order by net, computername, connections)
union
select net, computername, connections from 
(select distinct "remote" as net, computername, count(lport) as connections
from netremotes
where cast(lport as int) < 20000
and cast(lport as int) > 18
group by net, computername
order by net, computername, connections);


---Risks by Type in Communicating Services
create table commtypes as
select distinct risk, computername, protocol, localaddress, lport, remoteaddress, rport, commandline, country, city, lat, long, asn, owner from 
(select distinct risk, computername, protocol, localaddress, lport, remoteaddress, rport, commandline, country, city, lat, long, asn, owner from
(select distinct "1.Data Loss" as risk, n.computername, n.protocol, n.localaddress, n.lport, n.remoteaddress, n.rport, n.commandline, n.country, n.city, n.lat, n.long, a.asn, a.owner
 from netremotes n
 left join asn a on n.remoteaddress = a.ip
where ((n.lport like '2_' or n.rport like '2_') or (n.commandline like '%ftp%' or n.commandline like '%putty%' or n.commandline like '%scp%' or n.commandline like '%box%'
 or n.commandline like '%cloud%' or n.commandline like '%drive%')
and n.commandline not like '%sandbox%' and n.commandline not like '%driver%'))
UNION
select distinct risk, computername, protocol, localaddress, lport, remoteaddress, rport, commandline, country, city, lat, long, asn, owner from
(select distinct "2.User Behavior" as risk, n.computername, n.protocol, n.localaddress, n.lport, n.remoteaddress, n.rport, n.commandline, n.country, n.city, n.lat, n.long, a.asn, a.owner
 from netremotes n
 left join asn a on n.remoteaddress = a.ip
where (n.commandline like '%\users\%')
and n.commandline not like '%teams%' and n.commandline not like '%sandbox%' and n.commandline not like '%program files%'
and n.commandline not like '%box%' and n.commandline not like '%drive%' and n.commandline not like '%ftp%' and n.commandline not like '%putty%' 
and n.commandline not like '%scp%' and n.commandline not like '%cloud%')
UNION
select distinct risk, computername, protocol, localaddress, lport, remoteaddress, rport, commandline, country, city, lat, long, asn, owner from
(select distinct "3.Network Security" as risk, n.computername, n.protocol, n.localaddress, n.lport, n.remoteaddress, n.rport, n.commandline, n.country, n.city, n.lat, n.long, a.asn, a.owner
 from netremotes n
 left join asn a on n.remoteaddress = a.ip
where ((cast(n.lport as int) < 20000 or cast(n.rport as int) > 20000) or (cast(n.rport as int) < 20000 and n.rport not like '8_' and n.rport not like '443' and n.rport not like '808_')))
UNION
select distinct risk, computername, protocol, localaddress, lport, remoteaddress, rport, commandline, country, city, lat, long, asn, owner from
(select distinct "4.Services Configuration" as risk, n.computername, n.protocol, n.localaddress, n.lport, n.remoteaddress, n.rport, n.commandline, n.country, n.city, n.lat, n.long, a.asn, a.owner
 from netremotes n
 left join asn a on n.remoteaddress = a.ip
where ((n.commandline like '%windows\sys_____\%') and cast(n.lport as int) < 20000))
UNION
select distinct risk, computername, protocol, localaddress, lport, remoteaddress, rport, commandline, country, city, lat, long, asn, owner from
(select distinct "5.Build" as risk, n.computername, n.protocol, n.localaddress, n.lport, n.remoteaddress, n.rport, n.commandline, n.country, n.city, n.lat, n.long, a.asn, a.owner
 from netremotes n
 left join asn a on n.remoteaddress = a.ip
 where (n.commandline like '%install%' or n.commandline like '%setup%' or n.commandline like '%update%' or n.commandline like '%dosvc%')
 and n.commandline not like '%catalina%' and n.commandline not like '%firstrunupdate%'));
insert into commtypes 
select distinct "1.Data Loss" as risk, computername, "", "", "", dns as remoteaddress, "", "webmail", "", "", "", "", "", "" 
from dnscache
where (dns like '%gmail%' or dns like 'google.mail%' or dns like '%hotmail%' or dns like '%ymail%' or dns like '%.mail.ru'
or dns like '%mail.yahoo.%') and dns not like 'mymail%' and dns not like '%dailymail%';
update commtypes set asn = "unknown" where asn is NULL;
update commtypes set owner = "unknown" where owner is NULL;

 
---Services
---Discrepancies and distribution of DNS resolvers
create table dnservers as 
select distinct net, dnserver, hosts
FROM (select distinct net, dnserver, hosts from
(select distinct "local" as net, "dns server" as dnserver, count(distinct(computername)) as hosts
from nic where (dnserver like '10.%' or dnserver like '192.%')
group by net, dnserver
order by hosts)
UNION
select distinct net, dnserver, hosts from
(select distinct "remote" as net, "dns server" as dnserver, count(distinct(computername)) as hosts
from nic where (dnserver not like '10.%' and dnserver not like '192.%' and dnserver not like '')
group by net, dnserver
order by hosts));

---DHCP Services
create table dhcp as 
select distinct Type, dhcpenabled as DHCP, count(distinct(computername)) as hosts from 
(select distinct "Servers" as Type, computername, dhcpenabled from nic 
where ipaddress glob '[0-9]*' and "DNS Server" glob '[0-9]*' 
and computername in (select computername from osinfo where productname like '%server%')
union 
select distinct "End Users" as Type, computername, dhcpenabled from nic 
where ipaddress glob '[0-9]*' and "DNS Server" glob '[0-9]*' 
and computername in (select computername from osinfo where productname not like '%server%'))
group by type, dhcp
order by Type, dhcp, hosts;

---Identifiable Malware
---Communicating Malware or PUPs
create table malwarecomms as 
select distinct computername, remoteaddress, reference
from ((select distinct computername, remoteaddress, commandline || " ASN:" || Owner as reference 
from (select distinct n.computername, n.lport, n.remoteaddress, n.commandline, a.owner
from netremotes n
join asn a on (n.remoteaddress = a.ip)
where (cast(n.lport as int) < 20000
and ((n.commandline like '%\windows\%' and n.commandline not like '%search%')
or (n.commandline like '%\temp\%' or n.commandline like '%\users\%\roaming%' 
or n.commandline like '%cmd%' or n.commandline like '%dllhost%' 
or n.commandline like '%users\%\javaw%' or n.commandline like '%programdata%'))
and a.owner not like 'microsoft%' and a.owner not like 'google%' and a.owner not like 'akamai%'))
UNION
select distinct computername, remoteaddress, detail as reference 
from (select distinct n.computername, n.lport, n.remoteaddress, n.commandline, a.owner, c.detail
from netremotes n
join asn a on (n.remoteaddress = a.ip)
join c2 c on ((n.remoteaddress = c.c2) and (c.c2 = a.ip)))
UNION
select distinct computername, remoteaddress, detail as reference 
from (select distinct d.computername, d.dns as remoteaddress, c.detail
from dnscache d
join c2 c on (d.dns = c.detail))));

---Other Malware or PUPs
---Malware Processes and Schedules
create table malware as 
select distinct source, computername, path, commandline from 
(select distinct "processes" as source, computername, path, commandline 
from processes
where (commandline like '%\temp\%' or commandline like '%\installer\in\%' or commandline like '%\users\%\roaming\%' 
or commandline like '%\desktop\%' or commandline like '%\windows\sys_____\%\%' or commandline like '%\programdata\%')
and path not like '%windows\sys_____\%\%\%'
and path not like '%\wbem\%' and path not like '%\inetsrv\%' and path not like '%\dptf\%' and path not like '%\dell\%'
and path not like '%\powershell\%' and path not like '%program files%' and path not like '%admanager%'
and path not like '%\teams\%' and path not like '%\g2%' and path not like '%webex%' and path not like '%\1033\%'
and path not like '%\cba\%' and path not like '%\ctes%' and path not like '%search%' and path not like '%sys_____\dell%' 
and path not like '%datacard%' and path not like '%flex%' and path not like '%wudf%' and path not like '%epson%' 
and path not like '%landesk%' and path not like '%logishrd%' and path not like '%defender%' and path not like '%cache%'
and path not like '%rpcnet%' and path not like '%freemake%' and path not like '%\pfu\%' and path not like '%\fabric\%'
and path not like '%{%' and path not like '%\U3\%' and path not like '%vmware%' and path not like '%discord%' 
and path not like '%conferencing%' and path not like '%-%-%' and path not like '%dism%' and path not like '%lark%'
and path not like '%display%' and path not like '%usb%' and path not like '%jeans%' and path not like '%uniprint%'
and path not like '%chime%' and path not like '%spotify%' and path not like '%dropbox%'
and commandline not like '%\cavs\%' and commandline not like '%install%' and commandline not like '%setup%' 
and commandline not like '%updat%' and commandline not like '%\ctes\%' and commandline not like '%shcreatelocalserver%'
and commandline not like '%msiexec%' and commandline not like '%mmc%' and commandline not like '%plahost%'
and commandline not like '%hotplug%' and commandline not like '%drivers%' and commandline not like '%.cpl%'
and commandline not like '%bluetooth%' and commandline not like '%\hp\%' and commandline not like '%telemetry%'
and commandline not like '%dashlane%' and commandline not like '%solidworks%' and commandline not like '%samsung%'
and commandline not like '%dialpad%' and commandline not like '%slack%' and commandline not like '%goto%'
and commandline not like '%framework%' and commandline not like '%landesk%' and commandline not like '%inetcache%'
and commandline not like '%patch%' and commandline not like '%notify%' and commandline not like '%diagsvcs%'
and commandline not like '%\lenovo\%' and commandline  not like '%office%' and commandline not like '%-%-%'
and commandline not like '%firewallcontrolpanel%' and commandline not like '%\oem\%'
union
select distinct "startups" as source, computername, location as path, command || " User: " || user as commandline
 from startups
where ((commandline like '%\temp\%' or commandline like '%\users\%\roaming%' or commandline like '%cmd%' 
or commandline like '%rundll32%') or (commandline like '%:\windows\%' and commandline not like '%:\windows\%\%'))
and commandline not like '%uniprint%' and commandline not like '%hkcmd.exe%' and commandline not like '%spotify%'
and commandline not like '%chime%' and commandline not like '%webex%' and commandline not like '%goto%'
and commandline not like '%appmaster%' and commandline not like '%logifetch%' and commandline not like '%drivers%'
and commandline not like '%savesysteminfo%' and commandline not like '%bluetooth%' and commandline not like '%dashlane%'
and commandline not like '%cisco%' and commandline not like '%usb%' and commandline not like '%smilebox%'
and commandline not like '%desktopcal%' and commandline not like '%mouse%' and commandline not like '%virtual%'
and commandline not like '%taskbar%' and commandline not like '%bomgar%'
union
select distinct "services" as source, computername, filename as path, servicetype || " Name: " || servicename || " StartType: " || servicestarttype as commandline
 from syssvcstart
where path like '%.exe%'  
and path not like '%program%file%' and path not like '%driver%' and path not like '%systemroot%' and path not like '%pdq%' 
and path not like '%landesk%' and path not like '%sophos%' and path not like '%dell%' and path not like '%windows\sys_____\%'
and path not like '%zoho%' and path not like '%\cxsvc\%' and path not like '%windir%' and path not like '%bomgar%'
and path not like '%ctes%' and path not like '%rpcnet%' and path not like '%patches%' and path not like '%mercury%'
and path not like '%install%' and path not like '%updat%' and path not like '%setup%' and path not like '%mobile%'
and path not like '%\rps\%' and path not like '%audio%'
union
select distinct "services" as source, computername, servicedll as path, servicename as commandline 
 from servicedlls 
where path in 
(select servicedll as path from 
(select distinct servicename, servicedll, count(distinct(computername)) as hosts 
from servicedlls 
group by servicename collate nocase, ServiceDll collate nocase having hosts < 10
order by hosts asc))
union
select distinct "tasks" as source, computername, name as path, actions as commandline
 from tasks 
where ((commandline like '%\users\%\roaming%' or commandline like '%\temp\%' or commandline like '%:\windows\%'
or commandline like '%public%' or commandline like '%desktop%' or commandline like '%programdata%'
or commandline like '%powershell%enc%' or commandline like '%cmd%' or commandline like '%rundll32%')
and commandline not like '%flash%' and commandline not like '%seagate%' and commandline not like '%drivers%'
and commandline not like '%\intel\%' and commandline not like '%\autokms\%' and commandline not like '%bluestack%'
and commandline not like '%-%-%' and commandline not like '%updat%' and commandline not like '%instal%' 
and commandline not like '%setup%' and commandline not like '%bluestack%' and commandline not like '%nouaccheck%'
and commandline not like '%configure%' and commandline not like '%pnptask%' and commandline not like '%robocopy%'
and commandline not like '%inetpub%' and commandline not like '%desktopcentral%' and commandline not like '%\oem\%'
and commandline not like '%\scripts\%' and commandline not like '%player%' and commandline not like '%fileprotocol%'
and commandline not like '%program files%' and commandline not like '%samsung%' and commandline not like '%pcdr%'
and commandline not like '%windowstime%' and commandline not like '%tracing%' and commandline not like '%transport%'
and commandline not like '%pcalua%' and commandline not like '%twain%'));
---insert known malware
insert into malware 
select distinct source, computername, path, commandline from 
(select distinct "processes" as source, computername, path, commandline 
from processes
where (commandline like '%\7.exe%' or commandline like '%\windows.bat%' or commandline like '%\eset.exe%' or commandline like '%\pass.exe%' 
or commandline like '%\-s.exe%' or commandline like '%\whoami%' or commandline like '%\nltest%' or commandline like '%\decrypt-files%')
UNION
select distinct "startups" as source, computername, location as path, command || " User: " || user as commandline
 from startups
where (commandline like '%\7.exe%' or commandline like '%\windows.bat%' or commandline like '%\eset.exe%' or commandline like '%\pass.exe%' 
or commandline like '%\-s.exe%' or commandline like '%\whoami%' or commandline like '%\nltest%' or commandline like '%\decrypt-files%')
UNION 
select distinct "services" as source, computername, filename as path, servicetype || " Name: " || servicename || " StartType: " || servicestarttype as commandline
 from syssvcstart
where (path like '%\7.exe%' or path like '%\windows.bat%' or path like '%\eset.exe%' or path like '%\pass.exe%' 
or path like '%\-s.exe%' or path like '%\whoami%' or path like '%\nltest%' or path like '%\decrypt-files%')
UNION
select distinct "services" as source, computername, servicedll as path, servicename as commandline 
 from servicedlls 
where (path like '%\7.exe%' or path like '%\windows.bat%' or path like '%\eset.exe%' or path like '%\pass.exe%' 
or path like '%\-s.exe%' or path like '%\whoami%' or path like '%\nltest%' or path like '%\decrypt-files%')
UNION
select distinct "tasks" as source, computername, name as path, actions as commandline
 from tasks 
where (commandline like '%\7.exe%' or commandline like '%\windows.bat%' or commandline like '%\eset.exe%' or commandline like '%\pass.exe%' 
or commandline like '%\-s.exe%' or commandline like '%\whoami%' or commandline like '%\nltest%' or commandline like '%\decrypt-files%'));
insert into malware 
select distinct "files" as source, computername, "directoryname" || "\" || name as path, datetime(substr(creationtime,1,10),'unixepoch') as commandline 
 from exe
where (name like 'pass.exe' or name like 'eset.exe' or name like '-s.exe' or name like 'internat.exe');

---Network Services by OSType
create table netservices as 
select distinct cast(n.localport as int) as lport, o.productname as os, count(distinct(n.computername)) as hosts
 from netstat n, osinfo o
where ((n.computername = o.computername)
and lport < 20000
and lport > 18)
group by lport, os collate nocase
order by lport, os, hosts;
create table netservices2 as
select distinct os, service, sum(hosts) as connections
FROM
(select os, lport, "AMT" as service, hosts from netservices where (lport = 623 or lport = 16992 or lport = 16993) UNION 
select os, lport, "RDP" as service, hosts from netservices where (lport = 3389 or lport = 3390) UNION
select os, lport, "SMTP" as service, hosts from netservices where lport = 125 UNION
select os, lport, "POP3" as service, hosts from netservices where lport = 110 UNION
select os, lport, "IMAP" as service, hosts from netservices where lport glob '99[3-5]' UNION
select os, lport, "HTTP" as service, hosts from netservices where lport = 80 UNION
select os, lport, "HTTPS" as service, hosts from netservices where lport = 443 UNION
select os, lport, "KERB" as service, hosts from netservices where lport = 88 UNION
select os, lport, "RNTP" as service, hosts from netservices where lport = 123 UNION
select os, lport, "SMB" as service, hosts from netservices where lport = 445 UNION
select os, lport, "DO" as service, hosts from netservices where lport = 7680 UNION
select os, lport, "LDESK" as service, hosts from netservices where (lport = 9535 or lport = 12174) UNION
select os, lport, "LDAP" as service, hosts from netservices where lport = 389 UNION
select os, lport, "IRC" as service, hosts from netservices where lport glob '666[0-9]' UNION
select os, lport, "RADMIN" as service, hosts from netservices where lport = 4899 UNION
select os, lport, "BOT" as service, hosts from netservices where lport like '8443' UNION
select os, lport, "GoTo" as service, hosts from netservices where lport = 8200 UNION
select os, lport, "DNS" as service, hosts from netservices where lport = 53 UNION
select os, lport, "DHCP" as service, hosts from netservices where lport = 67 UNION
select os, lport, "TFTP" as service, hosts from netservices where lport = 20 UNION
select os, lport, "FTP" as service, hosts from netservices where lport = 21 UNION
select os, lport, "SCP" as service, hosts from netservices where lport = 22 UNION
select os, lport, "SSH" as service, hosts from netservices where lport = 23 UNION
select os, lport, "VNC" as service, hosts from netservices where lport glob '5[8-9]0[0-9]' UNION
select os, lport, "uTOR" as service, hosts from netservices where lport glob '688[1-9]' UNION
select os, lport, "TOR" as service, hosts from netservices where (lport = 9001 or lport = 9030) UNION
select os, lport, "SQL" as service, hosts from netservices where lport = 1433 UNION
select os, lport, "BTC" as service, hosts from netservices where lport glob '833[2-3]') 
group by os, Service
order by os, service, hosts;

---RemoteIT
create table if not exists remoteIT as 
select distinct source, computername, type FROM
(select "files" as source, computername, "LogMeIn" as type from exe where ((name like 'logmein%exe' or name like 'lmi%exe') or (directoryname like '%\lmi%' or directoryname like '%logmein%'))
 UNION
select "files" as source, computername, "VNC" as type from exe where ((name like '%vnc%exe' and name not like '%tsvnc%') or (directoryname like '%vnc%' and directoryname not like '%tsvnc%'))
 UNION
select "files" as source, computername, "Dameware" as type from exe where ((name like 'dwrc%exe' or name like 'dmwrc%exe' or name like 'dntu%exe' or name like 'dameware%exe') or directoryname like '%dameware%')
 UNION
select "files" as source, computername, "GoToAssist" as type from exe where ((name like 'gotoassist%exe' or name like '%g2%exe') or (directoryname like '%gotoassist%' or directoryname like '%g2ax%'))
 UNION 
select "files" as source, computername, "BomGar" as type from exe where ((name like 'bomgar%exe') or (directoryname like '%bomgar%'))
 UNION
select "files" as source, computername, "Teamviewer" as type from exe where ((name like 'tv__32%exe' or name like 'tv___64%exe' or name like 'teamview%exe') or (directoryname like '%teamview%'))
 UNION 
select "files" as source, computername, "IntelAMT" as type from exe where (name like 'lms%exe' and directoryname like '%\intel\%')
 UNION
select "files" as source, computername, "LanDesk" as type from exe where (directoryname like '%\landesk\%')
 UNION
select "processes" as source, computername, "LogMeIn" as type from processes where (commandline like '%logmein%' or commandline like '%\lmi%')
 UNION
select "processes" as source, computername, "VNC" as type from processes where (commandline like '%vnc%' and commandline not like '%tsvnc%')
 UNION
select "processes" as source, computername, "Dameware" as type from processes where (commandline like '%dwrc%exe%' or commandline like '%dmwrc%exe%' or commandline like '%dntu%exe%' or commandline like '%dameware%')
 UNION
select "processes" as source, computername, "GoToAssist" as type from processes where (commandline like '%gotoassist%' or commandline like '%g2ax%')
 UNION
select "processes" as source, computername, "BomGar" as type from processes where (commandline like '%bomgar%')
 UNION
select "processes" as source, computername, "TeamViewer" as type from processes where (commandline like '%\tv_____.exe%' or commandline like '%teamviwer%')
 UNION
select "processes" as source, computername, "IntelAMT" as type from processes where (commandline like '%\intel\%' and commandline like '%\lms.exe%')
 UNION
select "processes" as source, computername, "LanDesk" as type from processes where (commandline like '%\landesk\%')
 UNION
select "startups" as source, computername, "LogMeIn" as type from startups where (command like '%logmein%' or command like '%\lmi%')
 UNION
select "startups" as source, computername, "VNC" as type from startups where (command like '%vnc%' and command not like '%tsvnc%')
 UNION
select "startups" as source, computername, "Dameware" as type from startups where (command like '%dwrc%exe%' or command like '%dmwrc%exe%' or command like '%dntu%exe%' or command like '%dameware%')
 UNION
select "startups" as source, computername, "GoToAssist" as type from startups where (command like '%gotoassist%' or command like '%g2ax%')
 UNION
select "startups" as source, computername, "BomGar" as type from startups where (command like '%bomgar%')
 UNION
select "startups" as source, computername, "TeamViewer" as type from startups where (command like '%\tv_____.exe%' or command like '%teamviwer%')
 UNION
select "startups" as source, computername, "IntelAMT" as type from startups where (command like '%\intel\%' and command like '%\lms.exe%')
 UNION
select "startups" as source, computername, "LanDesk" as type from startups where (command like '%\landesk\%'));
create table remoteittally as 
select distinct type, source, count(distinct(computername)) as hosts 
from remoteIT
group by type,Source 
order by type, source, hosts;

--ShadowIT
create table if not exists shadowIT as 
select distinct source, computername, type FROM
(select "files" as source, computername, "Box" as type from exe where (name like 'box%exe' or directoryname like '%\box%')
 UNION
select "files" as source, computername, "DropBox" as type from exe where (name like 'Dropbox%exe' or directoryname like '%dropbox%')
 UNION
select "files" as source, computername, "OneDrive" as type from exe where (name like 'Onedrive%exe' or directoryname like '%Onedrive%')
 UNION
select "files" as source, computername, "SkyDrive" as type from exe where (name like 'SkyDrive%exe' or directoryname like '%skydrive%')
 UNION 
select "files" as source, computername, "GoogleDrive" as type from exe where (name like 'googledrive%exe' or directoryname like '%googledrive%')
 UNION
select "files" as source, computername, "Azure" as type from exe where (name like 'azure%exe' or directoryname like '%azure%')
 UNION 
select "files" as source, computername, "iCloud" as type from exe where (name like 'icloud%exe' or directoryname like '%\icloud\%')
 UNION
select "files" as source, computername, "OtherCloud" as type from exe where (directoryname like '%cloud%' and directoryname not like '%icloud%')
 UNION
select "processes" as source, computername, "Box" as type from processes where (commandline like '%\box%')
 UNION
select "processes" as source, computername, "DropBox" as type from processes where (commandline like '%\dropbox%')
 UNION
select "processes" as source, computername, "OneDrive" as type from processes where (commandline like '%onedrive%')
 UNION
select "processes" as source, computername, "SkyDrive" as type from processes where (commandline like '%skydrive%')
 UNION
select "processes" as source, computername, "GoogleDrive" as type from processes where (commandline like '%googledrive%')
 UNION
select "processes" as source, computername, "Azure" as type from processes where (commandline like '%azure%')
 UNION
select "processes" as source, computername, "iCloud" as type from processes where (commandline like '%icloud%')
 UNION
select "processes" as source, computername, "OtherCloud" as type from processes where (commandline like '%cloud%' and commandline not like '%icloud%')
 UNION
select "startups" as source, computername, "Box" as type from processes where (commandline like '%\box%')
 UNION
select "startups" as source, computername, "DropBox" as type from processes where (commandline like '%\dropbox%')
 UNION
select "startups" as source, computername, "OneDrive" as type from processes where (commandline like '%onedrive%')
 UNION
select "startups" as source, computername, "SkyDrive" as type from processes where (commandline like '%skydrive%')
 UNION
select "startups" as source, computername, "GoogleDrive" as type from processes where (commandline like '%googledrive%')
 UNION
select "startups" as source, computername, "Azure" as type from processes where (commandline like '%azure%')
 UNION
select "startups" as source, computername, "iCloud" as type from processes where (commandline like '%icloud%')
 UNION
select "startups" as source, computername, "OtherCloud" as type from processes where (commandline like '%cloud%' and commandline not like '%icloud%'));
create table shadowittally as 
select distinct type, source, count(distinct(computername)) as hosts 
from shadowIT
group by type,Source 
order by type, source, hosts;

---Users
---User Profiles
create table profiles as 
select distinct computername, username, created from 
(select distinct computername, substr(directoryname, 27) as username, datetime(substr(creationtime,1,10),'unixepoch') as created
from allprofiles where (directoryname like '%documents and settings%' and directoryname not like '%default%') UNION
select distinct computername, substr(directoryname, 10) as username, datetime(substr(creationtime,1,10),'unixepoch') as created
from allprofiles where (directoryname like '%users%' and directoryname not like '%default%' and directoryname not like '%default%'));
---User Privileges and Groups
create table localprivs as 
select distinct computername, username, lastlogin, enabled, groups from 
(select computername, username, datetime(substr(lastlogin,1,10),'unixepoch') as lastlogin, enabled, "Administrators" as groups 
 from allusers where groups like '%admin%' UNION
select computername, username, datetime(substr(lastlogin,1,10),'unixepoch') as lastlogin, enabled, "RemoteDesktopUsers" as groups 
 from allusers where groups like '%remote%' UNION
select computername, username, datetime(substr(lastlogin,1,10),'unixepoch') as lastlogin, enabled, "DomainUsers" as groups 
 from allusers where groups like '%Domain Users%' UNION
select computername, username, datetime(substr(lastlogin,1,10),'unixepoch') as lastlogin, enabled, "Other" as groups 
 from allusers where (groups not like '%admin%' and groups not like '%remote%' and groups not like '%Domain Users%' 
 and groups not like '' and groups not like ' '));
---Local Users and Rights
create table localusers as
select distinct computername, accounttype, name, sid from allusersreg;
---Local Logins
create table locallogins as 
select distinct x.computername, x.username, x.created, x.lastlogin, x.enabled, x.groups, u.SID
from 
(select distinct p.computername, p.username, p.created, l.lastlogin, l.enabled, l.groups 
 from profiles p
left join localprivs l
 on ((p.computername = l.computername) and (p.username = l.username collate nocase))
where l.enabled like 'true') x
 left join localusers u
 on ((x.computername = u.computername) and (x.username = u.name));
--RDP Use by Shift
create table rdp as
select distinct shift, lhost, logontime, username, domain, ipaddress, rhost from 
(select distinct "Night" as Shift, r.computername as Lhost, datetime(substr(r.eventtime,1,10),'unixepoch') as LogonTime, r.username, r.domain, r.ipaddress, n.computername as Rhost
from remotelogons r
left join nic n
on (r.ipaddress = n.ipaddress)
where (r.ipaddress not like '' and r.ipaddress not like ' ' and (logontime glob '* 2[0-2]:*' or logontime glob'* 0[0-7]'))
union 
select distinct "Day" as Shift, r.computername as Lhost, datetime(substr(r.eventtime,1,10),'unixepoch') as LogonTime, r.username, r.domain, r.ipaddress, n.computername as Rhost
from remotelogons r
left join nic n
on (r.ipaddress = n.ipaddress)
where (r.ipaddress not like '' and r.ipaddress not like ' ' and (logontime glob '* 0[8-9]:*' or logontime glob'* 1[0-9]*')));
--Commands History
create table suspcommands as 
select distinct computername, command, run 
 from 
 (select computername, substr(name, 1, length(name)-12) as command, datetime(substr(creationtime,1,11),'unixepoch') as run 
 from prefetch union 
select computername, substr(name, 1, length(name)-12) as command, datetime(substr(lastwritetime,1,11),'unixepoch') as run 
 from prefetch union 
select computername, command, datetime(lastmod,'unixepoch') as run from amcache)
where 
(((command like '-s.exe' or command like '7.exe' or command like 'whoami%' or command like 'adfind%' or command like 'pass.exe' 
or command like 'eset.exe' or command like 'internat.exe' or command like 'filezilla%' or command like 'fz%' 
or command like 'rar.exe' or command like 'putty.exe' or command like 'nltest%' or command like 'adfind%' or command like 'curl.exe'
or command like 'windows.bat' or command like 'cclean%' or command like 'wget.exe')
or (command like '%vnc%exe' and command not like '%tsvnc%')
or (command like 'mstsc.exe' and (run glob '* 2[0-3]:*' or run glob '* 0[0-5]:*')) 
or (command like '%ftp%' and (command not like '%ftpdfr%' and command not like 'pxe%')))
and command not like '%webex%' and command not like '%softphone%' and command not like '%bundle%' and command not like '%setup%'
and command not like '%sponso%' and command not like '%voyag%' and command not like '%softpa%' and command not like '%updat%')
and (run > date(('now'),'-180 days'))
group by computername, command collate nocase, run 
order by run desc;

---Data
---USB Device Usage
create table usbuse as
select distinct "#" || substr(serialno, 1, length(serialno)-2) as serial, count(distinct(computername)) as hosts
 from usbdev
where service like 'disk'
group by serial collate nocase
order by hosts desc;

---Summaries
-- Create Executive Actions for Remediation Discussion
CREATE TABLE IF NOT EXISTS execaction ('Risk' text,'Description' text,'Recommendation' text,'Reason' text,'Resolution' text);
insert into execaction values ("1.Data Loss","Potential Data Loss due to Browser use of Webmail service","Investigate for potential compromise or inappropriate use by Users","Reduce opportunity for data loss","Acceptable Use Policy Training");
insert into execaction values ("1.Data Loss","Potential Data Loss due to use of Data Packers and Exfil Tools","Investigate for potential compromise or inappropriate use by Users","Reduce opportunity for data loss","Acceptable Use Policy Training");
insert into execaction values ("1.Data Loss","Potential Data or System Sabotage","Investigate for potential compromise or inappropriate use by Users","Reduce opportunity for data loss or business interruption","File Integrity Monitoring and Roles Based Access Controls (RBAC)");
insert into execaction values ("2.User Behavior","Potentially Suspicious or Inappropriate User Activities and Tools Use","Investigate for potential compromise or inappropriate use by Users","Reduce opportunity to exploit vulnerable services","Acceptable Use Policy Training and Antivirus / Antimalware");
insert into execaction values ("2.User Behavior","Use of Administrator account for remote desktop access","Investigate for potential compromise or inappropriate use by Users","Reduce opportunity to exploit vulnerable services","Group Policy Object (GPO) Enforcement, User Behavior Analytics (UBA)");
insert into execaction values ("2.User Behavior","Suspicious Remote Desktop Access from External IP Address","Investigate for potential compromise or inappropriate use by Users","Reduce opportunity to exploit vulnerable services","Firewall Access Control Lists (ACLs) and Network Traffic Monitoring/Intelligence");
insert into execaction values ("2.User Behavior","Suspicious Local User Accounts","Review and clean up profiles for use on Endpoints","Reduce misuse of credentials risk","Group Policy Object (GPO) Enforcement, User Behavior Analytics (UBA)");
insert into execaction values ("3.Network Security","Suspicious Internet Service Connections","Investigate for potential Malware or inappropriate use by Users","Reduce opportunity to exploit vulnerable services","Firewall Access Control Lists (ACLs) and Network Traffic Monitoring/Intelligence");
insert into execaction values ("3.Network Security","Suspicious Internal Network Service Connections","Investigate for potential Malware or inappropriate use by Users","Reduce opportunity to exploit vulnerable services","Group Policy Object (GPO) Enforcement, Firewall Access Control Lists (ACLs), and Network Traffic Monitoring");
insert into execaction values ("4.Services Configuration","Potentially suspicious service or software configuration","Investigate for potential Malware or inappropriate use by Users","Reduce opportunity to exploit vulnerable services","Group Policy Object (GPO) Enforcement, Antivirus / Antimalware, Acceptable Use Policy Training");
insert into execaction values ("4.Services Configuration","Potentially Suspicious Network DNS Services Configuration","Ensure consistent use of DNS Services Configuration","Prevent DNS misdirection and compromise","Group Policy Object (GPO) Enforcement, Firewall Access Control Lists (ACLs), and Network Traffic Monitoring");
insert into execaction values ("5.Build","Internet Software Updates","Restrict software updates to corporate managment policies and tools","Reduce opportunity to exploit vulnerable services","Group Policy Object (GPO) Enforcement, Firewall Access Control Lists (ACLs), and Network Traffic Monitoring");
insert into execaction values ("5.Build","Missing Security or Management Software","Install Software, and audit results for consistency","Reduce opportunity to exploit vulnerable services","Group Policy Object (GPO) Enforcement, Configuration Management Database/Tool");
insert into execaction values ("5.Build","Host Vulnerable to SMB Exploit","Patch Operating System and Applications, and audit results for consistency","Reduce opportunity to exploit vulnerable services","Group Policy Object (GPO) Enforcement, Configuration Management Database/Tool");

---Hosts of Interest for Investigation
--Investigate
CREATE TABLE IF NOT EXISTS "Investigate" ("Computername" text, "AuditDate" text, "Risk" text, "Description" text, "Username" text, "Department" text, "Detail" text, "HOI" text); 
--- Data Loss and Sabotage
insert into investigate select distinct computername, date('now') as auditdate, '1.Data Loss', 'Potential Data Loss due to Browser use of Webmail service', " ", " ", commandline, " " from processes where (((path like '%internet%' or path like '%chrom%' or path like '%midori%' or path like '%firefox%' or path like '%edge%') and path not like '%chameleon%') and commandline like '%mail%'); 
insert into investigate select distinct Computername, date('now'), '1.Data Loss', 'Potential Data Loss due to Browser use of Webmail service', " ", " ",  Commandline || " LocalPort:" || lport || ' remoteaddress: ' || remoteaddress || ":" || rport || ' Country: ' || country, " " from commtypes where (risk like '1.Data Loss' and commandline like '%webmail%');
insert into investigate select distinct Computername, date('now'), '1.Data Loss', 'Potential Data Loss due to use of Data Packers and Exfil Tools', " ", " ", Command, " " from startups where (command like '%cloud%' or command like '%ftp%' or command like '%filezilla%' or command like '%putty%');
insert into investigate select distinct Computername, date('now'), '1.Data Loss', 'Potential Data Loss due to use of Data Packers and Exfil Tools', " ", " ", Commandline || " LocalPort:" || lport || ' remoteaddress: ' || remoteaddress || ":" || rport || ' Country: ' || country, " " from commtypes where (risk like '1.Data Loss' and commandline not like '%webmail%');
insert into investigate select distinct Computername, date('now'), '1.Data Loss', 'Potential Data or System Sabotage', " ", " ", Command, " " from startups where ((command like '%.exe%' or command like '%.bat%') and (command like '%desktop%.txt%' or command like '%desktop%.htm%' or command like '%decrypt-files.txt%')) and command not like '%progra%' and command not like '%\bin\%';
insert into investigate select distinct Computername, date('now'), '1.Data Loss', 'Potential Data or System Sabotage', " ", " ", Commandline, " " from processes where ((commandline like '%.exe%' or commandline like '%.bat%') and (commandline like '%desktop%.txt%' or commandline like '%desktop%.htm%' or commandline like '%decrypt-files.txt%')) and commandline not like '%progra%' and commandline not like '%\bin\%';
--- User Behavior
insert into investigate select distinct computername, date('now') as auditdate, '2.User Behavior', 'Potentially Suspicious or Inappropriate User Activities and Tools Use', " ", " ", commandline, " "  from processes where ((commandline like '%\users\%') and (commandline like '%cmd%' or commandline like '%rundll32%' or commandline like '%wmic%' or commandline like '%javaw%' or commandline like '%cscript%' or commandline like '%svchost%' or commandline like '%powershell%enc%'));
insert into investigate select distinct computername, date('now') as auditdate, '2.User Behavior', 'Potentially Suspicious or Inappropriate User Activities and Tools Use', " ", " ", Command || ' last run:' || Run, " " from suspcommands;
insert into investigate select distinct Lhost as Computername, date('now'), '2.User Behavior', 'Use of Administrator account for remote desktop access', username, " ", 
LogonTime || ' RemoteHost: ' || RHost || ' RemoteIP: ' || ipaddress || ' Domain: ' || Domain || ' Shift: ' || Shift, " " from rdp where username like '%administrator%';
insert into investigate select distinct Lhost as Computername, date('now'), '2.User Behavior', 'Suspicious Remote Desktop Access from External IP Address', username, " ", 
LogonTime || ' RemoteHost: ' || RHost || ' RemoteIP: ' || ipaddress || ' Domain: ' || Domain || ' Shift: ' || Shift, " " from rdp where ipaddress not like '10.%' and ipaddress not like '192.%' and ipaddress not like '%:%' and ipaddress not like '';
insert into investigate select distinct Computername, date('now'), '2.User Behavior', 'Potentially Suspicious or Inappropriate User Activities and Tools Use', " ", " ",  Commandline || " LocalPort:" || lport || ' remoteaddress: ' || remoteaddress || ":" || rport || ' Country: ' || country, " " from commtypes where (risk like '2.User Behavior');
insert into investigate select Computername, date('now'), '2.User Behavior', 'Suspicious Local User Accounts', " ", " ", username || " in " || groups || " group"|| " last login: " || lastlogin, " " from locallogins where ((groups like '%remote%' or groups like '%administrator%' and sid not null and computername not like '%dc%') and  (lastlogin > date(('now'),'-180 days'))); 
--- Network Security
insert into investigate select distinct Computername, date('now'), '3.Network Security', 'Suspicious Internet Service Connections', " ", " ", "ASN: " || owner ||  " LPort: " || lport || " RemoteAddres: " || remoteaddress || " RPort: " || rport || " " || commandline, " " from commtypes where (( cast(lport as int) < 20000 or cast(rport as int) > 20000) and  (risk like '3.%' and (owner not like 'microsoft%' and owner not like 'akamai%' and owner not like 'google%' and owner not like 'ATT%' and owner not like 'Apple%' and owner not like 'facebook%' and owner not like '%zoom%')));
insert into investigate select distinct Computername, date('now'), '3.Network Security', 'Suspicious Internet Service Connections', " ", " ", "ASN: " || owner ||  " LPort: " || lport || " RemoteAddres: " || remoteaddress || " RPort: " || rport || " " || commandline, " " from commtypes where ((rport not like '80' and rport not like '443') and (cast(lport as int) > 20000 and cast(rport as int) < 20000) and (risk like '3.%' and (owner not like 'microsoft%' and owner not like 'akamai%' and owner not like 'google%' and owner not like 'ATT%' and owner not like 'Apple%' and owner not like 'facebook%' and owner not like '%zoom%')));
insert into investigate select distinct lhost, date('now'), '3.Network Security', 'Suspicious Internal Network Service Connections', " ", " ", "LocalAddress: " || localaddress ||  ":" || localport || " RemoteComputer: " || rhost || " RemoteAddres: " || remoteaddress || ":" || remoteport || " ProcessName: " || processname, " " from interconnects where (cast(localport as int) < 20000 or cast(remoteport as int) < 20000);
--- Services Configuration Anomalies
insert into investigate select distinct Computername, date('now'), '4.Services Configuration', 'Potentially suspicious service or software configuration', " ", " ", "Source: " || source || " Path: " || path || " Commandline: " || Commandline, " " from malware;
insert into investigate select distinct Computername, date('now'), '4.Services Configuration', 'Potentially suspicious service or software configuration', " ", " ", "ASN: " || owner ||  " LPort: " || lport || " RemoteAddres: " || remoteaddress || " RPort: " || rport || " " || commandline, " " from commtypes where (risk like '4.%' and (owner not like 'microsoft%' and owner not like 'akamai%' and owner not like 'google%' and owner not like 'ATT%' and owner not like 'Apple%' and owner not like 'facebook%' and owner not like '%zoom%'));
insert into investigate select distinct Computername, date('now'), '4.Services Configuration', 'Potentially Suspicious Network DNS Services Configuration', " ", " ", "dns server" as dns, " " from nic where dns not like '10\.%' escape '\' and dns not like '' and dns not like ' ' and dns not like '172\.%' escape '\' and dns not like '192\.%' escape '\'; 
--- Build 
insert into investigate select distinct Computername, date('now'), '5.Build', 'Internet Software Updates', " ", " ", "ASN: " || owner ||  " LPort: " || lport || " RemoteAddres: " || remoteaddress || " RPort: " || rport || " " || commandline, " " from commtypes where (risk like '5.%');
insert into investigate select distinct computername, date('now'), '5.Build', 'Missing Security or Management Software', " ", " ", detail, " " from 
(select distinct computername, "OS: " || os || " Missing SentinelOne" as detail from av where computername not in (select computername from av where type like 'SentinelOne') union
select distinct computername, "OS: " || os || " Missing LanDesk" as detail from av where computername not in (select computername from av where type like 'landesk') union 
select distinct computername, "OS: " || os || " Missing Windows Defender" as detail from av where computername not in (select computername from av where type like 'WinDefender'));
insert into investigate select distinct computername, date('now'), '5.Build', 'Host Vulnerable to SMB Exploit', " ", " ", "Name: " || name || " v." || productversion || " OS: " || osver, " " from 
(select computername, name, productversion, osver from (select s.computername, s.name, s.productversion, o.productname || " " || o.csdversion as osver from smbdrivers s, osinfo o 
where ((s.computername = o.computername) and ((osver like 'Windows XP%' and s.productversion not like '5.1.2600.7208' and s.productversion not glob '5.[2-9].*')
or (osver like 'Windows Server 2003 Service Pack 2%' and s.productversion not like '5.2.3790.6021' and s.productversion not glob '5.[3-9].*')
or ((osver like 'Windows Vista%' or osver like 'Windows Server 2008 Service Pack 2%') and (s.productversion not like '6.0.6002.19743' and s.productversion not like '6.0.6002.24067' and s.productversion not glob '6.[1-9].*'))
or ((osver like 'Windows 7%' or osver like 'Windows Server 2008 R2:%') and s.productversion not like '6.1.7601.23689' and s.productversion not glob '6.[2-9].*' and s.productversion not glob '6.1.7601.[2-9]*' and s.productversion not glob '6.1.7601.17[6-9]*')
or ((osver like 'Windows 8%' or (osver like 'Windows Server 2012%' and osver not like '%r2%')) and s.productversion not like '6.2.9200.22099' and s.productversion not glob '6.2.9200.22[1-9]*' and s.productversion not glob '6.[3-9]*')
or ((osver like 'Windows 8.1%' or osver like 'Windows Server 2012 R2%') and s.productversion not like '6.3.9600.18604' and s.productversion not glob '6.3.9600.186[1-9]*' and s.productversion not glob '6.3.9600.18[7-9]*') and s.productversion not glob '6.3.9600.19[0-9]*'
or (osver like 'Windows 10' and s.productversion not like '10.0.10240.17319' and s.productversion not like '10.0.10586.839' and s.productversion not like '10.0.14393.953' and s.productversion not glob '10.0.1[5-9]*')
or (osver like 'Windows Server 2016%' and s.productversion not like '10.0.14393.953' and s.productversion not glob '10.0.[1-8]*')))));
delete from investigate where rowid not in (select max(rowid) from investigate group by computername, auditdate, risk, description, username, department, detail, hoi);

--- Office 
create table office as 
select distinct s.computername, o.productname, s.fileversion from sam s, osinfo o where ((s.computername = o.computername) and s.name like 'excel.exe');

---Statistics
---NOTE FOR FIRST RUN ENSUER THE UPDATE SECTION BELOW IS COMMENTED OUT, ONLY USE FOR SUBSEQUENT UPDATES
--# Drop tables to be Updated
/*
drop table departmentrisks;
drop table bubbles;
drop table execrisks;
drop table compositescore;
drop table stat;
drop table assessment;
*/

-- Department Risks
CREATE TABLE departmentrisks AS select department, risk, count(distinct(computername)) tally from investigate group by department, risk order by tally desc;
-- Bubbles
CREATE TABLE IF NOT EXISTS "Bubbles" ("Risk" text, "Departments" text, "Hosts" text);
insert into Bubbles select distinct(risk), count(distinct(department)) as Departments, count(distinct(Computername)) as Hosts from investigate where risk = '1.Data Loss';
insert into Bubbles select distinct(risk), count(distinct(department)) as Departments, count(distinct(Computername)) as Hosts from investigate where risk = '2.User Behavior';
insert into Bubbles select distinct(risk), count(distinct(department)) as Departments, count(distinct(Computername)) as Hosts from investigate where risk = '3.Network Security';
insert into Bubbles select distinct(risk), count(distinct(department)) as Departments, count(distinct(Computername)) as Hosts from investigate where risk = '4.Services Configuration';
insert into Bubbles select distinct(risk), count(distinct(department)) as Departments, count(distinct(Computername)) as Hosts from investigate where risk = '5.Build';
delete from Bubbles where rowid not in (select max(rowid) from Bubbles group by Risk, Departments, Hosts);
-- Create and populate Department Risks for Executive Review
CREATE TABLE IF NOT EXISTS ExecRisks ("Risk" text, "Description" text, "Departments" text, "Hosts" text, "Total" text);
insert into ExecRisks select risk, description, departments, hosts, sum(departments * hosts) as Total from (select distinct risk, description, count(distinct(department)) as Departments, count(distinct(Computername)) as Hosts from investigate group by risk, description order by count(distinct(department)) desc, count(distinct(Computername)) desc) group by risk, description, departments, Hosts order by Total desc;
delete from ExecRisks where rowid not in (select max(rowid) from ExecRisks group by risk, description, departments, hosts, total);
-- Create and populate CompositeRisk Scores
create table stat as select count(distinct(upper(computername))) as denominator from (assets);
CREATE TABLE IF NOT EXISTS CompositeScore ('Category' text,'Numerator' int,'Denominator' int,'Result' int);
insert into compositescore select category, numerator, denominator, (round(sum((numerator*1.00) /denominator),4)*100) as result  from (select '1.Data Loss' category, (select count(distinct(upper(computername))) from investigate where risk like '1.Data Loss') numerator, (select denominator from stat) denominator, '');
insert into compositescore select category, numerator, denominator, (round(sum((numerator*1.00) /denominator),4)*100) as result  from (select '2.User Behavior' category, (select count(distinct(upper(computername))) from investigate where risk like '2.User Behavior') numerator, (select denominator from stat) denominator, '');
insert into compositescore select category, numerator, denominator, (round(sum((numerator*1.00) /denominator),4)*100) as result  from (select '3.Network Security' category, (select count(distinct(upper(computername))) from investigate where risk like '3.Network Security') numerator, (select denominator from stat) denominator, '');
insert into compositescore select category, numerator, denominator, (round(sum((numerator*1.00) /denominator),4)*100) as result  from (select '4.Services Configuration' category, (select count(distinct(upper(computername))) from investigate where risk like '4.Services Configuration') numerator, (select denominator from stat) denominator, '');
insert into compositescore select category, numerator, denominator, (round(sum((numerator*1.00) /denominator),4)*100) as result  from (select '5.Build' category, (select count(distinct(upper(computername))) from investigate where risk like '5.Build') numerator, (select denominator from stat) denominator, '');

-- Results
create table assessment ("Assessed" int, "Investigate" int, "Risk" int);
insert into assessment select (select denominator from stat), (select count(distinct(upper(computername))) from investigate), '';
update assessment set risk = (select (round(sum(((investigate)*1.00)/assessed),4)*100) from assessment);
select * from assessment;

/*
---Post Processing to reduce db size
drop table allfiles;
drop table netstat;
drop table processes;
drop table services;
drop table servicedlls;
drop table allprofiles;
drop table allusers;
drop table amcache;
drop table prefetch;
drop table secsvcstart;
drop table startups;
drop table syssvcstart;
drop table tasks;
*/
