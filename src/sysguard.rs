use std::collections::HashMap;
use std::net::TcpListener;

use pnet::datalink;
use regex::Regex;
use serde::{Serialize, Deserialize};
use indoc::formatdoc;

use crate::util;

enum Mark {
    OK,
    ERR,
}

impl Mark {
    fn as_str(&self) -> &str {
        match self {
            Mark::OK => {
                "✓"
            },
            Mark::ERR => {
                "✗"
            },
        }
    }
    fn from(v: bool) -> Self {
        if v {
            Mark::OK
        } else {
            Mark::ERR
        }
    }
}

pub enum GuardItem {
    OS,
    IP,
    UserMgmt,
    PasswdComplexity,
    OperationTimeout,
    Port,
    Audit,
    IPTables,
    Service,
    CommandHistory,
}

#[derive(Serialize, Deserialize)]
pub struct GuardCell {
    pub mp: HashMap<String, String>,
}

impl GuardCell {
    pub fn new() -> Self {
        GuardCell {
            mp: HashMap::new(),
        }
    }

    pub fn add<S1, S2>(&mut self, pos: S1, val: S2) where S1: AsRef<str>, S2: AsRef<str> {
        self.mp.insert(pos.as_ref().to_string(), val.as_ref().to_string());
    }

    pub fn get<S>(&self, pos: S) -> String where S: AsRef<str> {
        if let Some(v) = self.mp.get(pos.as_ref()) {
            v.to_string()
        } else {
            "".to_string()
        }
    }
}

impl GuardItem {
    pub fn check(&self) -> GuardCell {
        let mut cell = GuardCell::new();
        match self {
            GuardItem::OS => {
                cell.add("A4", "操作系统");  //操作系统(operating system)
                if let Ok(r) = util::runcmd("cat /etc/issue", None) {
                    cell.add("B4", r.trim().replace("\r", " ").replace("\n", " "));
                } else {
                    println!("cannot read /etc/issue");
                    cell.add("B4", "");
                }
            },
            GuardItem::IP => {
                cell.add("A5", "设备 IP");  //设备 IP(Device IP)
                let mut iplist = vec![];
                for iface in datalink::interfaces() {
                    let ips = iface.ips.iter().filter(|x| x.is_ipv4())
                        .map(|x| x.ip().to_string().trim().to_string())
                        .filter(|x| x != "127.0.0.1")
                        .collect::<Vec<String>>();
                    if ips.len() > 0 {
                        iplist.extend(ips);
                    }
                }
                cell.add("B5", &iplist.join(";"));
            },
            GuardItem::UserMgmt => {
                cell.add("A8", "用户管理");  //用户管理(user management)

                // Umask is a shell built-in command, so it cannot be run directly through the Command module. The solution comes from
                // https://stackoverflow.com/questions/32146111/run-shell-builtin-command-in-python
                let mark = if let Ok(r) = util::runcmd("bash -i -c 'umask'", None) {
                    if r.trim() == "0022" {
                        Mark::from(true)
                    } else {
                        println!("[x] cannot run command 'umask'");
                        Mark::from(false)
                    }
                } else {
                    Mark::from(false)
                };
                cell.add("B8", &formatdoc!(r#"
                        [  ]应删除或锁定过期帐户、无用帐户和隐藏账号  //Expired accounts, useless accounts, and hidden accounts should be deleted or locked
                        [{}]每个用户是否按要求开展权限设置  //Has each user carried out permission settings as required
                    "#,  mark.as_str()),
                );

                let users = if let Ok(r) = util::runcmd("cat /etc/passwd", None) {
                    let lines = r.trim().lines()
                        .filter(|x| !x.trim().ends_with("/nologin") && !x.trim().ends_with("/false") && !x.trim().starts_with("#"))
                        .collect::<Vec<&str>>();
                    lines.join("\n")
                } else {
                    println!("cannot read /etc/passwd");
                    "".to_string()
                };
                cell.add("C9", &users);

                let mark = if let Ok(r) = util::runcmd("cat /etc/passwd", None) {
                    if let Some(_) = r.trim().lines().filter(|x| x.trim().starts_with("root")).nth(0) {
                        Mark::from(false)
                    } else {
                        Mark::from(true)
                    }
                } else {
                    println!("cannot read /etc/passwd");
                    Mark::from(false)
                };
                cell.add("B9", &formatdoc!("[{}]不能使用默认用户名，例如：root、superadmin、administrator等", mark.as_str()));  //Cannot use default usernames, such as root, superadmin, administrator, etc

            },
            GuardItem::PasswdComplexity => {
                cell.add("A10", "密码复杂度配置");  //密码复杂度配置(Password complexity configuration)

                #[derive(Debug, Serialize, Deserialize)]
                struct Passwd {
                    minimum_size: u32,
                    is_strong_combination: bool,
                    update_cycle: u32,
                }

                impl Default for Passwd {
                    fn default() -> Self {
                        Passwd {
                            minimum_size: 0u32,
                            is_strong_combination: false,
                            update_cycle: 99999u32,
                        }
                    }
                }

                let mut passwd = Passwd::default();

                if let Ok(r) = util::runcmd("cat /etc/login.defs", None) {
                    let get_value = |line: &str| -> Option<u32> {
                        if let Some(v) = line.split("\t").filter(|x| x.trim().len() > 0).nth(1) {
                            if let Ok(v) = v.parse::<u32>() {
                                return Some(v);
                            }
                        };
                        return None;
                    };
                    for line in r.trim().lines() {
                        if line.starts_with("PASS_MIN_LEN") {
                            if let Some(v) = get_value(line) {
                                passwd.minimum_size = v;
                            }
                        }

                        if line.starts_with("PASS_MAX_DAYS") {
                            if let Some(v) = get_value(line) {
                                passwd.update_cycle = v;
                            }
                        }
                    }
                } else {
                    println!("cannot read /etc/login.defs");
                }

                if let Ok(r) = util::runcmd("cat /etc/pam.d/system-auth", None) {
                    let mut credits = HashMap::new();

                    let credit_lines = r.trim().lines().filter(|x|
                        x.trim().starts_with("password requisite pam_cracklib")
                    ).collect::<Vec<&str>>();

                    if let Some(credit_line) = credit_lines.get(0) {
                        let re = Regex::new(r"([dulo]credit\s*=\s*-\d+)").unwrap();
                        for cap in re.captures_iter(credit_line) {
                            let kv = &cap[1].split("=").collect::<Vec<&str>>();
                            let (name, value) = (kv.get(0), kv.get(1));
                            if let Some(name) = name {
                                let value = if let Some(v) = value {
                                    if let Ok(v) = v.parse::<i32>() {
                                        v
                                    } else {
                                        0
                                    }
                                } else {
                                    0
                                };
                                credits.insert(name.to_string(), value);
                            }
                        }
                    }

                    let cond = |k: &str| {
                        if let Some(&v) = credits.get(k) {
                            v
                        } else {
                            0
                        }
                    };
                    if cond("ucredit") <= -2 && cond("lcredit") <= -1 && cond("dcredit") <= -4 && cond("ocredit") <= -1 {
                        passwd.is_strong_combination = true;
                    }
                } else {
                    println!("cannot read /etc/pam.d/system-auth");
                };

                cell.add("B10", &formatdoc!("
                        [{}]密码长度不小于8位  //Password length not less than 8 digits
                        [{}]采取字母、数字和特殊字符的混合组合  //Adopting a mixed combination of letters, numbers, and special characters
                        [  ]密码与用户名不相同  //Password and username are not the same
                        [{}]密码更新周期180天  //Password update cycle 180 days
                    ",
                    Mark::from(passwd.minimum_size >= 8).as_str(),
                    Mark::from(passwd.is_strong_combination).as_str(),
                    Mark::from(passwd.update_cycle <= 180).as_str(),
                ));
            },
            GuardItem::OperationTimeout => {
                cell.add("A11", "登录终端的操作超时锁定");  //登录终端的操作超时锁定(Lock after login terminal operation timeout)

                let mut tmout = None;
                if let Ok(r) = util::runcmd("cat /etc/profile", None) {
                    let re = Regex::new(r"TMOUT=(\d+)").unwrap();
                    for line in r.lines().rev() {
                        let line = line.trim();
                        if let Some(mat) = re.find(line) {
                            if let Some(v) = line[mat.start()..mat.end()].split("=").nth(1) {
                                tmout = Some(v.to_string())
                            }
                        }
                    }
                } else {
                    println!("cannot read /etc/profile");
                }

                let mut mark = Mark::ERR;
                if let Some(tmout) = tmout {
                    if let Ok(v) = tmout.parse::<i32>() {
                        // The default timeout unit is seconds, and the timeout time is required to be less than or equal to 10 minutes
                        if v <= 600 {
                            mark = Mark::OK;
                        }
                    }
                }

                cell.add("B11", &format!("[{}]设置操作超时为小于或等于10分钟", mark.as_str()));  //设置操作超时为小于或等于10分钟(Set the operation timeout to be less than or equal to 10 minutes)
            },
            GuardItem::Port => {
                cell.add("A14", "高危端口封闭");  //高危端口封闭(High risk port closure)

                let tcp_port_list = vec![135, 137, 138, 139, 445, 3389];
                let is_tcp_port_opened = |port: usize| -> bool {
                    match TcpListener::bind(("127.0.0.1", port as u16)) {
                        Ok(_) => true,
                        Err(_) => false,
                    }
                };
                let mut mp = HashMap::new();
                for port in tcp_port_list {
                    if is_tcp_port_opened(port) {
                        mp.insert(port, true);
                    }
                }

                cell.add("B14", &formatdoc!("
                        [{}]关闭135  //shutdown port 135
                        [{}]关闭137  //shutdown port 137
                        [{}]关闭138  //shutdown port 138
                        [{}]关闭139  //shutdown port 139
                        [{}]关闭445  //shutdown port 445
                        [{}]关闭3389  //shutdown port 3389
                    ",
                    Mark::from(!mp.contains_key(&135)).as_str(),
                    Mark::from(!mp.contains_key(&137)).as_str(),
                    Mark::from(!mp.contains_key(&138)).as_str(),
                    Mark::from(!mp.contains_key(&139)).as_str(),
                    Mark::from(!mp.contains_key(&445)).as_str(),
                    Mark::from(!mp.contains_key(&3389)).as_str(),
                ));
            },
            GuardItem::Service => {
                cell.add("A15", "关闭服务");   //关闭服务(shutdown services)

                let parse = |line: &str| -> Option<(String, [bool; 7])> {
                    let items = line.split("\t").filter(|x| x.trim().len() > 0).collect::<Vec<&str>>();
                    if items.len() != 8 {
                        return None;
                    }
                    let name = items[0].to_string();
                    // Whether the status is open or not, true indicates open
                    let mut switches: [bool; 7] = [true; 7];
                    for (idx, item) in items[1..].iter().enumerate() {
                        if let Some(status) = item.split(":").nth(1) {
                            if status == "关闭" {
                                //关闭(shutdown)
                                switches[idx] = false;
                            } else {
                                switches[idx] = true;
                            }
                        }
                    }
                    return Some((name, switches));
                };
                let service_name_main_list = vec![
                    // email service
                    "sendmail", "postfix",
                    // ftp service
                    "ftp", "vsftpd",
                    "telnet",
                    "rlogin",
                    "netbios",
                    "dhcpd",
                    // samba service: smb or samba
                    "smb", "samba",
                    "snmpd",
                    //remote desktop: vncserver or xdmcp
                    "xdmcp", "vncserver",
                ];

                let service_name_extra_list = vec![
                    "bluetooth",
                    "rwho",
                    "sh",
                    "rsh",
                    "rexec",
                    "sendmail",
                    "tftp",
                    "http",
                    "nfs",
                    "smtp",
                ];

                let mut mp = HashMap::<String, bool>::new();
                if let Ok(r) = util::runcmd("chkconfig --list", None) {
                    for line in r.lines() {
                        if let Some((name, switches)) = parse(line) {
                            let name = name.as_str();

                            //Update the actual service status
                            let is_service_enabeld = switches[2] && switches[3] && switches[4] && switches[5];
                            if service_name_main_list.contains(&name) && is_service_enabeld {
                                mp.insert(name.to_string(), true);
                            }
                            if service_name_extra_list.contains(&name) && is_service_enabeld {
                                mp.insert("minimum_service".to_string(), true);
                                mp.insert(name.to_string(), true);
                            }
                        }
                    }
                } else {
                    println!("cannot run 'chkconfig --list'");
                }

                let mut extra_open_service_list = vec![];
                for name in service_name_extra_list {
                    if mp.contains_key(name) {
                        extra_open_service_list.push(name);
                    }
                }
                let extra_open_service_list_desc = if extra_open_service_list.len() > 0 {
                    format!("以下服务未关闭：{}", extra_open_service_list.join("、"))  //以下服务未关闭(The following services have not been closed)
                } else {
                    "".to_string()
                };

                cell.add("B15", &formatdoc!("
                        [{}]E-Mail
                        [{}]FTP
                        [{}]telnet
                        [{}]rlogin
                        [{}]NetBIOS
                        [{}]DHCP
                        [{}]SMB
                        [{}]SNMPV3 and below versions
                        [{}]Remote desktop
                        [{}]Close other non essential services
                    ",
                    Mark::from(!(mp.contains_key("sendmail") || mp.contains_key("postfix"))).as_str(),
                    Mark::from(!(mp.contains_key("ftp") || mp.contains_key("vsftpd"))).as_str(),
                    Mark::from(!mp.contains_key("telnet")).as_str(),
                    Mark::from(!mp.contains_key("rlogin")).as_str(),
                    Mark::from(!mp.contains_key("netbios")).as_str(),
                    Mark::from(!mp.contains_key("dhcpd")).as_str(),
                    Mark::from(!(mp.contains_key("smb") || mp.contains_key("samba"))).as_str(),
                    Mark::from(!mp.contains_key("snmpd")).as_str(),
                    Mark::from(!(mp.contains_key("xdmcp") || mp.contains_key("vncserver"))).as_str(),
                    Mark::from(!mp.contains_key("minimum_service")).as_str(),
                ));

                cell.add("C15", &extra_open_service_list_desc);
            },
            GuardItem::Audit => {
                cell.add("A19", "远程访问/系统审计/审计内容");  //远程访问/系统审计/审计内容(Remote access/system audit/audit content)

                let mut mp = HashMap::new();

                if let Ok(r) = util::runcmd("cat /etc/ssh/sshd_config", None) {
                    for line in r.lines() {
                        let line = line.trim();
                        if line.starts_with("Port") {
                            if let Some(port) = line.split(" ").filter(|x| x.trim().len() > 0).nth(1) {
                                if port != "22" {
                                    mp.insert("not_default_ssh_port", true);
                                }
                            }
                        }
                        if line.trim().starts_with("SyslogFacility AUTH")  {
                            mp.insert("ssh_syslog_enabled", true);
                        }
                    }
                } else {
                    println!("cannot read /etc/ssh/sshd_config");
                }

                if let Ok(r) = util::runcmd("cat /etc/logrotate.conf", None) {
                    for line in r.lines() {
                        if line.starts_with("rotate ") {
                            if let Some(cycle) = line.split(" ").nth(1) {
                                if let Ok(cycle) = cycle.parse::<i32>() {
                                    if cycle >= 54 {
                                        mp.insert("logrotate_cycle_passed", true);
                                    }
                                }
                            }
                            break;
                        }
                    }
                } else {
                    println!("cannot read /etc/logrotate.conf");
                }

                let service_list = vec!["sshd", "rsyslog", "auditd"];
                for service in service_list {
                    let cmd = format!("service {} status", service);
                    if let Ok(r) = util::runcmd(&cmd, None) {
                        if r.contains("正在运行") {
                            //正在运行(running)
                            mp.insert(service, true);
                        }
                    } else {
                        println!("cannnot run command '{}'", &cmd);
                    }
                }

                let audit_file_list = vec![
                    "/etc/group", "/etc/passwd", "/etc/ssh/sshd_config", "/etc/shadow",
                    "/etc/sudoers", "/var/log/lastlog", "/etc/profile", "/etc/sysctl.conf",
                ];
                if let Ok(r) = util::runcmd("auditctl -l", None) {
                    let mut watch_rule_indicator = HashMap::new();
                    for audit_line in r.lines() {
                        let audit_line = audit_line.trim();
                        if audit_line.starts_with("-w") {
                            // Matching Pattern "-w /etc/profile.d/ -p rwxa"
                            let re = Regex::new(r"^-w\s+([^ ]+)\s+-p\s+([^ ]+)$").unwrap();
                            let caps = re.captures(audit_line).unwrap();
                            let watch_file = caps.get(1).map_or("", |m| m.as_str());
                            let watch_action = caps.get(2).map_or("", |m| m.as_str());
                            if audit_file_list.contains(&watch_file) && watch_action.contains(&['w', 'a'][..]) {
                                watch_rule_indicator.insert(watch_file, true);
                            }
                        }
                    }
                    let mut audit_file_passed = true;
                    for audit_file in audit_file_list {
                        if !watch_rule_indicator.contains_key(audit_file) {
                            audit_file_passed = false;
                            break;
                        }
                    }
                    if audit_file_passed {
                        mp.insert("audit_file_passed", true);
                    }
                } else {
                    println!("cannot run 'auditctl -l'");
                }

                cell.add("B19", &formatdoc!("
                        [{}]开启系统日志进程(syslog)  //Run the system log process (syslog)
                        [{}]开启审计进程(auditd)  //Run the audit process (auditd)
                        [{}]开启SSH日志审计  //Enable SSH log auditing
                        [{}]审计内容保存6个月  //Keep audit content for 6 months
                        [  ]将审计内容发送到其他日志审计设备存储  //Send audit content to other log audit devices for storage
                        [{}]至少包括：用户的添加和删除、审计功能的启动和关闭、审计策略的调整、权限变更、系统资源的异常使用、重要的系统操作（如用户登录、退出）等
                        //At least including: adding and deleting users, starting and closing audit functions, adjusting audit policies, changing permissions, abnormal use of system resources, important system operations (such as user login and logout), etc
                        [{}]启用SSH  //Enable SSH
                        [{}]修改SSH默认端口  //Modify SSH default port
                    ",
                    Mark::from(mp.contains_key("rsyslog")).as_str(),
                    Mark::from(mp.contains_key("auditd")).as_str(),
                    Mark::from(mp.contains_key("ssh_syslog_enabled")).as_str(),
                    Mark::from(mp.contains_key("logrotate_cycle_passed")).as_str(),
                    Mark::from(mp.contains_key("audit_file_passed")).as_str(),
                    Mark::from(mp.contains_key("sshd")).as_str(),
                    Mark::from(mp.contains_key("not_default_ssh_port")).as_str(),
                ));
            },
            GuardItem::IPTables => {
                cell.add("A21", "设定终端接入方式、网络地址范围");  //设定终端接入方式、网络地址范围(Set terminal access method and network address range)
                let iplist = if let Ok(r) = util::runcmd("cat /etc/sysconfig/iptables", None) {
                    let mut iplist = vec![];
                    for line in r.lines() {
                        if line.starts_with("-A whitelist") {
                            let re = Regex::new(r"(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}/(\d{1,2})?)").unwrap();
                            let caps = re.captures(line).unwrap();
                            let ip = caps.get(1).map_or("", |m| m.as_str());
                            iplist.push(ip);
                        }
                    }
                    iplist.join(";")
                } else {
                    println!("cannot read '/etc/sysconfig/iptables'");
                    "".to_string()
                };
                cell.add("C21", &iplist);
            },
            GuardItem::CommandHistory => {
                cell.add("A25", "his命令");  //his命令(his command)

                let mut mp = HashMap::<&str, usize>::new();
                if let Ok(r) = util::runcmd("cat /etc/profile", None) {
                    let parse_size = |re: &Regex, line: &str| -> Option<usize> {
                        if let Some(caps) = re.captures(line) {
                            if let Some(histsz) = caps.get(1) {
                                if let Ok(histsz) = histsz.as_str().parse::<usize>() {
                                    return Some(histsz);
                                }
                            }
                        }
                        return None;
                    };
                    let re_histsz = Regex::new(r"HISTSIZE=(\d+)").unwrap();
                    let re_histfsz = Regex::new(r"HISTFILESIZE=(\d+)").unwrap();
                    for line in r.lines() {
                        if !line.trim().starts_with("#") {
                            if let Some(v) = parse_size(&re_histsz, line) {
                                mp.insert("HISTSIZE", v);
                            }
                            if let Some(v) = parse_size(&re_histfsz, line) {
                                mp.insert("HISTFILESIZE", v);
                            }
                        }
                    }
                } else {
                    println!("cannot read /etc/profile");
                }
                let histsz = mp.get("HISTSIZE").map_or(50000, |&v| v);
                let histfsz = mp.get("HISTFILESIZE").map_or(50000, |&v| v);
                cell.add("B25", &format!("[{}]删除系统his命令", Mark::from(histsz <= 5 && histfsz <= 5).as_str()));  //删除系统his命令(delete his command from system)
            },
        }
        cell
    }
}
