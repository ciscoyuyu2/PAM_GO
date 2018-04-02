/*
 * ------------------------------------------------------------------
 * monitor_crash_lib.go
 *
 *
 * April, 2018, Paul Yu
 *
 * Copyright (c) 2018 by cisco Systems, Inc.
 * All rights reserved.
 * ------------------------------------------------------------------
 */

package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

type OsTypeInfo struct {
	platform, boardtype, simulator, vf1_3073_ip, hostType, ws, efr, hostname, buildHost, buildDate string
}

type WS struct {
	ws, buildHost, buildDate, efr string
}

var defaultSeverity = []string{
	"emerg",
	"alert",
	"crit",
	"err",
	"warning",
	"notice",
	"info",
	"debug",
}

func getOsType() *OsTypeInfo {
	// OsType := OsTypeInfo{}

	var mount = "/"
	var hostType string
	var simulator string
	// var earmsFile = "/etc/rc.d/rc.local"
	var hostnamecmd = "uname"
	if _, err := os.Stat("/pkg/bin/uname"); err == nil {
		hostnamecmd = "/pkg/bin/uname"
	}
	out, err := exec.Command(hostnamecmd, "-n").Output()
	if err != nil {
		log.Fatal(err)
	}
	hostname := string(out)
	hostname = strings.TrimSuffix(hostname, "\r\n")

	f, err := ioutil.ReadFile(mount + "/proc/cmdline")
	if err != nil {
		log.Fatal(err)
	}
	fStr := string(f)
	fStr = strings.TrimSuffix(fStr, "\n")
	re1 := regexp.MustCompile(`vmtype=(\S+)`)
	vmtype := re1.FindString(fStr)
	vmtype = strings.Replace(vmtype, "vmtype=", "", 1)

	re2 := regexp.MustCompile(`platform=(\S+)`)
	platform := re2.FindString(fStr)
	platform = strings.Replace(platform, "platform=", "", 1)

	re3 := regexp.MustCompile(`boardtype=(\S+)`)
	boardtype := re3.FindString(fStr)
	boardtype = strings.Replace(platform, "boardtype=", "", 1)

	re4 := regexp.MustCompile(`simulator=(\S+)`)
	match, err := regexp.MatchString("simulator=.*", fStr)
	if match == true && err == nil {
		simulator := re4.FindString(fStr)
		simulator = strings.Replace(simulator, "platform=", "", 1)
	} else if err != nil {
		simulator = "no"
	}

	if strings.Contains(vmtype, "xr") {
		hostType = "xr"
	} else if strings.ContainsAny(vmtype, "calvados & sysadmin") {
		hostType = "calvados"
	} else if strings.Contains(vmtype, "host") {
		hostType = "host"
	}

	if strings.Contains(hostname, "uvf") {
		vmtype = "urf"
		hostType = "uvf"
	}
	var vf1_3073_ip string
	var vf1 string
	if strings.ContainsAny(vmtype, "xr & calvados & sysadmin") == true {
		vf1 = "eth-vf1.3073"
		if strings.HasPrefix(platform, "fretta & zermatt & tourin") == true {
			vf1 = "eth-vf1"
		}
		vf1_3073_ip = getOsVrfIp(vf1)
	}

	version := getWS()
	efr := (*version).efr
	ws := (*version).ws
	buildHost := (*version).buildHost
	buildDate := (*version).buildDate

	OsType := OsTypeInfo{
		platform:    platform,
		boardtype:   boardtype,
		simulator:   simulator,
		vf1_3073_ip: vf1_3073_ip,
		hostType:    hostType,
		ws:          ws,
		hostname:    hostname,
		buildHost:   buildHost,
		buildDate:   buildDate,
		efr:         efr,
	}
	// fmt.Println(OsType)

	return &OsType
}

func getWS() *WS {
	var mount = "/"
	var showFile = mount + "/etc/show_version.txt"
	var buildFile = mount + "/etc/build-info.txt"
	var delimiter string
	WSInfo := WS{
		ws:        "",
		buildHost: "",
		buildDate: "",
		efr:       "",
	}

	if _, err := os.Stat(showFile); err == nil {

		f, err := ioutil.ReadFile(showFile)
		if err != nil {
			log.Fatal(err)
		}
		fStr := string(f)
		fStr = strings.TrimSuffix(fStr, "\n")
		re1 := regexp.MustCompile(`Workspace = (\S+)`)
		ws := re1.FindString(fStr)
		ws = strings.Replace(ws, "Workspace = ", "", 1)

		re2 := regexp.MustCompile(`Host = (\S+)`)
		buildHost := re2.FindString(fStr)
		buildHost = strings.Replace(buildHost, "Host = ", "", 1)

		re3 := regexp.MustCompile(`Date: (\w+ \w+ \d+ ([0-5]\d):([0-5]\d):([0-5]\d) \w+ \d+)`)
		buildDate := re3.FindString(fStr)
		buildDate = strings.Replace(buildDate, "Date: ", "", 1)

		re4 := regexp.MustCompile(`Lineup = (\S+)`)
		efrString := re4.FindString(fStr)
		re5 := regexp.MustCompile(`(00000+\d+)`)
		efr := re5.FindString(efrString)

		WSInfo = WS{
			ws:        ws,
			buildDate: buildDate,
			buildHost: buildHost,
			efr:       efr,
		}

	} else if os.IsNotExist(err) {
		WSInfo = WS{
			ws:        "",
			buildHost: "",
			buildDate: "",
			efr:       "",
		}
	} else if _, err := os.Stat(buildFile); err == nil {
		f, err := ioutil.ReadFile(buildFile)
		if err != nil {
			log.Fatal(err)
		} else {
			fStr := string(f)
			fStr = strings.TrimSuffix(fStr, "\n")
			//need figure out how to handle delimiter in go
			if strings.Contains(fStr, "xr") {
				delimiter = "### XR Information"
			} else if strings.ContainsAny(fStr, "calvados & sysadmin") {
				delimiter = "### Calvados Information"
			} else if strings.Contains(fStr, "host") {
				delimiter = "### Thirdparty Information"
			}
			stringSlice := strings.Split(fStr, delimiter)
			fmt.Println(stringSlice)
			re1 := regexp.MustCompile(`Workspace = (\S+)`)
			ws := re1.FindString(fStr)
			ws = strings.Replace(ws, "Workspace = ", "", 1)

			re2 := regexp.MustCompile(`Host = (\S+)`)
			buildHost := re2.FindString(fStr)
			buildHost = strings.Replace(buildHost, "Host = ", "", 1)

			re3 := regexp.MustCompile(`Built On \s+: (\w+ \w+ \d+ ([0-5]\d):([0-5]\d):([0-5]\d) \w+ \d+)`)
			buildDate := re3.FindString(fStr)
			buildDate = strings.Replace(buildDate, "Built On     : ", "", 1)

			re4 := regexp.MustCompile(`Lineup = (\S+)`)
			efrString := re4.FindString(fStr)
			re5 := regexp.MustCompile(`(00000+\d+)`)
			efr := re5.FindString(efrString)

			WSInfo = WS{
				ws:        ws,
				buildDate: buildDate,
				buildHost: buildHost,
				efr:       efr,
			}
		}

	}
	return &WSInfo
}

func getOsVrfIp(intfname string) string {
	var ip string
	netns_cmd := ""
	var mount = "/"
	f, err := ioutil.ReadFile(mount + "/proc/cmdline")
	if err != nil {
		log.Fatal(err)
	}
	fStr := string(f)
	fStr = strings.TrimSuffix(fStr, "\n")

	re1 := regexp.MustCompile(`vmtype=(\S+)`)
	vmtype := re1.FindString(fStr)
	// vmtype = strings.Replace(vmtype, "vmtype=", "", 1)

	re2 := regexp.MustCompile(`platform=(\S+)`)
	platform := re2.FindString(fStr)
	// platform = strings.Replace(platform, "platform=", "", 1)

	if strings.Contains(vmtype, "xr") && strings.ContainsAny(platform, "panini & scapa & ncs4k & ncs6k") == false {
		myPid := os.Getpid()
		netns_identify := `/sbin/ip netns identify ` + string(myPid)
		out, err := exec.Command(netns_identify).Output()
		if err != nil {
			log.Fatal(err)
		}
		outputs := string(out)
		if strings.Contains(outputs, "xrnns") == false {
			netns_cmd = "/sbin/ip netns exec xrnns "
		}
	}

	if strings.ContainsAny(platform, "fretta & asr9k & skywarp & ncs5k & ncs5500 & ncs540 & rosco & ncs1 & mystique & ncs560") {
		// command1 := netns_cmd + `netns_cmd /sbin/ifconfig ` + intfname + `|grep "inet addr"`
		ipAddress1, err := exec.Command("/sbin/ifconfig", intfname).Output()
		if err != nil {
			log.Fatal(err)
		}
		ip = string(ipAddress1)
	} else {
		if _, err := os.Stat("/opt/cisco/calvados/sbin/ccc_driver"); err == nil && strings.Contains(intfname, "eth-vf1.513") {
			command2 := netns_cmd + `/sbin/chvrf 2 /sbin/ifconfig ` + intfname + `grep "inet addr"`
			ipAddress2, err := exec.Command(command2).Output()
			if err != nil {
				log.Fatal(err)
			}
			ip = string(ipAddress2)
		} else if _, err := os.Stat("/opt/cisco/calvados/sbin/ccc_driver"); err == nil && strings.ContainsAny(intfname, "eth-vf1.3073 & eth-vf1.3074") {
			command3 := netns_cmd + `/sbin/chvrf 0 /sbin/ifconfig ` + intfname + `grep "inet addr"`
			ipAddress3, err := exec.Command(command3).Output()
			if err != nil {
				log.Fatal(err)
			}
			ip = string(ipAddress3)
		} else {
			command4 := netns_cmd + `/sbin/ifconfig ` + intfname + `grep "inet addr"`
			ipAddress4, err := exec.Command(command4).Output()
			if err != nil {
				log.Fatal(err)
			}
			ip = string(ipAddress4)
		}
	}
	re3 := regexp.MustCompile(`inet addr:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)
	ipaddress := re3.FindString(ip)
	ip = strings.Replace(ipaddress, "inet addr:", "", 1)
	ip = strings.TrimRight(ip, "\n")
	return ip
}

func getPamLogDir() string {
	var logDir = "/harddisk:/cisco_support/"
	if _, err := os.Stat(logDir); err != nil {
		logDir = "${HOME}/cisco_support/"
	}
	return logDir
}

func createFolder(logdir string) bool {
	if _, err := os.Stat(logdir); os.IsNotExist(err) {
		err = os.MkdirAll(logdir, 0755)
		if err != nil {
			return false
		}
	}
	return true
}

func stringInSlice(list []string, str string) bool {
	for _, v := range list {
		if v == str {
			return true
		}
	}
	return false
}

func getRpIPFromSysdb() map[string]interface{} {
	var mount = "/"
	netns_cmd := ""
	sysdbInfo := make(map[string]interface{})
	var nodeList []string
	f, err := ioutil.ReadFile(mount + "/proc/cmdline")
	if err != nil {
		log.Fatal(err)
	}
	fStr := string(f)
	fStr = strings.TrimSuffix(fStr, "\n")
	fmt.Println(strings.ContainsAny(fStr, "panini & scapa & ncs4k & ncs6k"))
	if strings.Contains(fStr, "xr") && strings.ContainsAny(fStr, "panini & scapa & ncs4k & ncs6k") == false {
		myPid := os.Getpid()
		netns_identify := `/sbin/ip netns identify ` + string(myPid)
		out, err := exec.Command(netns_identify).Output()
		if err != nil {
			log.Fatal(err)
		}
		outputs := string(out)
		if strings.Contains(outputs, "xrnns") == false {
			netns_cmd = "/sbin/ip netns exec xrnns "
		}
	}

	if _, err := os.Stat("/pkg/bin/show_platform_sysdb"); err == nil {
		cmd := exec.Command(netns_cmd+"/pkg/bin/show_platform_sysdb", "-v")
		out, err := cmd.Output()
		if err != nil {
			log.Fatal(err)
		}
		fStr := string(out)
		fStr = strings.TrimSuffix(fStr, "\r\n")
		re1 := regexp.MustCompile(`\s*(\S+)\s+(R[S]?P|LC)\s+\((\S+)\)\s+\S+\s+FINAL Band\s+(\d+\.\d+\.\d+\.\d+)`)
		a := re1.FindAllStringSubmatch(fStr, -1)
		for i, v := range a {
			Node := a[i][1]
			nodeList = append(nodeList, Node)
			sysdbInfo["nodeList"] = nodeList
			sysdbInfo[v[1]] = map[string]interface{}{
				"IP":   v[4],
				"type": v[3],
			}
		}
		fmt.Println(sysdbInfo)
	}
	return sysdbInfo
}

func getChassisID(osType interface{}) string {
	if o, ok := osType.(*OsTypeInfo); ok {
		hostType := o.hostType
		boardtype := o.boardtype
		vf1_3073_ip := o.vf1_3073_ip
		osType := o.hostType
		fmt.Println(hostType, boardtype, vf1_3073_ip, osType)
		if strings.Contains(o.hostType, "xr") == true {
			nodeInfo := getRpIPFromSysdb()
			for _, v := range nodeInfo {
				switch vv := v.(type) {
				case []string:
					for _, v := range vv {
						if nodeInfo[v].(map[string]interface{})["IP"] == vf1_3073_ip {
							chassisID := getChassisIDFromNode(v)
							return chassisID
						}
					}
				}
			}
		} else if strings.Contains(o.hostType, "sysadmin & calvados") == true {
			//verify calvados
			fmt.Println("waiting for calvados verification")
		}
	}
	return ""
}

func getChassisIDFromNode(node string) string {
	node = strings.TrimSuffix(node, "\r\n")
	re1 := regexp.MustCompile(`(\d+)\/(R[S]?P)?\d+\/(CPU|VM)?\d+`)
	a := re1.FindAllStringSubmatch(node, -1)
	result := a[0][1]
	return result

}

func createSyslog(osType interface{}, message string, severity ...string) {
	var netns_cmd = ""
	var cmd = ""
	var s string
	if o, ok := osType.(*OsTypeInfo); ok {
		platform := o.platform
		osType := o.hostType
		if len(severity) > 0 {
			s = severity[0]
			if stringInSlice(defaultSeverity, s) == false {
				s = "info"
			}
		} else {
			s = "info"
		}

		if strings.Contains(osType, "xr") && strings.ContainsAny(platform, "panini & scapa & ncs4k & ncs6k") == false {
			myPid := os.Getpid()
			netns_identify := `/sbin/ip netns identify ` + string(myPid)
			out, err := exec.Command(netns_identify).Output()
			if err != nil {
				log.Fatal(err)
			}
			outputs := string(out)
			if strings.Contains(outputs, "xrnns") == false {
				netns_cmd = "/sbin/ip netns exec xrnns "
			}
		}

		if strings.Contains(osType, "xr") {
			cmd = netns_cmd + "/pkg/bin/logger"
			_, err := exec.Command(cmd, "-s", s, message).Output()
			if err != nil {
				log.Fatal(err)
			}
		} else if strings.Contains(osType, "calv") {
			if strings.ContainsAny(platform, "panini & scapa & ncs4k & ncs6k") {
				chvrf := netns_cmd + "/sbin/chvrf 0"
				cmd = netns_cmd + chvrf + "/opt/cisco/calvados/bin/cal_logger"
				_, err := exec.Command(cmd, "-s", s, message).Output()
				if err != nil {
					log.Fatal(err)
				}
			}
		} else {
			cmd = "/usr/bin/logger"
			_, err := exec.Command(cmd).Output()
			if err != nil {
				log.Fatal(err)
			}
		}
	}
}

func pamLogger(osType interface{}, pamLogDir, msg, bucket string) bool {
	var status bool
	status = false
	if o, ok := osType.(*OsTypeInfo); ok {
		pamfile := pamLogDir + "/pam-" + bucket + ".log"
		osType := o.hostType
		ret := createFolder(pamLogDir)
		if ret == false {
			var severity = "warning"
			createSyslog(osType, msg, severity)
			status = false
		}
		t := time.Now().String()
		t = strings.TrimSuffix(t, "\r\n")
		f, err := ioutil.ReadFile(pamfile)
		fStr := string(f)
		if err != nil {
			log.Fatal(err)
		} else {
			fmt.Println(fStr + strings.Repeat("=", 10) + t + strings.Repeat("=", 10) + "\n")
			status = true
		}
	}
	return status
}

// func checkProcess(osType interface{}) []string {
// 	var exclude_pid = 0
// 	var min_pid = 200
// 	var processName string
// 	var allPros []int
// 	var proc_dir = "/proc"
// 	var osTypeInfo = ""
// 	var files []string

// 	if o, ok := osType.(*OsTypeInfo); ok {
// 		osType := o.hostType
// 		f, err := ioutil.ReadDir(proc_dir)
// 		if err != nil {
// 			return files
// 		} else {

// 		}
// 	}
// }
