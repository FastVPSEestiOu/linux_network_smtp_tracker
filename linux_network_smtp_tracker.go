package main

/*

Based on
	https://github.com/FastVPSEestiOu/linux_network_activity_tracker

*/
import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

const proc_tcp = "/proc/net/tcp"
const proc_tcp6 = "/proc/net/tcp6"

var out io.Writer = ioutil.Discard
var smtp_ports map[uint64]string
var max_smtp_connections_number uint
var SocketInodeMap map[uint64]uint64
var work_mux sync.Mutex
var json_output bool

func init() {
	maxConnCountFlag := flag.Uint("m", 128, "Max count smtp connections, which we ignored")
	jsonFlag := flag.Bool("j", false, "Output in json")
	flag.Parse()

	smtp_ports = map[uint64]string{
		25:  "SMTP",
		587: "SMTP TLS",
	}

	max_smtp_connections_number = *maxConnCountFlag

	json_output = *jsonFlag
	if json_output {
		out = ioutil.Discard
	} else {
		out = os.Stdout
	}

}

type PidInfo struct {
	Pid  uint64 `json:"pid"`
	Name string `json:"pid_name"`
	Ctid uint32 `json:"ctid"`
	Uid  uint64 `json:"uid"`
	Gid  uint64 `json:"gid"`
}

type InetConnection struct {
	IpLocal    string  `json:"ip_local"`
	IpRemote   string  `json:"ip_remote"`
	PortLocal  uint64  `json:"port_local"`
	PortRemote uint64  `json:"port_remote"`
	Inode      uint64  `json:"inode"`
	Type       string  `json:"type"`
	BadLocal   bool    `json:"bad_local"`
	Reason     string  `json:"reason"`
	Process    PidInfo `json: "process"`
}

var SmtpConnections []InetConnection

func main() {
	/*

		Get all tcp/tcp6/  connections from /proc/net via 2 thread

	*/

	runtime.GOMAXPROCS(4)
	runtime.UnlockOSThread()
	var waitReadNetProc sync.WaitGroup
	waitReadNetProc.Add(2)
	go func() {
		defer waitReadNetProc.Done()
		err := GetAndParseNetFile(proc_tcp, "tcp")
		if err != nil {
			fmt.Fprintln(out, "Cannot read proc net tcp file")
			fmt.Fprintln(out, err)
			os.Exit(1)
		}
	}()
	go func() {
		defer waitReadNetProc.Done()
		err := GetAndParseNetFile(proc_tcp6, "tcp6")
		if err != nil {
			fmt.Fprintln(out, "Cannot read proc net tcp file")
			fmt.Fprintln(out, err)
			os.Exit(1)
		}
	}()
	waitReadNetProc.Wait()

	/*
		End get all connections
	*/

	// Not found suspicious connections - exit
	if len(SmtpConnections) == 0 {
		fmt.Fprintln(out, "We not find smtp connections")
		os.Exit(0)
	}
	fmt.Fprintln(out, "We found ", len(SmtpConnections), " smtp connetions")
	fmt.Fprintln(out, "Found they process, please be patient")

	// Get all pids
	pidList := GetPidList()

	SocketInodeMap = make(map[uint64]uint64)
	forOneThread := len(pidList) / 4
	forOneThread++

	/*
		Build inode -> pid map
	*/

	var waitGetSockMap sync.WaitGroup
	waitGetSockMap.Add(4)
	go func() {
		defer waitGetSockMap.Done()
		for _, pid := range pidList[:forOneThread] {
			GetLinksForPidToMap(pid)
		}
	}()
	go func() {
		defer waitGetSockMap.Done()
		for _, pid := range pidList[forOneThread : forOneThread*2] {
			GetLinksForPidToMap(pid)
		}
	}()
	go func() {
		defer waitGetSockMap.Done()
		for _, pid := range pidList[forOneThread*2 : forOneThread*3] {
			GetLinksForPidToMap(pid)
		}
	}()
	go func() {
		defer waitGetSockMap.Done()
		for _, pid := range pidList[forOneThread*3:] {
			GetLinksForPidToMap(pid)
		}
	}()
	waitGetSockMap.Wait()

	/*
		End build inode->pid map
	*/

	// Get info about pid
	smtpByCtid := make(map[uint32]uint)
	for i := range SmtpConnections {
		//fmt.Println(connection)
		if SocketInodeMap[SmtpConnections[i].Inode] > 0 {
			SmtpConnections[i].Process = GetInfoAboutPid(SocketInodeMap[SmtpConnections[i].Inode])
			smtpByCtid[SmtpConnections[i].Process.Ctid]++
		} else {
			//fmt.Fprintln(out, "Warning - cannot find pid for ", SmtpConnections[i])
		}
	}

	// Convert ctid to string for json output
	overusedSmtpByCtid := make(map[string]uint)
	for ctid, smtpCount := range smtpByCtid {
		if smtpCount > max_smtp_connections_number {
			overusedSmtpByCtid[fmt.Sprintf("%v", ctid)] = smtpCount
		}

	}

	if json_output {
		json_data, _ := json.Marshal(overusedSmtpByCtid)
		fmt.Print(string(json_data))
	} else {
		for ctid, smtpCount := range overusedSmtpByCtid {
			fmt.Fprintf(out, "Ctid: %s Smtp Connections: %v\n", ctid, smtpCount)
		}

	}

}

func GetAndParseNetFile(fileName string, Type string) error {
	proc_file_content, err := ioutil.ReadFile(fileName)
	if err != nil {
		fmt.Fprintln(out, err)
		return err
	}
	proc_file_data := strings.Split(string(proc_file_content), "\n")
	regexp_for_split_params := regexp.MustCompile(`\s+`)
	regexp_for_cut_first_spaces := regexp.MustCompile(`^\s+`)
	//regexp_for_split_ip_port := regexp.MustCompile(`:`)
	for _, line := range proc_file_data[1:] {
		splitedLine := regexp_for_split_params.Split(regexp_for_cut_first_spaces.ReplaceAllString(line, ""), -1)
		if len(splitedLine) >= 13 {
			var inetConnect InetConnection
			inetConnect.IpLocal, inetConnect.PortLocal, _ = ParseIpPort(splitedLine[1])
			inetConnect.IpRemote, inetConnect.PortRemote, _ = ParseIpPort(splitedLine[2])
			inetConnect.Inode, _ = strconv.ParseUint(splitedLine[9], 10, 64)
			inetConnect.Type = Type
			//fmt.Println(inetConnect, splitedLine[1])
			//fmt.Println(inetConnect.IpLocal, splitedLine, inetConnect.PortRemote, inetConnect.IpRemote, inetConnect.PortLocal)
			if CheckConnetToSmtpPorts(&inetConnect) {
				work_mux.Lock()
				SmtpConnections = append(SmtpConnections, inetConnect)
				work_mux.Unlock()
			}
		}
	}
	return err
}

func ParseIpPort(ip_port_raw string) (ip string, port uint64, err error) {
	ip_port_array := strings.Split(ip_port_raw, ":")
	if len(ip_port_array) == 2 {
		ip, _ = HexStringToIp(ip_port_array[0])
		port, _ = strconv.ParseUint(ip_port_array[1], 16, 64)
	} else {
		err = errors.New("Parse error - not p:port format")
	}
	return
}

func HexStringToIpv4(ip_raw string) (ip string, err error) {
	for len(ip_raw) > 1 {
		octet, _ := strconv.ParseInt(ip_raw[0:2], 16, 32)
		ip = fmt.Sprintf("%v.", octet) + ip
		ip_raw = ip_raw[2:]
	}
	ip = ip[0 : len(ip)-1]
	return
}

func HexStringToIp(ip_raw string) (ip string, err error) {
	if len(ip_raw) > 8 {
		if ip_raw[:23] == "0000000000000000FFFF000" {
			// it is ipv4 in fact
			ip, err = HexStringToIpv4(ip_raw[24:])
			ip = "::ffff:" + ip
		} else {
			var byte_befor []uint8
			for len(ip_raw) > 1 {
				ui, _ := strconv.ParseUint(ip_raw[0:2], 16, 8)
				ui8 := uint8(ui)
				byte_befor = append(byte_befor, ui8)
				ip_raw = ip_raw[2:]
			}

			byte_after := []uint8{
				byte_befor[3], byte_befor[2], byte_befor[1], byte_befor[0],
				byte_befor[7], byte_befor[6], byte_befor[5], byte_befor[4],
				byte_befor[11], byte_befor[10], byte_befor[9], byte_befor[8],
				byte_befor[15], byte_befor[14], byte_befor[13], byte_befor[12],
			}
			var ipv6 net.IP
			ipv6 = byte_after
			ip = ipv6.String()
		}
	} else {
		ip, err = HexStringToIpv4(ip_raw)
	}

	return
}

func CheckConnetToSmtpPorts(inetConnect *InetConnection) (isSmtp bool) {
	isSmtp = false
	if len(smtp_ports[inetConnect.PortRemote]) > 0 {
		isSmtp = true
		inetConnect.Reason = smtp_ports[inetConnect.PortRemote]
	}
	return
}

func GetPidList() (pidList []uint64) {
	dirHandle, err := os.Open("/proc/")
	if err != nil {
		panic(err)
	}
	fileList, err := dirHandle.Readdir(-1)
	if err != nil {
		panic(err)
	}

	for _, file := range fileList {
		if file.Mode().IsDir() {
			pidNumber, err := strconv.ParseUint(file.Name(), 10, 64)
			if err != nil {
				continue
			}
			pidList = append(pidList, pidNumber)
		}

	}
	return
}

func GetLinksForPidToMap(pid uint64) {
	dirHandle, err := os.Open("/proc/" + fmt.Sprintf("%v", pid) + "/fd/")
	if err != nil {
		return
	}
	fileList, err := dirHandle.Readdir(-1)
	if err != nil {
		return
	}
	socketRegexp := regexp.MustCompile(`^socket\:\[(\d+)\]$`)

	for _, fdFile := range fileList {
		fileName := fmt.Sprintf("/proc/%v/fd/%s", pid, fdFile.Name())
		fileStat, err := os.Lstat(fileName)
		if err != nil {
			continue
		}
		if fileStat.Mode()&os.ModeSymlink != 0 {
			linkName, err := os.Readlink(fileName)
			if err != nil {
				continue
			}
			result := socketRegexp.FindAllStringSubmatch(linkName, -1)
			if result != nil {
				inode, _ := strconv.ParseUint(result[0][1], 10, 64)
				work_mux.Lock()
				SocketInodeMap[inode] = pid
				work_mux.Unlock()
			}
		}
	}
}

func GetInfoAboutPid(pid uint64) (pidInfo PidInfo) {
	statusFile_content, err := ioutil.ReadFile(fmt.Sprintf("/proc/%v/status", pid))
	if err != nil {
		return
	}
	pidInfo.Pid = pid
	statusFile_data := strings.Split(string(statusFile_content), "\n")
	regexpForSplit := regexp.MustCompile(`\s+`)
	regexpForName := regexp.MustCompile(`^Name:`)
	regexpForCtid := regexp.MustCompile(`^envID:`)
	regexpForUid := regexp.MustCompile(`^Uid:`)
	regexpForGid := regexp.MustCompile(`^Gid:`)
	for _, line := range statusFile_data {
		splitedLine := regexpForSplit.Split(line, -1)
		if regexpForName.MatchString(line) && len(splitedLine) == 2 {
			pidInfo.Name = splitedLine[1]
		}

		if regexpForCtid.MatchString(line) && len(splitedLine) == 2 {
			i, _ := strconv.ParseUint(splitedLine[1], 10, 32)
			pidInfo.Ctid = uint32(i)
		}

		if regexpForUid.MatchString(line) && len(splitedLine) > 1 {
			pidInfo.Uid, _ = strconv.ParseUint(splitedLine[1], 10, 64)
		}
		if regexpForGid.MatchString(line) && len(splitedLine) > 1 {
			pidInfo.Gid, _ = strconv.ParseUint(splitedLine[1], 10, 64)
		}

	}

	return
}
