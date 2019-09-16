package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	cm "./common"
	ft "./timestamps"
)

var matched = 0
var cleared = 0

var filesToScan = make(chan string,1000)
var regexString = ""
var regexExts regexp.Regexp

type timestamp struct {
	created  string
	modified string
	accessed string
}

type response struct {
	filepath   string
	size       int
	md5        string
	timestamps timestamp
	matches    []string
}

//var regex = ""

/*
### TODO
Test Cases

CPU/Mem Limits
### Server Detection (Scan Profiles)
IIS
- Web.Config parsing (ISAPI Filters/Handlers)
-- Detect all web roots to scan automatically
Apache
- Detect web roots to scan
Tomcat
- Catalina Logs
- War File Deployment Logs
*/

func longStringMatches(f string) (fileMatches map[string]int) {
	fileMatches = make(map[string]int)
	if len(f) < 20*1024 {
		return fileMatches
	}
	r := regexp.MustCompile(`(\'[^\']*\')|(\"[^\"]*\")`)
	r1 := regexp.MustCompile(`[a-zA-Z0-9\+\/\=]`)
	matches := r.FindAllString(f, -1)
	if len(matches) > 0 {
		for _, it := range matches {
			if len(it) < 64 {
				continue
			}
			for _, x := range r1.FindStringSubmatch(it) {
				if len(x) == len(it)-2 {
					continue
				}
			}
			fileMatches[it]++
		}
	}
	return fileMatches
}

func base64Matches(f string) (fileMatches map[string]int) {
	r := regexp.MustCompile(`(\"(?:[A-Za-z0-9\+\/]{4}){10,}(?:[A-Za-z0-9\+\/]{2}\=\=|[A-Za-z0-9\+\/]{3}\=)\")|(\'(?:[A-Za-z0-9\+\/]{4}){10,}(?:[A-Za-z0-9\+\/]{2}\=\=|[A-Za-z0-9\+\/]{3}\=)\')`)
	r1 := regexp.MustCompile(`[a-fA-F0-9]+`)
	r2 := regexp.MustCompile(`[a-zA-Z0-9\/]+`)
	fileMatches = make(map[string]int)
	matches := r.FindAllString(f, -1)
	if len(matches) > 0 {
		for _, it := range matches {
			for _, x := range r1.FindStringSubmatch(it) {
				if len(x) == len(it)-2 {
					continue
				}
			}
			for _, x := range r2.FindStringSubmatch(it) {
				if len(x) == len(it)-2 {
					continue
				}
			}
			fileMatches[it] = len(it)
		}
	}
	return fileMatches
}

func splitMatches(f string) (fileMatches map[string]int) {
	r := regexp.MustCompile(`eval|file\_put\_contents|base64\_decode|python\_eval|exec|passthru|popen|proc\_open|pcntl|assert|system|shell|uncompress|cmd\.exe|execute|escapeshellcmd|os\.popen|\/bin\/sh|\/bin\/bash|create_function|executionpolicybypass`)
	r1 := regexp.MustCompile(`(\'[^\']*\')|(\"[^\"]*\")`)
	r2 := regexp.MustCompile(`[^\w\/]`)
	fileMatches = make(map[string]int)
	matches1 := r1.FindAllString(f, -1)
	var s1 string
	if len(matches1) > 0 {
		for _, it := range matches1 {
			s1 += it
		}
	}
	s1 = r2.ReplaceAllString(s1, "")
	matchesr1 := r.FindAllString(strings.ToLower(s1), -1)
	if len(matchesr1) > 0 {
		for _, it := range matchesr1 {
			fileMatches[it]++
		}
	}
	return fileMatches
}

func compressMatches(f string) (fileMatches map[string]int) {
	fileMatches = make(map[string]int)
	if len(f) < 20*1024 {
		return fileMatches
	}
	buf := make([]byte, len(f))
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	if _, err := gz.Write(buf); err != nil {
		fmt.Println(err)
	}
	if err := gz.Flush(); err != nil {
		fmt.Println(err)
	}
	if err := gz.Close(); err != nil {
		fmt.Println(err)
	}
	readBuf, _ := ioutil.ReadAll(&b)
	if float64(len(readBuf))/float64(len(f)) > 0.74 {
		fileMatches["Compress"] = int(float64(len(readBuf)) / float64(len(f)) * 100)
	}
	return fileMatches
}

func entropyMatches(f string) (fileMatches map[string]int) {
	var entropy float64
	if len(f) < 20*1024 {
		return fileMatches
	}
	fileMatches = make(map[string]int)
	fdata := strings.ReplaceAll(f, " ", "")
	for i := 0; i < 256; i++ {
		pX := float64(strings.Count(fdata, string(i))) / float64(len(fdata))
		if pX > 0.00 {
			entropy += -pX * math.Log2(pX)
		}
	}
	if entropy > 7.4 {
		fileMatches["Entropy"] = int(entropy * 10)
	}
	return fileMatches
}

func stringMatches(j string) (fileMatches map[string]int) {
	fileMatches = make(map[string]int)
	r := regexp.MustCompile(regexString)
	matches := r.FindAllString(strings.ToLower(j), -1)
	if len(matches) > 0 {
		for _, it := range matches {
			fileMatches[it]++
		}
	}
	return fileMatches
}

func scanExtention(j string) (fileMatches map[string]int) {
	fileMatches = make(map[string]int)
	r1 := regexp.MustCompile(`[^a-zA-Z0-9\-\_\.]{2,}`)
	r2 := regexp.MustCompile(`\.[a-zA-Z0-9]{2,4}\.`)
	r3 := regexp.MustCompile(`\.php|\.asp|\.aspx|\.sh|\.bash|\.zsh|\.csh|\.tsch|\.pl|\.py|\.cgi|\.cfm|\.jsp|\.htaccess|\.ashx|\.vbs`)
	matches := r1.FindAllString(j, -1)
	if len(matches) > 0 {
		for _, x := range matches {
			fileMatches[x]++
		}
	}
	matches = r2.FindAllString(j, -1)
	if len(matches) > 0 {
		for _, x := range matches {
			matches = r3.FindStringSubmatch(x)
			if len(matches) > 0 {
				fileMatches[x]++
			}
		}
	}
	return fileMatches
}

func processMatches(j string) (fileMatches map[string]int, size int64, csvlog string) {
	totalFileMatches := make(map[string]int)
	fileMatches = make(map[string]int)
	var scanInfo string
	var count int
	count = 0
	fileHandle, err := os.Open(j)
	if err != nil {
		log.Fatal(err)
		return totalFileMatches, 0, ""
	}
	defer fileHandle.Close()

	fi, err := os.Stat(j)
	if err != nil {
		log.Println(err)
		return totalFileMatches, 0, ""
	}

	fileMatches = scanExtention(filepath.Base(j))
	if len(fileMatches) > 0 {
		for x := range fileMatches {
			totalFileMatches[x] = fileMatches[x]
		}
		scanInfo += "TRUE"
		count++
	}
	scanInfo += ","
	var fdata string
	fileScanner, err := ioutil.ReadAll(fileHandle)
	cmtR := regexp.MustCompile(`(\/\*([^*]|[\r\n]|(\*+([^*\/]|[\r\n])))*\*+\/)|(\/\/.*)`)
	fdata = cmtR.ReplaceAllString(string(fileScanner), "")
	cmtR = regexp.MustCompile(`[\s\n\r\t]+`)
	fdata = cmtR.ReplaceAllString(string(fileScanner), " ")
	fdata = strings.ReplaceAll(fdata, "  ", " ")
	fdata = strings.ReplaceAll(fdata, " (", "(")
	codeR := regexp.MustCompile(`<\?php(.*?)\?>|<script(.*?)<\/script>|<%(.*?)%>`)
	matches := codeR.FindAllString(fdata, -1)
	if len(matches) > 0 {
		fdata = ""
		for _, x := range matches {
			fdata += x
		}
	} else {
		return totalFileMatches, 0, ""
	}

	fileMatches = stringMatches(fdata)
	if len(fileMatches) > 0 {
		for x := range fileMatches {
			totalFileMatches[x] = fileMatches[x]
		}
		scanInfo += fmt.Sprintf("%d", len(fileMatches))
		count++
	}
	scanInfo += ","
	fileMatches = entropyMatches(fdata)
	if len(fileMatches) > 0 {
		totalFileMatches["Entropy"] = fileMatches["Entropy"]
		scanInfo += fmt.Sprintf("%d", totalFileMatches["Entropy"])
		count++
	}
	scanInfo += ","
	fileMatches = compressMatches(fdata)
	if len(fileMatches) > 0 {
		totalFileMatches["Compress"] = fileMatches["Compress"]
		scanInfo += fmt.Sprintf("%d", totalFileMatches["Compress"])
		count++
	}
	scanInfo += ","
	fileMatches = splitMatches(fdata)
	if len(fileMatches) > 0 {
		for x := range fileMatches {
			totalFileMatches[x] = fileMatches[x]
		}
		scanInfo += fmt.Sprintf("%d", len(fileMatches))
		count++
	}
	scanInfo += ","
	fileMatches = base64Matches(fdata)
	if len(fileMatches) > 0 {
		for x := range fileMatches {
			totalFileMatches[x] = fileMatches[x]
		}
		scanInfo += fmt.Sprintf("%d", len(fileMatches))
		count++
	}
	/*scanInfo += ","
	fileMatches = longStringMatches(fdata)
	if len(fileMatches) > 0 {
		for x := range fileMatches {
			totalFileMatches[x] = fileMatches[x]
		}
		scanInfo += fmt.Sprintf("%d", len(fileMatches))
		count++
	}*/
	if count > 0 {
		return totalFileMatches, fi.Size(), fmt.Sprintf("%s,%s", j, strings.ReplaceAll(scanInfo, " ", ""))
	}
	return totalFileMatches, fi.Size(), ""
}

func md5HashFile(filePath string) (string, error) {
	var returnMD5String string
	file, err := os.Open(filePath)
	if err != nil {
		return returnMD5String, err
	}
	defer file.Close()
	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return returnMD5String, err
	}
	hashInBytes := hash.Sum(nil)[:16]
	returnMD5String = hex.EncodeToString(hashInBytes)
	return returnMD5String, nil
}

func compressEncode(filePath string, fileSize int64) string {
	fileItem, err := os.Open(filePath)
	if err != nil {
		return ""
	}
	defer fileItem.Close()
	buf := make([]byte, fileSize)
	fReader := bufio.NewReader(fileItem)
	fReader.Read(buf)
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	if _, err := gz.Write(buf); err != nil {
		fmt.Println(err)
		return ""
	}
	if err := gz.Flush(); err != nil {
		fmt.Println(err)
		return ""
	}
	if err := gz.Close(); err != nil {
		fmt.Println(err)
		return ""
	}
	readBuf, _ := ioutil.ReadAll(&b)
	imgBase64Str := base64.StdEncoding.EncodeToString(readBuf)
	return imgBase64Str
}

func scanFunc(wg *sync.WaitGroup, rawContents bool, fjson *os.File, fcsv *os.File) {
	for j := range filesToScan {
		Jdata := cm.FileObj{}
		Jdata.FilePath = j
		fileMatches, size, csvlog := processMatches(j)
		Jdata.Size = size
		Jdata.Matches = fileMatches
		if len(fileMatches) > 0 && size > 0 {
			matched = matched + 1
		} else {
			cleared = cleared + 1
			continue
		}
		fHash, err := md5HashFile(j)
		if err != nil {
			log.Println(err)
		}
		Jdata.MD5 = fHash
		Jdata.RawContents = compressEncode(j, Jdata.Size)
		// File Timestamps
		timestamps, err := ft.StatTimes(j)
		Jdata.Timestamps = timestamps
		// PROD
		logcsv := fmt.Sprintf("%s,%d,%s,%s,%s,%s\n", csvlog, Jdata.Size, Jdata.MD5, Jdata.Timestamps.Created, Jdata.Timestamps.Modified, Jdata.Timestamps.Accessed)
		data, err := json.Marshal(Jdata)
		if err != nil {
			log.Fatal(err)
		}
		fjson.Write([]byte(data))
		fcsv.Write([]byte(logcsv))
	}
	wg.Done()
}

func main() {

	start := time.Now()
	var dir = flag.String("dir", "", "Directory to scan for webshells")
	var customRegex = flag.String("regex", "", "Override default regex with your own")
	var size = flag.Int64("size", 1, "Specify max file size to scan (default is 10 MB)")
	var exts = flag.String("exts", "", "Specify extensions to target. Multiple extensions should be passed with pipe separator (asp|aspx|php|cfm). Default is all extensions")
	var rawContents = flag.Bool("raw_contents", true, "If a match is found, grab the raw contents and base64 + gzip compress the file into the JSON object.")
	var timeScan = flag.String("time", "2000-01-01", "Scan all file created or modified after this time <yyyy-mm-dd>")
	var workers = flag.Int("workers", 10, "Count of concurrent workers.")
	flag.Parse()

	if *dir == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *customRegex == "" {
		regexString = `Filesman|(@\$_\[\]=|\$_=@\$_GET|\$_\[\+""\]=)|eval\(\$(\w|\d)|Load\(Request\.BinaryRead\(int\.Parse\(Request\.Cookies|Html \= Replace\(Html\, \"\%26raquo\;\"\, \"?\"\)|pinkok|internal class reDuh|c0derz shell|md5 cracker|umer rock|Function CP\(S\,D\)\{sf\=CreateObject\(\"java\"\,\"java\.io\.File|Arguments\=xcmd\.text|asp cmd shell|Maceo|TEXTAREA id\=TEXTAREA1 name\=SqlQuery|CMD Bilgileri|sbusqlmod|php assert\(\$\_POST\[|oWshShellNet\.UserName|PHP C0nsole|rhtools|WinX Shell|system\(\$\_GET\[\'cmd\'|Successfully uploadet|\'Are you sure delete|sbusqlcmd|CFSWITCH EXPRESSION\=\#Form\.chopper|php\\HFile|\"ws\"\+\"cr\"\+\"ipt\.s\"\+\"hell\"|eval\(request\(|string rootkey|uZE Shell|Copyed success\!|InStr\(\"\$rar\$mdb\$zip\$exe\$com\$ico\$\"|Folder dosen\'t exists|Buradan Dosya Upload|echo passthru\(\$\_GET\[\'cmd\'|javascript:Bin\_PostBack|The file you want Downloadable|arguments\=\"/c \#cmd\#\"|cmdshell|AvFBP8k9CDlSP79lDl|AK-74 Security Team Web Shell|cfexecute name \= \"\#Form\.cmd\#\"|execute\(|Gamma Web Shell|System\.Reflection\.Assembly\.Load\(Request\.BinaryRead\(int\.Parse\(Request\.Cookies|fcreateshell|bash to execute a stack overflow|Safe Mode Shell|ASPX Shell|dingen\.php|azrailphp|\$\_POST\[\'sa\']\(\$\_POST\[\'sb\']\)|AspSpy|ntdaddy|\.HitU\. team|National Cracker Crew|eval\(base64\_decode\(\$\_REQUEST\[\'comment\'|Rootshell|geshi\\tsql\.php|tuifei\.asp|GRP WebShell|No Permission :\(|powered by zehir|will be delete all|WebFileManager Browsing|Dive Shell|diez\=server\.urlencode|@eval\(\$\_POST\[\'|ifupload\=\"ItsOk\"|eval\(request\.item|\(eval request\(|wsshn\.username|connect to reDuh|eval\(gzinflate\(base64\_decode|Ru24PostWebShell|ASPXTOOL\"|aspshell|File upload successfully you can download here|eval request\(|if\(is\_uploaded\_file\(\$HTTP|Sub RunSQLCMD|STNC WebShell|doosib|WinExec\(Target\_copy\_of\_cmd|php passthru\(getenv|win\.com cmd\.exe /c cacls\.exe|TUM HAKLARI SAKLIDIR|Created by PowerDream|Then Request\.Files\(0\)\.SaveAs\(Server\.MapPath\(Request|cfmshell|\{ Request\.Files\[0]\.SaveAs\(Server\.MapPath\(Request|\%execute\(request\(\"|php eval\(\$\_POST\[|lama\'s\'hell|RHTOOLS|data\=request\(\"dama\"|digitalapocalypse|hackingway\.tk|\.htaccess stealth web shell|strDat\.IndexOf\(\"EXEC \"|ExecuteGlobal request\(|Deleted file have finished|bin\_filern|CurrentVersionRunBackdoor|Chr\(124\)\.O\.Chr\(124\)|does not have permission to execute CMD\.EXE|G-Security Webshell|system\( \"\./findsock|configwizard|textarea style\=\"width:600\;height:200\" name\=\"cmd\"|ASPShell|repair/sam|BypasS Command eXecute|\%execute\(request\(|arguments\=\"/c \#hotmail|Coded by Loader|Call oS\.Run\(\"win\.com cmd\.exe|DESERTSUN SERVER CRASHER|ASPXSpy|cfparam name\=\"form\.shellpath\"|IIS Spy Using ADSI|p4ssw0rD|WARNING: Failed to daemonise|C0mmand line|phpinfo\(\) function has non-permissible|letaksekarang|Execute Shell Command|DXGLOBALSHIT|IISSpy|execute request\(|Chmod Ok\!|Upload Gagal|awen asp\.net|execute\(request\(\"|oSNet\.ComputerName|aspencodedll\.aspcoding|vbscript\.encode|exec\(|shell\_exec\(|popen\(|system\(|escapeshellcmd|passthru\(|pcntl\_exec|proc\_open|db\_connect|mysql\_query|execl\(|cmd\.exe|os\.popen|ls\ \-la|\/etc\/passwd|\/etc\/hosts|adodb\.connection|sqlcommandquery|shellexecute|oledbcommand|mime\-version|exif\_read\_data\(|gethostbyname\(|create\_function\(|base64\_decode\(|\-executionpolicy\ bypass`
	} else {
		regexString = *customRegex
	}

	if *exts == "" {
		*exts = `\.php|\.asp|\.aspx|\.sh|\.bash|\.zsh|\.csh|\.tsch|\.pl|\.py|\.cgi|\.cfm|\.jsp|\.htaccess|\.ashx|.\vbs|.ps1`
	}
	regexExts := regexp.MustCompile(*exts)

	const shortForm = "2006-01-02"
	timeToScan, _ := time.Parse(shortForm, *timeScan)

	osName, _ := os.Hostname()
	//envVars := os.Environ()
	theUser, _ := user.Current()

	y, m, d := start.Date()
	h, min, s := start.Clock()
	_ = os.MkdirAll(fmt.Sprintf("%s_output_%4d_%2d_%2d_%2d_%2d_%2d/", osName, y, m, d, h, min, s), os.ModePerm)
	fjson, err := os.Create(fmt.Sprintf("%s_output_%4d_%2d_%2d_%2d_%2d_%2d/log.json", osName, y, m, d, h, min, s))
	fcsv, err := os.Create(fmt.Sprintf("%s_output_%4d_%2d_%2d_%2d_%2d_%2d/log.csv", osName, y, m, d, h, min, s))

	fcsv.Write([]byte("PathName,FakeName,String,Entropy,Compress,Split,Base64,Size,MD5,Created,Modified,Accessed\n"))
	totalFilesScanned := 0

	var wg sync.WaitGroup
	for w := 1; w <= *workers; w++ {
		wg.Add(1)
		go scanFunc(&wg, *rawContents, fjson, fcsv)
	}
	timeFomat := "2006-01-02 15:04:05"
	_ = filepath.Walk(*dir, func(path string, f os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !f.IsDir() {
			if f.Size() < (*size * 1024 * 1024) {
				if len(regexExts.FindStringSubmatch(strings.ToLower(path))) > 0 {
					timePath, _ := ft.StatTimes(path)
					mdf, _ := time.Parse(timeFomat, timePath.Modified)
					if /*timeToScan.Before(cre) || */ timeToScan.Before(mdf) {
						filesToScan <- path
						totalFilesScanned = totalFilesScanned + 1
					}
				}
			}
		}
		return nil
	})

	close(filesToScan)
	wg.Wait()

	metrics := cm.Metrics{}
	metrics.Scanned = totalFilesScanned
	metrics.Clear = cleared
	metrics.Matched = matched
	metrics.ScannedDir = *dir
	metrics.ScanTime = time.Since(start).Minutes()

	metrics.SystemInfo.Hostname = osName
	//metrics.SystemInfo.EnvVars = envVars
	metrics.SystemInfo.Username = theUser.Username
	metrics.SystemInfo.UserID = theUser.Uid
	metrics.SystemInfo.RealName = theUser.Name
	metrics.SystemInfo.UserHomeDir = theUser.HomeDir

	data, err := json.Marshal(metrics)
	if err != nil {
		log.Fatal(err)
	}
	fjson.Write([]byte(data))
	fmt.Println("Scan done!")
}
