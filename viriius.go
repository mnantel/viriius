package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/MonaxGT/gomalshare"
	bolt "go.etcd.io/bbolt"
)

var (
	fsaKey     string
	fsaSession string

	db *bolt.DB

	malshareAPIKey = flag.String("a", "", "Malshare API key.")
	path           = flag.String("p", "viriius.db", "Path to hash cache DB (will be created if non-existent).")
	storelocal     = flag.String("l", "", "Download locally: create a copy of the file in target folder. Will not submit to FSA.")
	dryrun         = flag.Bool("d", false, "Dry run: display list of new hashes but dont download them.")
	ignore         = flag.Bool("i", false, "Ignore existing hash list and download all new files.")
	ssl            = flag.Bool("s", false, "Disable SSL certificate validation (useful when testing inline MITM inspection device).")
	logexists      = flag.Bool("e", false, "Output message for files that already exist.")
	submittofsa    = flag.Bool("f", false, "Submit to FSA.")
	FSAIP          = flag.String("fip", "192.168.129.15", "FSA IP address.")
	FSAUsername    = flag.String("fuser", "admin", "FSA Username.")
	FSAPasswd      = flag.String("fpass", "password", "FSA Password.")
)

var (
	Info = Teal
	Warn = Yellow
	Fata = Red
)

var (
	Black   = Color("\033[1;30m%s\033[0m")
	Red     = Color("\033[1;31m%s\033[0m")
	Green   = Color("\033[1;32m%s\033[0m")
	Yellow  = Color("\033[1;33m%s\033[0m")
	Purple  = Color("\033[1;34m%s\033[0m")
	Magenta = Color("\033[1;35m%s\033[0m")
	Teal    = Color("\033[1;36m%s\033[0m")
	White   = Color("\033[1;37m%s\033[0m")
)

type apiFSAUpload struct {
	Method  string               `json:"method"`
	Params  []apiFSAUploadParams `json:"params"`
	Session string               `json:"session"`
	ID      string               `json:"id"`
	Ver     string               `json:"ver"`
}
type apiFSAUploadMeta struct {
	MetaFilename string `json:"meta_filename"`
	MetaURL      string `json:"meta_url"`
}
type apiFSAUploadParams struct {
	File            string           `json:"file"`
	Filename        string           `json:"filename"`
	SkipSteps       string           `json:"skip_steps"`
	URL             string           `json:"url"`
	Type            string           `json:"type"`
	OverwriteVMList string           `json:"overwrite_vm_list"`
	ArchivePassword string           `json:"archive_password"`
	Meta            apiFSAUploadMeta `json:"meta"`
	Timeout         string           `json:"timeout"`
}

type apiFSALogin struct {
	Method string              `json:"method"`
	Params []apiFSALoginParams `json:"params"`
	ID     string              `json:"id"`
	Ver    string              `json:"ver"`
}
type apiFSALoginData struct {
	User   string `json:"user"`
	Passwd string `json:"passwd"`
}
type apiFSALoginParams struct {
	URL  string            `json:"url"`
	Data []apiFSALoginData `json:"data"`
}

type apiFSALoginResponse struct {
	ID     int    `json:"id"`
	Ver    string `json:"ver"`
	Result struct {
		URL    string `json:"url"`
		Status struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"status"`
	} `json:"result"`
	Session string `json:"session"`
}

func Color(colorString string) func(...interface{}) string {
	sprint := func(args ...interface{}) string {
		return fmt.Sprintf(colorString,
			fmt.Sprint(args...))
	}
	return sprint
}

func main() {

	flag.Parse()
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	loginFSA()

	var err error
	var conf *gomalshare.Client

	db, err = bolt.Open(*path, 0666, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	initDb()

	conf, err = gomalshare.New(*malshareAPIKey, "https://malshare.com/") // Initiate new connection to API
	if err != nil {
		panic(err)
	}

	fmt.Println("### ", time.Now(), " ###")
	var list24 *[]gomalshare.HashList
	list24, _ = conf.GetListOfHash24()
	for _, e := range *list24 {
		processSample(&e)
	}

}

func processSample(s *gomalshare.HashList) {

	conf, err := gomalshare.New(*malshareAPIKey, "https://malshare.com/")
	var file []byte
	// EXIST AND NOT LOGGING EXIST AND NOT IGNORING - SKIP EVERYTHING
	if existHash(s.Md5) && !*logexists && !*ignore {
		return
	}
	defer fmt.Printf("\r\n")

	// Otherwise start logging
	fmt.Printf("Sample MD5: %s", s.Md5)

	// EXISTS
	if existHash(s.Md5) {
		fmt.Printf("[%s]", Purple("EXISTS"))
	}

	// Download files locally
	if !*dryrun && (!existHash(s.Md5) || *ignore) && *storelocal != "" {
		if err != nil {
			fmt.Printf("[%s]", Red("APIERROR"))
			return
		}
		file, err = conf.DownloadFileFromHash(s.Md5)
		if err != nil {
			fmt.Printf("...%s %s", Red("DLERROR"), Red(err))
			return
		}
		fmt.Printf("[%s]", Green("DOWNLOADED"))
		addHash(s.Md5)
		err = ioutil.WriteFile(*storelocal+s.Md5, file, 0644)
		if err == nil {
			fmt.Printf("[%s]", Yellow("STOREDLOCAL"))
		}
		return
	}

	// DOWNLOAD if not dryrun AND not exists

	if !*dryrun && (!existHash(s.Md5) || *ignore) {
		// Initiate new connection to API
		if err != nil {
			fmt.Printf("[%s]", Red("APIERROR"))
			return
		}
		file, err = conf.DownloadFileFromHash(s.Md5)
		if err != nil {
			fmt.Printf("...%s %s", Red("DLERROR"), Red(err))
			return
		}
		fmt.Printf("[%s]", Green("DOWNLOADED"))
		addHash(s.Md5)
		if *submittofsa {
			submitFileFSA(&file, *s)
			fmt.Printf("...%s", Magenta("FSA"))
		}
	}

	// DRYRUN: if dryrun AND not exist
	if *dryrun && !existHash(s.Md5) {
		fmt.Printf("...%s", Yellow("DRYRUN"))
	}

}

func initDb() {
	db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("hashes"))
		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}
		return nil
	})
}
func addHash(hash string) {
	db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("hashes"))
		err := b.Put([]byte(hash), []byte("1"))
		return err
	})
}

func existHash(hash string) bool {
	var res []byte
	db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("hashes"))
		res = b.Get([]byte(hash))
		return nil
	})
	if res != nil {
		return true
	}
	return false
}

func loginFSA() {

	fsaLoginData := apiFSALoginData{
		User:   *FSAUsername,
		Passwd: *FSAPasswd,
	}
	fsaLoginParams := apiFSALoginParams{
		URL: "/sys/login/user",
	}
	fsaLogin := apiFSALogin{
		Method: "exec",
		ID:     "1",
		Ver:    "2.0",
	}
	fsaLoginParams.Data = append(fsaLoginParams.Data, fsaLoginData)
	fsaLogin.Params = append(fsaLogin.Params, fsaLoginParams)

	login, err := json.Marshal(fsaLogin)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	reqURI := fmt.Sprintf("https://%s:%s/%s", *FSAIP, "443", "jsonrpc")
	req, err := http.NewRequest("POST", reqURI, bytes.NewBuffer(login))
	if err != nil {
		fmt.Println(err)
	}
	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	resbody, _ := ioutil.ReadAll(res.Body)
	var response apiFSALoginResponse
	_ = json.Unmarshal(resbody, &response)
	fsaSession = response.Session
	fmt.Println(fsaSession)
}

func submitFileFSA(file *[]byte, meta gomalshare.HashList) bool {

	// enc := base64.StdEncoding.EncodeToString(file)

	uploadParams := apiFSAUploadParams{
		File:      base64.StdEncoding.EncodeToString(*file),
		Filename:  base64.StdEncoding.EncodeToString([]byte(meta.Md5)),
		SkipSteps: "1,2,8",
		URL:       "/alert/ondemand/submit-file",
		Type:      "file",
	}

	uploadFSA := apiFSAUpload{
		Method:  "set",
		Session: fsaSession,
		ID:      "1",
		Ver:     "2.5",
	}

	uploadFSA.Params = append(uploadFSA.Params, uploadParams)
	upload, err := json.Marshal(uploadFSA)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	reqURI := fmt.Sprintf("https://%s:%s/%s", *FSAIP, "443", "jsonrpc")
	req, err := http.NewRequest("POST", reqURI, bytes.NewBuffer(upload))
	if err != nil {
		fmt.Println(err)
	}
	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	resbody, _ := ioutil.ReadAll(res.Body)
	fmt.Println(string(resbody))
	// var response apiFSALoginResponse
	// _ = json.Unmarshal(resbody, &response)
	// fsaSession = response.Session
	// fmt.Println(fsaSession)

	return true
}
