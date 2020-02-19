package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/MonaxGT/gomalshare"
	bolt "go.etcd.io/bbolt"
)

// const (
// 	malshareAPIKey = "1d3e5832208312e0955491bc25b9fd5aff9e2d916e3dae4ba2d212b9f29e4e6d"
// 	path           = "viriius.db"
// )

// go run viriius.go -a 1d3e5832208312e0955491bc25b9fd5aff9e2d916e3dae4ba2d212b9f29e4e6d -p viriius.db -d

var (
	db             *bolt.DB
	malshareAPIKey = flag.String("a", "", "Malshare API key.")
	path           = flag.String("p", "viriius.db", "Path to hash cache DB (will be created if non-existent).")
	dryrun         = flag.Bool("d", false, "Dry run: display list of new hashes but dont download them.")
	ignore         = flag.Bool("i", false, "Ignore existing hash list and download all new files.")
	ssl            = flag.Bool("s", false, "Disable SSL certificate validation (useful when testing inline MITM inspection device).")
	exists         = flag.Bool("e", false, "Output message for files that already exist.")
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
	for i, e := range *list24 {
		if existHash(e.Md5) && !*exists {
			continue
		}
		fmt.Printf("Sample %d MD5: %s", i, e.Md5)
		if !existHash(e.Md5) || *ignore {
			if !*dryrun {
				_, err := conf.DownloadFileFromHash(e.Md5)
				if err != nil {
					fmt.Printf("...%s %s\r\n", Red("ERROR"), Red(err))
					continue
				}
				addHash(e.Md5)
				fmt.Printf("...%s\r\n", Green("DOWNLOADED"))
				continue
			}
			fmt.Printf("...%s\r\n", Yellow("SKIP (DRYRUN)"))
			continue
		}
		fmt.Printf("...%s\r\n", Purple("EXISTS"))

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
