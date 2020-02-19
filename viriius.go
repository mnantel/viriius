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
)

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
		if existHash(e.Md5) == false || *ignore {
			fmt.Print("Sample ", i, " MD5: ", e.Md5)
			if !*dryrun {
				_, err := conf.DownloadFileFromHash(e.Md5)
				if err != nil {
					fmt.Println("...Error downloading hash: ", e.Md5)
					continue
				}
				fmt.Println("...OK! (downloaded)")
			}
			addHash(e.Md5)
			fmt.Println("...OK! (skip download)")
		}
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
