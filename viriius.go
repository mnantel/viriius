package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"

	"github.com/MonaxGT/gomalshare"
	bolt "go.etcd.io/bbolt"
)

const (
	malshareAPIKey = "1d3e5832208312e0955491bc25b9fd5aff9e2d916e3dae4ba2d212b9f29e4e6d"
	path           = "viriius.db"
)

var (
	db *bolt.DB
)

func main() {

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	var err error
	var conf *gomalshare.Client

	db, err = bolt.Open(path, 0666, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	initDb()

	conf, err = gomalshare.New(malshareAPIKey, "https://malshare.com/") // Initiate new connection to API
	if err != nil {
		panic(err)
	}

	var list24 *[]gomalshare.HashList
	list24, _ = conf.GetListOfHash24()
	for _, e := range *list24 {
		if existHash(e.Md5) == false {
			fmt.Println(e.Md5)
			_, err := conf.DownloadFileFromHash(e.Md5)
			if err != nil {
				fmt.Println("Error downloading hash: ", e.Md5)
				continue
			}
			addHash(e.Md5)
		}
	}

	// example with return list of types of downloading files last 24 hours
	// typeCount, _ := conf.GetListOfTypesFile24()
	// fmt.Println(typeCount)

	// example with return current api key limit
	// var limitKey *gomalshare.LimitKey
	// limitKey, _ = conf.GetLimitKey()
	// fmt.Println(limitKey)

	// example with return information of files by using sample
	// var search *[]gomalshare.SearchDetails
	// search, err = conf.GetSearchResult("emotet")
	// if err != nil {
	// 	fmt.Println(err)
	// }
	// for _, v := range *search {
	// 	fmt.Println(v.Md5)
	// }
	// example upload file
	// filename := "test.test"
	// err = conf.UploadFile(filename)
	// if err != nil {
	// 	fmt.Println(err)
	// }

	// // example for download file by hash request
	// file, err := conf.DownloadFileFromHash("95bc3d64f49b03749427fcd6601fa8a7")
	// if err != nil {
	// 	fmt.Println(err)
	// }
	// fmt.Println(string(file))
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
