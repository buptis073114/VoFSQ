package proverInitPhase

import (
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"os"
	"time"
)

var (
	size int64
	path string
)

func genreateBlock(){
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0777)
	if err != nil {
		log.Fatalln(err)
	}
	err = os.Truncate(path, size)
	if err != nil {
		log.Fatalln(err)
	}
	log.Printf("file create succeed, path: %s, size: %d Byte\n", path, size)
	file.Close()
}

func calculatesha256(){
	// 对文件加密
	f, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("The sha256 value of the block is %x\n", h.Sum(nil))
}

func TestGenerateBlock(){
	size=4*1024*1024
	path="Block"
	genreateBlock()
	start := time.Now()
	calculatesha256()
	elapsed := time.Since(start)
	fmt.Println("consumed time of sha256 is ", elapsed)
	generateBlockFile()
}
func generateBlockFile(){
	size=1*1024
	path="1K"
	genreateBlock()
	fmt.Println("1K blockfile generate success")

	size=5*1024
	path="5K"
	genreateBlock()
	fmt.Println("5K blockfile generate success")

	size=50*1024
	path="50K"
	genreateBlock()
	fmt.Println("50K blockfile generate success")


	size=500*1024
	path="500K"
	genreateBlock()
	fmt.Println("500K blockfile generate success")

	size=1024*1024
	path="1024K"

	genreateBlock()
	fmt.Println("1024K blockfile generate success")

	size=2048*1024
	path="2048K"
	genreateBlock()
	fmt.Println("2048K blockfile generate success")


	
	size=3*1024*1024
	path="3072K"
	genreateBlock()
	fmt.Println("3072K blockfile generate success")

	size=4*1024*1024
	path="4096K"
	genreateBlock()
	fmt.Println("4096K blockfile generate success")

	size=5*1024*1024
	path="5120K"
	genreateBlock()
	fmt.Println("5120K blockfile generate success")
}