package main

import (
	"./lib"
	"./proverInitPhase"
	"time"
	"unsafe"

	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
)

const (
	message = "hello world!"
	secret  = "0933e54e76b24731a2d84b6b463ec04c"
	//fileName = "C:\\Users\\Yuan Fy\\OneDrive\\Documents\\ITFSS\\ITFSS\\bianyi.png"
	fileName = "C:\\Users\\ss\\D\\GoProject\\ITFSS\\01.png"
	readbitlen int64 = 10
)

func ComputeHmacSha256(message string, secret string) string {		
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	//	fmt.Println(h.Sum(nil))
	sha := hex.EncodeToString(h.Sum(nil))
	//	fmt.Println(sha)
	//	hex.EncodeToString(h.Sum(nil))
	return base64.StdEncoding.EncodeToString([]byte(sha))

}
func file2Bytes(filename string) ([]byte, error) {

	// File
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// FileInfo:
	stats, err := file.Stat()
	if err != nil {
		return nil, err
	}

	// []byte
	data := make([]byte, stats.Size())
	count, err := file.Read(data)
	if err != nil {
		return nil, err
	}
	fmt.Printf("read file %s len: %d \n", filename, count)
	return data, nil
}

func testevidencefile(identity string) {
	//根据分享的文件生成证明文件，包括两部分，一部分是生成默克尔树的叶子节点，存储在.block文件中，另外一部分是随机数，保存在.nounce文件中
	//fileName := "C:\\Users\\Yuan Fy\\OneDrive\\Documents\\ITFSS\\ITFSS\\bianyi.png"
	var evidencefilepath = fileName + ".blocks"
	var evidencenouncefile = fileName + ".nounce"
	lib.GenerateEvidenceFile(identity, fileName, evidencefilepath, evidencenouncefile, readbitlen)
	evidencefilesize := lib.CalcEvidenceFileSize(fileName, readbitlen, 256)
	//获取文件大小
	filesize := lib.GetFileSize(evidencefilepath)
	if evidencefilesize == filesize {
		fmt.Println("yes")
		fmt.Println("size of file .blocks is ",filesize)
		fmt.Println("size of file .nounceis ",lib.GetFileSize(evidencenouncefile))
	}
}

func testevidencecachfile(evidencefile string, evidencecachfile string, ch string) {
	lib.NewMerkleTreeContainAllNodes(evidencefile, ch, evidencecachfile)
}



func main() {
	proverInitPhase.TestGenerateBlock()
	//generate ecc public and private pair
	//lib.GenerateECCKey1()
	////read publickey，generate idnetity
	publicKey := lib.GetECCPublicKeyByte("eccpublic.pem")
	identity := lib.GetSHA256HashCode(publicKey)
	fmt.Println("user identity is ", identity)
	////测试生成证明文件，
	t1:=time.Now() //获取本地现在时间
	testevidencefile(identity)
	elapsed := time.Since(t1)
	fmt.Println("生成验证文件的时间：", elapsed)
	//1000个计算hash值的时间
	/*
		t1:=time.Now() //获取本地现在时间
		for i:=0;i<1000;i++{
			TestSha256Time()
		}
		elapsed := time.Since(t1)
		fmt.Println("elapsed=", elapsed)
	*/


	//给定一个ch，生成默克尔树
	//evidencefileName是存放所有叶子节点的文件
	evidencefileName := fileName + ".blocks"
	//node需要nouce
	evidencenouncefile := fileName + ".nounce"
	//node需要filedigest
	//var filedigest string
	//filedigest = lib.GetSHA256HashCodeFile(fileName)
	//fmt.Println(fileName+"文件摘要 is ", filedigest)
	//node是[head||tail||nouce||filedigest]
	var ch string = "12345678901234567890123456789014"
	//将默克尔树写进缓存
	//testevidencecachfile(evidencefileName, evidencecachfile, ch)
	//得到node的序号和值
	var node map[int64][]byte
	node = lib.GetNodePath(fileName, evidencefileName, evidencenouncefile, ch,readbitlen)
	//fmt.Println("传输的信息 is ", node)
	//unsafe.Sizeof(hmap) + (len(theMap) * 8) + (len(theMap) * 8 * unsafe.Sizeof(x)) + (len(theMap) * 8 * unsafe.Sizeof(y))
	fmt.Println("传输的信息大小 is ", unsafe.Sizeof(node))
	//node = lib.GetNodePath(evidencefileName, ch)
	var verifyresult string
	verifyresult = lib.Verify(node,fileName,identity,readbitlen,ch)
	fmt.Println("verifyresult is ", verifyresult)

}

func TestSha256Time(){
	var identity string="c472b3aeaf26ef4ceed0c3b2403b530c7a57962ee2bda1d6edafdc0ef04afc12345678901234567890123456789012";
	var tyrnum int64= 1023
	var trys string
	trys += identity
	trys += strconv.FormatInt(tyrnum, 10)
	lib.GetSHA256HashCode([]byte(trys))
}