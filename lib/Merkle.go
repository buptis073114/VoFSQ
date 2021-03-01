package lib

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/imroc/biu"
	"io"

	//"io"
	"os"
	"strconv"
	"strings"
	"time"
	"unsafe"
)

//叶子节点到根节点的路径节点
type PathNode struct {
	Row    int64
	Column int64
	Data   []byte
}

func min(a int64, b int64) int64 {
	if a > b {
		return b
	}
	return a
}

//默克尔树节点
type MerkleTree struct {
	RootNode *MerkleNode
}

//默克尔根节点
type MerkleNode struct {
	Left  *MerkleNode
	Right *MerkleNode
	Data  []byte
}

//计算hmac_sha256的算法
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

//生成默克尔树中的节点，如果是叶子节点，则Left，right为nil，如果为非叶子节点，根据Left，Right生成当前节点的hash
func NewMerkleNode(left, right *MerkleNode, key []byte, data []byte) *MerkleNode {
	mnode := MerkleNode{}
	if nil == left && nil == right {
		mnode.Data = data
		//fmt.Println("mnode.Data is ",mnode.Data)
	} else {
		prevhashes := append(left.Data, right.Data...)

		//计算hmac_sha256
		h := hmac.New(sha256.New, key)
		h.Write(prevhashes)
		//sha := hex.EncodeToString(h.Sum(nil))

		//firsthash := sha256.Sum256(prevhashes)
		//fmt.Println("firsthash[:] is ",firsthash[:])
		mnode.Data = h.Sum(nil)
	}
	mnode.Left = left
	mnode.Right = right
	return &mnode
}

func NewMerkleTree(data [][]byte) *MerkleTree {
	var nodes []MerkleNode
	var key []byte
	//构建叶子节点
	for _, dataum := range data {
		node := NewMerkleNode(nil, nil, key, dataum)
		nodes = append(nodes, *node)
	}
	//j代表的是某一层的第一个元素
	var i int64 = 0
	var j int64 = 0
	var nSize int64
	//第一层循环代表，nSize代表某一层的个数，每次循环一次减半
	for nSize = int64(len(data)); nSize > 1; nSize = (nSize + 1) / 2 {
		//第二条循环i+=2代表两两拼接，i2是为了当个数是奇数的时候，拷贝最后的元素。
		for i = 0; i < nSize; i += 2 {
			i2 := min(i+1, nSize-1)
			node := NewMerkleNode(&nodes[j+i], &nodes[j+i2], key, nil)
			nodes = append(nodes, *node)
		}
		//j代表的是某一层的第一个元素
		j += nSize
	}
	mTree := MerkleTree{&(nodes[len(nodes)-1])}

	fmt.Println("len is ", len(nodes))

	return &mTree
}


//SHA256生成文件哈希值
func GetSHA256HashCodeFile(path string) (hash string) {
	file, err := os.Open(path)
	if err == nil {
		h_ob := sha256.New()
		_, err := io.Copy(h_ob, file)
		if err == nil {
			hash := h_ob.Sum(nil)
			hashvalue := hex.EncodeToString(hash)
			return hashvalue
		} else {
			return "something wrong when use sha256 interface..."
		}
	} else {
		fmt.Printf("failed to open %s\n", path)
	}
	defer file.Close()
	return
}


//SHA256生成哈希值
func GetSHA256HashCode(message []byte) string {
	//方法一：
	//创建一个基于SHA256算法的hash.Hash接口的对象
	hash := sha256.New()
	//输入数据
	hash.Write(message)
	//计算哈希值
	bytes := hash.Sum(nil)
	//将字符串编码为16进制格式,返回字符串
	hashCode := hex.EncodeToString(bytes)
	//返回哈希值
	return hashCode

	//方法二：
	//bytes2:=sha256.Sum256(message)//计算哈希值，返回一个长度为32的数组
	//hashcode2:=hex.EncodeToString(bytes2[:])//将数组转换成切片，转换成16进制，返回字符串
	//return hashcode2
}

//SHA256生成哈希值
func GetSHA256HashCodeString(s string) string {

	hash := sha256.New()
	//输入数据
	//hash.Write(s)
	io.WriteString(hash,s);
	//计算哈希值
	bytes := hash.Sum(nil)
	//将字符串编码为16进制格式,返回字符串
	hashCode := hex.EncodeToString(bytes)
	//返回哈希值
	return hashCode


}

/**
* Bit比较，该函数会比较两个byte数组的前bitlen bit是否一致
* origin byte数组1
* target byte数组1
* bitlen 比较的bit长度
* 如果相同，则返回true，否则返回false
 */
func bitcompare(origin []byte, target []byte, bitlen int64) (bool, error) {
	var merchant int64 = bitlen / 8
	var remainder int64 = bitlen % 8
	//fmt.Println("merchant is ",merchant)
	//fmt.Println("remainder is ",remainder)
	if merchant > 0 {
		var iter int64
		for iter = 0; iter < merchant; iter++ {
			//fmt.Println("origin[",iter,"] is ",origin[iter])
			//fmt.Println("target[",iter,"] is ",target[iter])
			if origin[iter] != target[iter] {
				return false, fmt.Errorf("not equal")
			}
		}
	}
	if remainder > 0 {
		//fmt.Println("origin[",merchant,"] is ",biu.ByteToBinaryString(origin[merchant]))
		//fmt.Println("target[",merchant,"] is ",biu.ByteToBinaryString(target[merchant]))
		var aaa byte = origin[merchant] >> (8 - remainder)
		var bbb byte = target[merchant] >> (8 - remainder)
		//fmt.Println("aaa is ",biu.ByteToBinaryString(aaa))
		//fmt.Println("bbb is ",biu.ByteToBinaryString(bbb))
		if aaa != bbb {
			return false, fmt.Errorf("not equal")
		}
	}
	return true, fmt.Errorf("equal")
}

//将文件读取到内存中，并按照32byte切分，生成数组
func ReadAllFileIntoMemmory(filePth string) ([][]byte, error) {
	datalen := GetFileSize(filePth)
	file, err := os.Open(filePth)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data := make([]byte, datalen)
	_, err = file.Read(data)
	nodenumber := datalen / 32
	//int_num := *(*int)(unsafe.Pointer(&nodenumber))
	var dataarray [][]byte
	var readiter int64 = 0
	for readiter = 0; readiter < nodenumber; readiter++ {
		var byteiter int64 = 0
		tmpdata := make([]byte, 32)
		for byteiter = 0; byteiter < 32; byteiter++ {
			tmpdata[byteiter] = data[readiter*32+byteiter]
		}
		dataarray = append(dataarray, tmpdata)
	}
	//var dataarray [][]byte =  bytes.SplitN(data,nil,int_num)
	return dataarray, fmt.Errorf("")
}
//将nouce读取到内存中，并按照,切分，生成数组
func ReadAllNouceIntoMemmory(filePth string) ([]string, error) {

	file,err := os.Open(filePth)
	if err != nil {
		return nil, err
	}

	defer file.Close()
	fileinfo,err := file.Stat()
	if err != nil {
		return nil, err
	}

	fileSize := fileinfo.Size()
	buffer := make([]byte,fileSize)

	bytesread,err := file.Read(buffer)
	if err != nil {
		return nil, err
	}

	fmt.Println("bytes read:",bytesread)
	//fmt.Println("bytestream to string:",string(buffer))
	dataarray := strings.Split(string(buffer), ",")
	//fmt.Println("bytestream to string:",dataarray)

	return dataarray, fmt.Errorf("")


	//datalen := GetFileSize(filePth)
	//file, err := os.Open(filePth)
	//if err != nil {
	//	return nil, err
	//}
	//defer file.Close()
	//data := make([]byte, datalen)
	//fmt.Println("data to string:",string(data))
	//_, err = file.Read(data)
	////noucenumber := bytes.IndexByte(data, ',')
	//nodenumber := datalen / 32
	////int_num := *(*int)(unsafe.Pointer(&nodenumber))
	//
	//var dataarray [][]byte
	//var readiter int64 = 0
	//for readiter = 0; readiter < nodenumber; readiter++ {
	//	var byteiter int64 = 0
	//	tmpdata := make([]byte, 32)
	//	for byteiter = 0; byteiter < 32; byteiter++ {
	//		tmpdata[byteiter] = data[readiter*32+byteiter]
	//	}
	//	dataarray = append(dataarray, tmpdata)
	//}
	////var dataarray [][]byte =  bytes.SplitN(data,nil,int_num)
	//return dataarray, fmt.Errorf("")
}

/**
* 该函数从filePth文件中跳过skipbitlen个bit长度读取bufSize个bit，返回byte数组
* filePth 文件路径
* bufSize 要读取bit大小
* skipbitlen 跳过的bit大小
* 返回读取的byte数组，一个byte等于8bit，返回的byte数组包含要读取的全部bit
 */
func ReadBlock(filePth string, bufSize int64, skipbitlen int64) ([]byte, error) {
	var merchant int64 = skipbitlen / 8
	var remainder int64 = skipbitlen % 8
	var blockbitsize int64
	var iter int64
	if (bufSize % 8) > 0 {
		blockbitsize = (bufSize/8 + 1)
	} else {
		blockbitsize = (bufSize / 8)
	}
	var datalen = blockbitsize + 1
	// File
	file, err := os.Open(filePth)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data := make([]byte, datalen)
	for iter = 0; iter < datalen; iter++ {
		data[iter] = 0
	}
	retdata := make([]byte, blockbitsize)
	for iter = 0; iter < blockbitsize; iter++ {
		retdata[iter] = 0
	}
	_, err = file.ReadAt(data, merchant)
	//fmt.Println("count is ",count)
	//datasignStr := fmt.Sprintf("%x", data)
	//fmt.Println("data is ", datasignStr)

	if remainder > 0 {
		for iter = 0; iter < blockbitsize; iter++ {
			retdata[iter] = (data[iter] << remainder) ^ (data[iter+1] >> (8 - remainder))
		}
	} else {
		for iter = 0; iter < blockbitsize; iter++ {
			retdata[iter] = data[iter]
		}
	}
	return retdata, fmt.Errorf("")
}

//exists Whether the path exists
func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil || os.IsExist(err)
}

//getFileSize get file size by path(B)
func GetFileSize(path string) int64 {
	if !exists(path) {
		return 0
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return fileInfo.Size()
}

func getFileName(path string) string {
	if !exists(path) {
		return ""
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return fileInfo.Name()
}

func WriteBlock(path string, comparebyte []byte) {
	//           写文件
	outputFile, outputError := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if outputError != nil {
		fmt.Println(outputError)
		return
	}
	defer outputFile.Close()
	outputWriter := bufio.NewWriter(outputFile)
	outputWriter.Write(comparebyte)
	// 一定得记得将缓冲区内容刷新到磁盘文件
	outputWriter.Flush()
}

func WriteNounce(path string, content string) {
	//           写文件
	outputFile, outputError := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if outputError != nil {
		fmt.Println(outputError)
		return
	}
	defer outputFile.Close()
	outputWriter := bufio.NewWriter(outputFile)
	outputWriter.WriteString(content)
	// 一定得记得将缓冲区内容刷新到磁盘文件
	outputWriter.Flush()
}

//根据分享的文件路径，计算证明文件的大小，单位是Byte
func CalcEvidenceFileSize(filepath string, readbitlen int64, hashlen int64) int64 {
	var blocknum int64 = 0
	filesize := GetFileSize(filepath)
	if (filesize * 8 / readbitlen) > 0 {
		blocknum = (filesize*8/readbitlen + 1)
	} else {
		blocknum = (filesize * 8 / readbitlen)
	}
	return blocknum * hashlen / 8
}

//根据要分享的数据路径，生成证明文件
//第一个参数是个人唯一id，第二个参数是源文件路径，第三个参数是每次读取的bit长度
//该函数会生成一个后缀是.blocks的证明文件和.nounce的文件
func  GenerateEvidenceFile(
	identity string,
	fileName string,
	evidencefilepath string,
	evidencenouncefile string,
	readbitlen int64) {
	var readiter int64 = 0
	var previoushash string
	var tyrnum int64 = 0
	//fmt.Println("filesize is ", filesize)
	var blocknum int64

	var blockbytebuffer bytes.Buffer
	//var blockbyte []byte
	var noncestring string
	//首先删除原来的evidencefile
	if exists(evidencefilepath) {
		//删除文件
		del := os.Remove(evidencefilepath)
		if del != nil {
			fmt.Println(del)
		}
	}

	//首先删除原来的evidencenouncefile
	if exists(evidencenouncefile) {
		//删除文件
		del := os.Remove(evidencenouncefile)
		if del != nil {
			fmt.Println(del)
		}
	}

	//将文件切割为readbitlen长度的block，一共有blocknum个block
	filesize := GetFileSize(fileName)
	if (filesize * 8 / readbitlen) > 0 {
		blocknum = (filesize*8/readbitlen + 1)
	} else {
		blocknum = (filesize * 8 / readbitlen)
	}
	fmt.Println("blocknum is ", blocknum)
	//filename := getFileName(fileName)
	for readiter = 0; readiter < blocknum; readiter++ {
		//fmt.Println("readiter is ", readiter)
		retdata, _ := ReadBlock(fileName, readbitlen, readiter*readbitlen)
		//fmt.Println("retdata is ", retdata)
		if 0 == readiter {
			for tyrnum = 0; ; tyrnum++ {
				var trys string
				trys += identity
				trys += strconv.FormatInt(tyrnum, 10)
				//fmt.Println("trys is ",trys)
				//t1:=time.Now()  //获取本地现在时间
				calc_hash := GetSHA256HashCode([]byte(trys))
				//t2:=time.Now()
				//d:=t2.Sub(t1)  //两个时间相减
				//fmt.Println("计算一次sha256耗时",d)
				//fmt.Println("calc_hash is ",calc_hash)
				var comparebyte []byte
				comparebyte, _ = hex.DecodeString(calc_hash)
				ret, _ := bitcompare(retdata, comparebyte, readbitlen)
				if ret {
					//fmt.Println("calc_hash is ", calc_hash)
					//fmt.Println("retdata is ", retdata)
					//fmt.Println("comparebyte is ", comparebyte)
					//fmt.Println("tyrnum is ", tyrnum)

					previoushash = calc_hash
					//这个comparebyte是head||tail，也是Hash（id||previous hash||nounce）
					//blockbyte = blockbyte + comparebyte
					blockbytebuffer.Write(comparebyte)
					noncestring += strconv.FormatInt(tyrnum, 10)

					//WriteBlock(evidencefilepath, comparebyte)
					//WriteNounce(evidencenouncefile, strconv.FormatInt(tyrnum, 10))
					break
				}
			}
		} else {
			for tyrnum = 0; ; tyrnum++ {
				var trys string
				trys += identity
				trys += previoushash
				trys += strconv.FormatInt(tyrnum, 10)
				//fmt.Println("trys is ",trys)
				calc_hash := GetSHA256HashCode([]byte(trys))
				//fmt.Println("calc_hash is ",calc_hash)
				var comparebyte []byte
				comparebyte, _ = hex.DecodeString(calc_hash)
				ret, _ := bitcompare(retdata, comparebyte, readbitlen)
				if ret {
					//fmt.Println("trys is ",trys)
					//fmt.Println("tyrnum is ", tyrnum)
					//fmt.Println("retdata is ", retdata)
					//fmt.Println("comparebyte is ", comparebyte)
					previoushash = calc_hash
					blockbytebuffer.Write(comparebyte)
					noncestring += ","+strconv.FormatInt(tyrnum, 10)

					//WriteBlock(evidencefilepath, comparebyte)
					//WriteNounce(evidencenouncefile, ","+strconv.FormatInt(tyrnum, 10))
					break
				}
			}
		}
	}
	WriteBlock(evidencefilepath, blockbytebuffer.Bytes() )
	WriteNounce(evidencenouncefile, noncestring)


}

func NewMerkleTreeContainAllNodes(evidencepath string, ch string, evdencecachpath string) []MerkleNode {
	var nodes []MerkleNode
	//获取证明数据的大小
	evidencefilesize := GetFileSize(evidencepath)
	//计算叶子节点的个数
	nodenumber := evidencefilesize / 32
	//j代表的是某一层的第一个元素
	var i int64 = 0
	var j int64 = 0
	var k int64 = 0
	var keybyte []byte = []byte(ch)
	//第一层循环代表，nSize代表某一层的个数，每次循环一次减半
	for nSize := nodenumber; nSize > 1; nSize = (nSize + 1) / 2 {
		//第二条循环i+=2代表两两拼接，i2是为了当个数是奇数的时候，拷贝最后的元素。
		for i = 0; i < nSize; i += 2 {
			i2 := min(i+1, nSize-1)
			if k <= 0 {
				readdata1, _ := ReadBlock(evidencepath, 256, i*256)
				readdata2, _ := ReadBlock(evidencepath, 256, i2*256)
				var node1 MerkleNode
				var node2 MerkleNode
				node1.Data = readdata1
				node2.Data = readdata2
				node := NewMerkleNode(&node1, &node2, keybyte, nil)
				WriteBlock(evdencecachpath, node.Data)
				k += 1
			} else {
				readdata1, _ := ReadBlock(evdencecachpath, 256, (j+i)*256)
				readdata2, _ := ReadBlock(evdencecachpath, 256, (j+i2)*256)
				var node1 MerkleNode
				var node2 MerkleNode
				node1.Data = readdata1
				node2.Data = readdata2
				node := NewMerkleNode(&node1, &node2, keybyte, nil)
				WriteBlock(evdencecachpath, node.Data)
				j += nSize
			}
		}
	}
	//mTree:=MerkleTree{&(nodes[len(nodes)-1])}

	//fmt.Println("len is ", len(nodes))

	return nodes
}

//在内存中生成默克尔树
func NewMerkleTreeMemory(evidencepath string, evidencecachpath string, ch string) *MerkleTree {
	var nodes []MerkleNode
	var key []byte = []byte(ch)
	var data [][]byte

	data, _ = ReadAllFileIntoMemmory(evidencepath)
	//fmt.Println("len(data) is ", len(data))
	//var nodenum int64 =int64( len(data))

	//构建叶子节点
	for _, dataum := range data {
		node := NewMerkleNode(nil, nil, key, dataum)
		nodes = append(nodes, *node)
	}
	//j代表的是某一层的第一个元素
	var i int64 = 0
	var j int64 = 0
	var nSize int64
	//第一层循环代表，nSize代表某一层的个数，每次循环一次减半
	for nSize = int64(len(data)); nSize > 1; nSize = (nSize + 1) / 2 {
		//第二条循环i+=2代表两两拼接，i2是为了当个数是奇数的时候，拷贝最后的元素。
		for i = 0; i < nSize; i += 2 {
			i2 := min(i+1, nSize-1)
			node := NewMerkleNode(&nodes[j+i], &nodes[j+i2], key, nil)
			nodes = append(nodes, *node)
			//WriteBlock(evidencecachpath, node.Data)
		}
		//j代表的是某一层的第一个元素
		j += nSize
	}
	mTree := MerkleTree{&(nodes[len(nodes)-1])}
	fmt.Println("len is ", len(nodes))
	//GetNodePath(&mTree,nodenum)
	return &mTree
}

func ChunkString(s string, chunkSize int) []string {
	var chunks []string
	runes := []rune(s)

	if len(runes) == 0 {
		return []string{s}
	}

	for i := 0; i < len(runes); i += chunkSize {
		nn := i + chunkSize
		if nn > len(runes) {
			nn = len(runes)
		}
		chunks = append(chunks, string(runes[i:nn]))
	}
	return chunks
}

//数组去重
func RemoveRepeatedElement(arr []int64) (newArr []int64) {
	newArr = make([]int64, 0)
	for i := 0; i < len(arr); i++ {
		repeat := false
		for j := i + 1; j < len(arr); j++ {
			if arr[i] == arr[j] {
				repeat = true
				break
			}
		}
		if !repeat {
			newArr = append(newArr, arr[i])
		}
	}
	return
}

func GetNodePath(filename string,evidencepath string,evidencenoucepath string, ch string,readbitlen int64) map[int64][]byte {
	var nodes []MerkleNode
	var key []byte = []byte(ch)
	var evidencedata [][]byte
	var evidencenouncedata []string
	//var filedigestbyte []byte

	//将hashstring转为byte[]
	//filedigestbyte, _ = hex.DecodeString(filedigest)
	//fmt.Println("filedigestbyte is ", filedigestbyte)
	//将.blocks文件读取到内存中，并将其按照32byte大小切割成数组
	evidencedata, _ = ReadAllFileIntoMemmory(evidencepath)
	fmt.Println("len(data) is ", len(evidencedata))
	//将.nouce文件读取到内存中，并将其读取到数组中
	evidencenouncedata,_ = ReadAllNouceIntoMemmory(evidencenoucepath)
	//fmt.Println("evidencenouncedata is ", evidencenouncedata)
	fmt.Println("len(evidencenouncedata) is ", len(evidencenouncedata))
	t1:=time.Now() //获取本地现在时间


	//默克尔树叶子节点的个数
	var nodenum int64 = int64(len(evidencedata))

	var filenodehashbyte []byte = filenodehash(filename,ch,nodenum,readbitlen)

	//构建叶子节点
	var nodenumiter int64 = 0
	fmt.Println("nodenum: ",nodenum)
	for _, dataum := range evidencedata {
		//将随机数转为八个字节的byte[]

		nouceint,err := strconv.ParseInt(evidencenouncedata[nodenumiter], 10, 64)
		if err != nil {
			fmt.Println("err: ",err)
		}
		//fmt.Println("nouceint: ",nouceint)
		var buf = make([]byte, 8)
		binary.BigEndian.PutUint64(buf, uint64(nouceint))
		//fmt.Println("buf is ", buf)
		//fmt.Println("dataum is ", dataum)
		//叶子节点是head||tail||nounce||filedigest
		for _,nounceum := range buf{
			dataum=append(dataum,nounceum)

			//dataum = append(dataum,filedigestbyte)

		}
		for _,filenodehashbytenum := range filenodehashbyte{
			dataum=append(dataum,filenodehashbytenum)
			//dataum = append(dataum,filedigestbyte)
		}


		//for _,filedigestum := range filedigestbyte{
		//	dataum=append(dataum,filedigestum)
		//}
		//fmt.Println("叶子节点 is ", nodenumiter)
		//fmt.Println("dataum is ", dataum)
		node := NewMerkleNode(nil, nil, key, dataum)
		nodes = append(nodes, *node)
		nodenumiter++
	}

	//构建除了叶子节点的其他节点。j代表的是某一层的第一个元素
	var i int64 = 0
	var j int64 = 0
	var nSize int64
	//第一层循环代表，nSize代表某一层的个数，每次循环一次减半
	for nSize = int64(len(evidencedata)); nSize > 1; nSize = (nSize + 1) / 2 {
		//第二条循环i+=2代表两两拼接，i2是为了当个数是奇数的时候，拷贝最后的元素。
		for i = 0; i < nSize; i += 2 {
			i2 := min(i+1, nSize-1)
			node := NewMerkleNode(&nodes[j+i], &nodes[j+i2], key, nil)
			nodes = append(nodes, *node)
			//WriteBlock(evidencecachpath, node.Data)
		}
		//j代表的是某一层的第一个元素
		j += nSize
	}
	mTree := MerkleTree{&(nodes[len(nodes)-1])}
	fmt.Println("len nodes is ", len(nodes))
	fmt.Println("生成merkle树的时间", time.Since(t1))
	//var data [][]byte
	var rootnode MerkleNode = *mTree.RootNode
	//将 默克尔树的根节点 转成01字符串
	var rootnodestring string = biu.ToBinaryString(rootnode.Data)
	//去掉所有"["
	rootnodestring = strings.Replace(rootnodestring, "[", "", -1)
	//去掉所有"]"
	rootnodestring = strings.Replace(rootnodestring, "]", "", -1)
	//去掉所有空格
	rootnodestring = strings.Replace(rootnodestring, " ", "", -1)

	//fmt.Println("rootnodestring is ", rootnodestring)
	var bittosting string = biu.ToBinaryString(nodenum)

	bittosting = strings.Replace(bittosting, "[", "", -1)
	bittosting = strings.Replace(bittosting, "]", "", -1)
	bittosting = strings.Replace(bittosting, " ", "", -1)
	var stringlen = len(bittosting)
	fmt.Println("nodenum is ", bittosting)
	fmt.Println("stringlen is ", stringlen)
	var stringiter int = 0
	//zerolen是计算二进制表示叶子节点个数时，有zerolen位0
	var zerolen int = 0
	for stringiter = 0; stringiter < stringlen; stringiter++ {
		if '0' != bittosting[stringiter] {
			//zerolen = stringiter + 1
			zerolen = stringiter
			break
		}
	}

	//fmt.Println("zerolen is ", zerolen)

	//计算需要eachlen个bit才能表示叶子节点的总个数，例如叶子节点的个数是245441，那么就需要17个bit才能表示
	var eachlen uintptr = ((unsafe.Sizeof(nodenum) * 8) - uintptr(zerolen))
	//fmt.Println("eachlen is ", eachlen)

	//由根节点切割得到的叶子节点的序号
	var nodeposition []int64
	//将根节点的bit字符串按每eachlen一份进行切割，生成[]string
	var chunkarray []string = ChunkString(rootnodestring, int(eachlen))
	//fmt.Println("chunkarray is ", chunkarray)
	var bititer int = 0
	for bititer = 0; bititer < len(chunkarray); bititer++ {
		var tmpint int64 = 0
		var partiter int = 0
		for partiter = 0; partiter < len(chunkarray[bititer]); partiter++ {
			tmpint = (tmpint << 1)
			if '1' == chunkarray[bititer][partiter] {
				tmpint = (tmpint) ^ 1
			}
			if tmpint >= nodenum {
				tmpint = tmpint % nodenum
			}

		}
		nodeposition = append(nodeposition, tmpint)
	}

	//fmt.Println("nodeposition is ", nodeposition)
	//将随机取到的叶子节点的序号去重，   将Hch（com）解析为k个索引，得到 i0 ...ik-1
	nodeposition = RemoveRepeatedElement(nodeposition)
	fmt.Println("nodeposition is ", nodeposition)


	//fmt.Println("nodeposition is ", nodeposition)
	//由叶子节点的序号，生成各个叶子节点到根节点的路径
	//路径
	//route:=make(map[int64][]byte)
	var routenodenum [][]int64
	//被选中的所有叶子节点
	var firstrownodenum []int64
	var nodeiter int64 = 0
	for nodeiter = 0; nodeiter < int64(len(nodeposition)); nodeiter++ {
		var value int64 = nodeposition[nodeiter]
		if 0 == value%2 { //如果叶子节点的序号为偶数
			firstrownodenum = append(firstrownodenum, value)
			if value < nodenum {
				if value == nodenum - 1{//如果遇到了这一层的末尾节点
					firstrownodenum = append(firstrownodenum, value)
				}else{//如果不是末尾节点
					firstrownodenum = append(firstrownodenum, value+1)
				}
				if 0 != value {//发送它之前的两个节点
					firstrownodenum = append(firstrownodenum, value-1)
					firstrownodenum = append(firstrownodenum, value-2)
				}
			}

		} else {//如果叶子节点的序号是奇数
			firstrownodenum = append(firstrownodenum, value)
			firstrownodenum = append(firstrownodenum, value-1)
		}
	}
	routenodenum = append(routenodenum, RemoveRepeatedElement(firstrownodenum))
	//fmt.Println("需要的叶子节点is ", routenodenum)

	var routenSize int64 = 0
	var routej int64 = 0
	var mapiter int64 = 0 //表示层数，由下到上
	//第一层循环代表，nSize代表某一层的个数，每次循环一次减半
	for routenSize = int64(len(evidencedata)); routenSize > 1; routenSize = (routenSize + 1) / 2 {
		var previousarray []int64 = routenodenum[mapiter]
		var previousarrayiter int64 = 0
		var tmproutenum []int64
		//fmt.Println("层数是：", mapiter)
		for previousarrayiter = 0; previousarrayiter < int64(len(previousarray)); previousarrayiter++ {
			var rowvalue int64 = previousarray[previousarrayiter] / 2
			if 0 == rowvalue%2 { //如果是偶数
				//fmt.Println("routenSize is ",routenSize,",rowvalue is", rowvalue,",(routenSize+1)/2-1 is",(routenSize+1)/2-1)
				if rowvalue >= (routenSize+1)/2-1 { //如果遇到了这一层的末尾节点
					tmproutenum = append(tmproutenum, rowvalue)
				}else {
					tmproutenum = append(tmproutenum, rowvalue+1)
				}
			} else {
				tmproutenum = append(tmproutenum, rowvalue-1)
			}
		}

		mapiter++
		//j代表的是某一层的第一个元素
		routej += routenSize
		routenodenum = append(routenodenum, RemoveRepeatedElement(tmproutenum))
	}
	//fmt.Println("routenodenum len is ", len(routenodenum), " routenodenum is ", routenodenum)
	var routeniter int64 = 0
	var arraynum int64 = 0
	var accumulatednumber int64 = 0
	for routeniter = int64(len(evidencedata)); routeniter > 1; routeniter = (routeniter + 1) / 2 {
		var arrayiter int64 = 0
		for arrayiter = 0; arrayiter < int64(len(routenodenum[arraynum])); arrayiter++ {
			routenodenum[arraynum][arrayiter] = routenodenum[arraynum][arrayiter]+accumulatednumber
		}
		arraynum++
		accumulatednumber = accumulatednumber + routeniter
	}
	//根节点
	routenodenum[arraynum][0] = routenodenum[arraynum][0]+accumulatednumber
	//fmt.Println("routenodenum len is ", len(routenodenum), " routenodenum is ", routenodenum)

	//返回node的序号和node的值。使用集合map存储node[][]
	var node map[int64][]byte
	node = make(map[int64][]byte)

	var nodelayiter int = 0
	var nodeeiter int = 0
	for nodelayiter = 0; nodelayiter < len(routenodenum); nodelayiter++{
		for nodeeiter = 0; nodeeiter < len(routenodenum[nodelayiter]); nodeeiter++{
			var num = routenodenum[nodelayiter][nodeeiter]
			node [num] = nodes[num].Data
		}
	}
	//fmt.Println("node is ",node)
	fmt.Println("生成选中叶子节点路径的时间", time.Since(t1))
	return node
}

//根据ch和叶子节点的个数来选取某些节点的文件哈希值
func filenodehash(filename string,ch string,nodenum int64,readbitlen int64) []byte{
	//将H（ch）解析为k个索引。
	//计算ch的哈希值Hch
	var Hch string = GetSHA256HashCodeString(ch)
	var Hchbyte, _ = hex.DecodeString(Hch)
	//Hch,_ := hex.DecodeString(ch)
	fmt.Println("Hch is ", Hch)
	fmt.Println("Hchbyte is ", Hchbyte)
	//将 Hch 转成01字符串
	var Hchstring string = biu.ToBinaryString(Hchbyte)
	//去掉所有"["
	Hchstring = strings.Replace(Hchstring, "[", "", -1)
	//去掉所有"]"
	Hchstring = strings.Replace(Hchstring, "]", "", -1)
	//去掉所有空格
	Hchstring = strings.Replace(Hchstring, " ", "", -1)
	fmt.Println("Hchstring is ", Hchstring)
	//将nodenum转为01
	var bittosting string = biu.ToBinaryString(nodenum)

	bittosting = strings.Replace(bittosting, "[", "", -1)
	bittosting = strings.Replace(bittosting, "]", "", -1)
	bittosting = strings.Replace(bittosting, " ", "", -1)
	var stringlen = len(bittosting)

	fmt.Println("nodenum is ", bittosting)
	fmt.Println("stringlen is ", stringlen)

	var stringiter int = 0
	//zerolen是计算二进制表示叶子节点个数时，有zerolen位0
	var zerolen int = 0
	for stringiter = 0; stringiter < stringlen; stringiter++ {
		if '0' != bittosting[stringiter] {
			//zerolen = stringiter + 1
			zerolen = stringiter
			break
		}
	}

	fmt.Println("zerolen is ", zerolen)

	//计算需要eachlen个bit才能表示叶子节点的总个数，例如叶子节点的个数是245441，那么就需要17个bit才能表示
	var eachlen uintptr = ((unsafe.Sizeof(nodenum) * 8) - uintptr(zerolen))
	fmt.Println("eachlen is ", eachlen)



	//由Hchstring切割得到原文件序号
	var fileposition []int64
	//将Hchstring的bit字符串按每eachlen一份进行切割，生成[]string
	var Hcharray []string = ChunkString(Hchstring, int(eachlen))
	//fmt.Println("chunkarray is ", chunkarray)
	var filebititer int = 0
	for filebititer = 0; filebititer < len(Hcharray); filebititer++ {
		var tmpint int64 = 0
		var partiter int = 0
		for partiter = 0; partiter < len(Hcharray[filebititer]); partiter++ {
			tmpint = (tmpint << 1)
			if '1' == Hcharray[filebititer][partiter] {
				tmpint = (tmpint) ^ 1
			}
			if tmpint >= nodenum {
				tmpint = tmpint % nodenum
			}

		}
		fileposition = append(fileposition, tmpint)
	}

	fmt.Println("fileposition is ", fileposition)
	//将随机取到的叶子节点的序号去重，   将Hch（com）解析为k个索引，得到 i0 ...ik-1
	fileposition = RemoveRepeatedElement(fileposition)
	fmt.Println("fileposition is ", fileposition)
	var fileretdata []byte
	//将选取的文件点进行拼接计算哈希值。
	//retdata, _ := ReadBlock(filename, readbitlen, 0*readbitlen)
	//fmt.Println("000000000000retdata is ", retdata)
	var readiter int
	for readiter = 0; readiter < len(fileposition); readiter++ {
		//fmt.Println("readiter is ", readiter)
		//fmt.Println("now fileposition is ", fileposition[readiter])
		retdata, _ := ReadBlock(filename, readbitlen, (fileposition[readiter])*readbitlen)
		//fmt.Println("retdata is ", retdata)
		for _,nounceum := range retdata{
			fileretdata=append(fileretdata,nounceum)
		}

	}
	fmt.Println("fileretdata is ", fileretdata)
	fileretdata_hash := GetSHA256HashCode([]byte(fileretdata))

	var filebyte_hash []byte
	filebyte_hash, _ = hex.DecodeString(fileretdata_hash)
	fmt.Println("filebyte_hash is ", filebyte_hash)
	return filebyte_hash

}
//根据收到的节点的值进行验证
//第一个参数是证明方发送过来的节点的序号及值，第二个参数是本地文件路径，第三个参数是个人身份id，第四个参数是每次读取的bit长度，第五个参数是发送的挑战ch
//该函数返回验证结果
func Verify(node map[int64][]byte, filename string,identity string, readbitlen int64,ch string) string {
	fmt.Println("开始验证")
	t1:=time.Now() //获取本地现在时间

	//计算需要验证的叶子节点的序号
	//根据readbitlen计算得到叶子节点的个数leafnodenum以及总节点的个数nodenum
	var leafnodenum int64
	var nodenum int64
	filesize := GetFileSize(filename)
	if (filesize * 8 / readbitlen) > 0 {
		leafnodenum = (filesize*8/readbitlen + 1)
	} else {
		leafnodenum = (filesize * 8 / readbitlen)
	}
	fmt.Println("leafnodenum is ", leafnodenum)
	nodenum = Calcnodenumber(leafnodenum)
	fmt.Println("nodenum is ", nodenum)
	//将根节点com的值取出，并按照叶子节点的个数进行划分
	/*查看根节点在node中是否存在 */
	rootnodevalue, ok := node [ nodenum-1 ] /*如果确定是真实的,则存在,否则不存在 */
	if (ok) {
		fmt.Println("rootnodevalue is ", rootnodevalue)
	} else {
		fmt.Println("rootnodevalue不存在")
		var result = "根节点不存在，验证不成功"
		return result
	}
	//将 默克尔树的根节点 转成01字符串
	var rootnodestring string = biu.ToBinaryString(rootnodevalue)
	//去掉所有"["
	rootnodestring = strings.Replace(rootnodestring, "[", "", -1)
	//去掉所有"]"
	rootnodestring = strings.Replace(rootnodestring, "]", "", -1)
	//去掉所有空格
	rootnodestring = strings.Replace(rootnodestring, " ", "", -1)
	//fmt.Println("rootnodestring is ", rootnodestring)
	//将叶子节点的个数转成01字符串
	var bittosting string = biu.ToBinaryString(leafnodenum)

	bittosting = strings.Replace(bittosting, "[", "", -1)
	bittosting = strings.Replace(bittosting, "]", "", -1)
	bittosting = strings.Replace(bittosting, " ", "", -1)
	var stringlen = len(bittosting)
	//fmt.Println("leafnodenum is ", bittosting)
	//fmt.Println("stringlen is ", stringlen)
	var stringiter int = 0
	//zerolen是计算二进制表示叶子节点个数时，有zerolen位0
	var zerolen int = 0
	for stringiter = 0; stringiter < stringlen; stringiter++ {
		if '0' != bittosting[stringiter] {
			//zerolen = stringiter + 1
			zerolen = stringiter
			break
		}
	}
	//fmt.Println("zerolen is ", zerolen)
	//计算需要eachlen个bit才能表示叶子节点的总个数，例如叶子节点的个数是245441，那么就需要17个bit才能表示
	var eachlen uintptr = ((unsafe.Sizeof(leafnodenum) * 8) - uintptr(zerolen))
	//fmt.Println("eachlen is ", eachlen)
	//由根节点切割得到的叶子节点的序号
	var nodeposition []int64
	//将根节点的bit字符串按每eachlen一份进行切割，生成[]string
	var chunkarray []string = ChunkString(rootnodestring, int(eachlen))
	//fmt.Println("chunkarray is ", chunkarray)
	var bititer int = 0
	for bititer = 0; bititer < len(chunkarray); bititer++ {
		var tmpint int64 = 0
		var partiter int = 0
		for partiter = 0; partiter < len(chunkarray[bititer]); partiter++ {
			tmpint = (tmpint << 1)
			if '1' == chunkarray[bititer][partiter] {
				tmpint = (tmpint) ^ 1
			}
			if tmpint >= leafnodenum {
				tmpint = tmpint % leafnodenum
			}

		}
		nodeposition = append(nodeposition, tmpint)
	}
	//fmt.Println("nodeposition is ", nodeposition)
	//将随机取到的叶子节点的序号去重，   将Hch（com）解析为k个索引，得到 i0 ...ik-1
	nodeposition = RemoveRepeatedElement(nodeposition)
	fmt.Println("需要验证的叶子节点 is ", nodeposition)


	//1. 验证叶子节点的head值与本地存储的文件的head值是否一致

	var headiter int
	fmt.Println("len(nodeposition) is ", len(nodeposition))

	//fmt.Println("verifyfile is ", verifyfile)
	for headiter = 0; headiter < len(nodeposition); headiter++ {

		//var nodenumber int64
		//nodenumber = nodeposition[headiter]
		//fmt.Println(nodenumber,"验证与本地文件是否相同的节点 ", nodeposition[headiter])
		//fmt.Println("node[nodeposition[headiter]] is ", node[nodeposition[headiter]])
		var verifyfile []byte
		//取验证文件的前readbitlen位
		verifyfile,_ = ReadBlock(filename,readbitlen,readbitlen*nodeposition[headiter])
		//fmt.Println("verifyfile is ", verifyfile)
		if(verifyfile != nil){
			//fmt.Println("verifyfile is ", verifyfile)
		}else {
			fmt.Println("verifyfile is nil")
			return "验证失败"
		}
		if(node[nodeposition[headiter]] != nil){
			//fmt.Println("node[nodeposition[headiter]] is ", node[nodeposition[headiter]])
		}else {
			return "验证失败"
		}
		ret, _ := bitcompare(verifyfile, node[nodeposition[headiter]], readbitlen)
		if(ret){

			//fmt.Println("与本地文件相同节点：", nodeposition[headiter])
		}else {
			fmt.Println("验证失败节点:",nodeposition[headiter])
			return "节点不正确，验证不成功"
		}
	}
	fmt.Println("1.节点的head值与本地文件相同")


	//2，验证hash（id||previoushash||nonce)与head||tail是否一致

	var nodeiter int
	//var nodevalue []byte
	//var previousnode []byte
	for nodeiter = 0; nodeiter < len(nodeposition); nodeiter++{
		//fmt.Println("验证节点： ", nodeposition[nodeiter])
		nodevalue, ok := node [ nodeposition[nodeiter] ]
		if (ok) {
			//fmt.Println("nodevalue is ", nodevalue)
		} else {
			fmt.Println("不存在node:",nodeposition[nodeiter])
			var result = "节点不存在，验证不成功"
			return result
		}
		if(nodeposition[nodeiter] ==0){//如果是第一个叶子节点
			var trys string
			var noucevalue int64
			trys += identity
			//计算叶子节点中的随机数（后8个byte），转为10进制的int64
			noucevalue = calnoucevalue(nodevalue)
			//identity||nouce
			trys += strconv.FormatInt(noucevalue, 10)
			//计算hash
			calc_hash := GetSHA256HashCode([]byte(trys))

			var comparebyte []byte
			comparebyte, _ = hex.DecodeString(calc_hash)
			ret, _ := bitcompare(nodevalue, comparebyte, 32*8)
			if ret {
				//fmt.Println("nodevalue is ", nodevalue)
				//fmt.Println("comparebyte is ", comparebyte)
				//fmt.Println("验证成功节点 ", nodeposition[nodeiter])

			}else{
				fmt.Println("验证失败节点:",nodeposition[nodeiter])
				var result = "节点不正确，验证不成功"
				return result
			}
		}else{
			//fmt.Println("previousnode is ", nodeposition[nodeiter]-1)
			previousnode, ok := node [ nodeposition[nodeiter]-1 ]
			if (ok) {
				//fmt.Println("previousnode is ", nodeposition[nodeiter]-1)
				//fmt.Println("previousnodevalue is ", previousnode)
				var trys string
				var previoushash string
				var noucevalue int64
				var previousnodehead []byte
				previousnodehead = make([]byte,32)
				copy(previousnodehead,previousnode)
				//fmt.Println("previousnodehead is ", previousnodehead)
				trys += identity
				//previousenodevalue变为hash
				previoushash = hex.EncodeToString(previousnodehead)
				trys += previoushash
				//计算叶子节点中的随机数（后8个byte），转为10进制的int64
				noucevalue = calnoucevalue(nodevalue)
				//identity||previouse||nonce
				trys += strconv.FormatInt(noucevalue, 10)
				//计算hash
				calc_hash := GetSHA256HashCode([]byte(trys))

				var comparebyte []byte
				comparebyte, _ = hex.DecodeString(calc_hash)
				//fmt.Println("comparebyte is ", comparebyte)
				ret, _ := bitcompare(nodevalue, comparebyte, 32)
				if ret {
					//fmt.Println("nodevalue is ", nodevalue)
					//fmt.Println("comparebyte is ", comparebyte)
					//fmt.Println("验证成功节点 ", nodeposition[nodeiter])

				}else{
					fmt.Println("验证失败节点previousnode:",nodeposition[nodeiter])
					var result = "节点不正确，验证不成功"
					return result
				}

			} else {
				fmt.Println("不存在previousnode:",nodeposition[nodeiter])
				var result = "节点不存在，验证不成功"
				return result
			}
		}
	}
	fmt.Println("2.hash（id||previoushash||nonce)与head||tail一致")



	//3. 验证叶子节点到根节点的路径是否正确。
	//nodeposition是需要验证的叶子节点
	//默克尔树的每一层节点的个数是rownum[]
	var rownum []int64
	var nSize int64
	var allnodenum int64 = 0
	var key []byte = []byte(ch)
	for nSize = leafnodenum; nSize > 1; nSize = (nSize + 1) / 2 {
		allnodenum = nSize + allnodenum
		rownum = append(rownum, allnodenum)
	}
	//添加最上面一层根节点，个数为1
	rownum = append(rownum,allnodenum+1)
	fmt.Println("默克尔树的层数:",len(rownum))
	//fmt.Println("每一层最后一个节点的序号+1:",rownum)

	var nodenumiter int64 = 0
	for nodenumiter = 0; nodenumiter < int64(len(nodeposition)); nodenumiter++ {
		//从第二层即i=1开始计算节点的路径,i代表第几层
		var nodepath []int64
		nodepath = append(nodepath, nodeposition[nodenumiter])
		var i int
		var childnode int64
		var nodenumber int64 = nodeposition[nodenumiter]
		var nodevalue []byte
		for i=1; i<len(rownum);i++{
			//计算该层节点的子节点在该层是第几个节点
			//如果是第二层，则子节点为叶子节点
			if(i == 1){
				childnode = nodeposition[nodenumiter]
			}else{//如果不是第一层，则子节点是
				childnode = childnode/2
			}
			//计算该节点的值
			var verifynodevalue []byte
			if(i == 1){//如果子节点是叶子节点
				if Oddornot(childnode) {//如果子节点的序号是奇数
					leftnodevalue, ok := node[nodenumber-1]
					if (!ok) {
						return "节点不存在"
					}
					rightnodevalue, ok := node[nodenumber]
					if (!ok) {
						return "节点不存在"
					}
					//根据左右子节点计算该节点的值
					verifynodevalue = CalMerkleNodeValue(leftnodevalue, rightnodevalue, key)

				} else{//如果子节点的序号是偶数
					if(nodenumber == rownum[0]-1){//如果子节点是该层最后一个节点
						leftnodevalue, ok := node[nodenumber]
						if (!ok) {
							return "节点不存在"
						}
						rightnodevalue:= node[nodenumber]
						verifynodevalue = CalMerkleNodeValue(leftnodevalue, rightnodevalue, key)
					}else{
						leftnodevalue, ok := node[nodenumber]
						if (!ok) {
							return "节点不存在"
						}
						rightnodevalue, ok := node[nodenumber+1]
						if (!ok) {
							return "节点不存在"
						}
						verifynodevalue = CalMerkleNodeValue(leftnodevalue, rightnodevalue, key)
					}
				}
			}else{//如果子节点不是叶子节点，则需要用到之前计算的子节点的值nodevalue
				if Oddornot(childnode) {
					leftnodevalue, ok := node[nodenumber-1]
					if (!ok) {
						return "节点不存在"
					}
					rightnodevalue := nodevalue
					verifynodevalue = CalMerkleNodeValue(leftnodevalue, rightnodevalue, key)
				} else{
					if(nodenumber == rownum[i-1]-1){
						leftnodevalue := nodevalue;
						rightnodevalue := nodevalue
						verifynodevalue = CalMerkleNodeValue(leftnodevalue, rightnodevalue, key)
					}else{
						leftnodevalue := nodevalue;
						rightnodevalue, ok := node[nodenumber+1]
						if (!ok) {
							return "节点不存在"
						}
						verifynodevalue = CalMerkleNodeValue(leftnodevalue, rightnodevalue, key)
					}
				}

			}
			nodevalue = verifynodevalue
			if(i == len(rownum)-1) {
				//计算至根节点
				//fmt.Println("根节点:",node[rownum[i]-1])
				//fmt.Println("nodevalue",nodevalue)
				ret, _ := bitcompare(nodevalue, node[rownum[i]-1], 32*8)
				if (ret) {
				} else {
					return "验证失败，路径不对"
				}
			}
			//j代表该节点在该层是第几位
			var j int64
			j = childnode / 2
			//nodenumber是该节点的在默克尔树中的序号
			nodenumber = rownum[i-1]+j
			nodepath = append(nodepath, nodenumber)
		}
		//fmt.Println("该节点的路径:",nodepath)
	}
	fmt.Println("3.节点路径验证成功")

	elapsed := time.Since(t1)
	fmt.Println("验证所用时间=", elapsed)
	var result = "验证成功"
	return result
}

func CalMerkleNodeValue(leftnodevalue []byte,rightnodevalue []byte,key []byte) []byte{
	var nodevalue []byte
	prevhashes := append(leftnodevalue,rightnodevalue...)
	//计算hmac_sha256
	h := hmac.New(sha256.New, key)
	h.Write(prevhashes)
	nodevalue = h.Sum(nil)
	return nodevalue
}

func calnoucevalue(nodevalue []byte) int64 {
	var nouncestring string
	var nouncebyte []byte
	var i int
	for i=32;i<40;i++{
		nouncebyte = append(nouncebyte, nodevalue[i])
	}
	//fmt.Println("nouncebyte:",nouncebyte)
	nouncestring = hex.EncodeToString(nouncebyte)
	//fmt.Println("nouncestring:",nouncestring)
	s, err := strconv.ParseInt(nouncestring, 16, 64)
	if err != nil {
		panic(err)
	}
	//fmt.Println("nouncestring:",s)


	return s
}

func calcparentroutenodenum(routenSize int64, nodearray []int64) []int64 {
	var tmpint []int64
	for _, value := range nodearray {
		var parentnodenum int64 = value / 2
		tmpint = append(tmpint, parentnodenum)
	}
	return tmpint
}

//判断奇数偶数
func Oddornot(input int64) bool {
	if 1 == (input & 1) {
		return true
	} else {
		return false
	}
}

func Calcnodenumber(n int64) int64 {
	var m int64 = 0
	//n表示叶子节点的个数，m表示默克尔树节点的个数
	m = m + n
	for ; n > 1; {
		if Oddornot(n) {
			n = (n + 1) / 2
			m = m + n
		} else {
			n = n / 2
			m = m + n
		}
	}
	return m
}

//第一个参数是选择的最底层叶子节点序号，第二个参数是最底层叶子节点的个数，第三个参数是生成的证明文件路径，第四个参数是根据ch生成的证明缓存文件路径
func CalcRoute(m []int64, nodenum int64,
	evidencepath string, evidencecachpath string) map[int64]string {
	//给定叶子节点序号，返回叶子节点到跟的路径
	scene := make(map[int64]string)
	for _, data := range m {
		var number int64
		if data > nodenum {
			number := data % nodenum
			fmt.Println("remainder is ", number)
		} else {
			number = data
		}
		for ; number > 1; {
			if Oddornot(number) {
				//(number+1)/2

			} else {

			}
		}
		//scene[data] = "route"
	}
	return scene
}
