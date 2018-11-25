package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
)

type MyWriter struct {

}

func (writer MyWriter) Write(p []byte) (n int, err error) {
	// fmt.Printf("Write")
	// fmt.Printf(string(p))
	//return crypto.MD4.New().Write(p)

	return len(p), nil
}

type MyReader struct {
}

func (reader MyReader) Read(p []byte) (n int, err error) {
	// fmt.Printf("Read")

	// file, _ := os.OpenFile("/dev/random", os.O_RDONLY, 0400)
	file, _ := os.OpenFile("/etc/hosts", os.O_RDONLY, 0400)

	fmt.Println("Read start: %s", len(p))
	fmt.Printf("%v", p[0])
	nn, eerr := file.Read(p)
	fmt.Println("!!")
	fmt.Printf(string(p))
	fmt.Println("Read finish")
	return nn, eerr
	// bufio.NewReader(file)
	// scanner := bufio.NewScanner(file);
	// scanner.
	//random := os.NewFile("/dev/random")
	//return random.Read(p)
	//return len(p), nil
}

func main() {
	bug := []int{};
	fmt.Println("%s", len(bug))
	add(bug)
	fmt.Println("%s", len(bug))



	// writer := MyWriter{}
	// reader := MyReader{}
	(func() {
		//int, e := io.Copy(writer, reader)
		//fmt.Println(int)
		//fmt.Println(e)
	})()

	// d, _ := ioutil.ReadAll(reader);

	fmt.Println(os.Stdout.Name())
}

func add(arr []int)  {
	arr = append(arr, 2)
}

func ssh () {
	// subProcess := exec.Command("ssh", "-p", "2222", "-tt", "coredns@127.0.0.1")
	// subProcess := exec.Command("bash", "-c", "sleep 2 && echo \"ssss\"")
	/*subProcess := exec.Command("bash", "-c", "sleep 2 && echo \"ssss\" && ssh -p 2222 coredns@127.0.01")

	stdin, err := subProcess.StdinPipe()
	if err != nil {
		fmt.Println(err) //replace with logger, or anything you want
	}
	defer stdin.Close() // the doc says subProcess.Wait will close it, but I'm not sure, so I kept this line

	subProcess.Stdout = os.Stdout
	subProcess.Stderr = os.Stderr

	fmt.Println("START") //for debug
	if err = subProcess.Start(); err != nil { //Use start, not run
		fmt.Println("An error occured: ", err) //replace with logger, or anything you want
	}

	// io.WriteString(stdin, "4\n")
	subProcess.Wait()
	fmt.Println("END") //for debug
*/


	cmd := exec.Command("ssh", "-p", "2222", "-tt", "coredns@127.0.0.1")
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if nil != err {
		log.Fatalf("Error obtaining stdin: %s", err.Error())
	}
	stdout, err := cmd.StdoutPipe()
	if nil != err {
		log.Fatalf("Error obtaining stdout: %s", err.Error())
	}
	reader := bufio.NewReader(stdout)
	go func(reader io.Reader) {
		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			log.Printf("Reading from subprocess: %s", scanner.Text())
			stdin.Write([]byte("some sample text\n"))
		}
	}(reader)
	if err := cmd.Start(); nil != err {
		log.Fatalf("Error starting program: %s, %s", cmd.Path, err.Error())
	}
	cmd.Wait()
}