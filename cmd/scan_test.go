package cmd

import (
	"testing"
	"strings"
	"strconv"
	"fmt"
	"os"
	"io/ioutil"

	"github.com/praetorian-inc/gokart/util"
	"github.com/spf13/cobra"
)

func TestScanFileCommand(t *testing.T) {
	// Tests the ability to scan an individual go file by specifying it on the command line	
	baseDir, err := os.Getwd()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	gokartUrl := "https://github.com/praetorian-inc/gokart.git"
	os.MkdirAll(baseDir + "/.tmp_test/start/", 0755)
	os.Chdir(baseDir + "/.tmp_test/start/")
	
	//pause stdout to keep messages out of tests
	stdout := PauseStdout()
	util.CloneModule("gokart",gokartUrl)
	ResumeStdout(stdout)
	
	testBaseDir := baseDir + "/.tmp_test/start/gokart/"
	os.Chdir(testBaseDir)


	var tests = []struct {
		args []string
		expect string
	}{
		{[]string{"scan", "test/testdata/vulnerablemodule/command_injection/command_injection.go"},"GoKart found 2 potentially vulnerable functions"},
		{[]string{"scan", "test/testdata/vulnerablemodule/command_injection/command_context_injection_safe.go"}, "GoKart found 0 potentially vulnerable functions"},
		{[]string{"scan", "test/testdata/vulnerablemodule/"}, "GoKart found 10 potentially vulnerable functions"},
		{[]string{"scan", "test/testdata/vulnerablemodule"}, "GoKart found 10 potentially vulnerable functions"},
		{[]string{"scan", "test/testdata/vulnerablemodule/path_traversal/"}, "GoKart found 7 potentially vulnerable functions"},
		{[]string{"scan", "test/testdata/vulnerablemodule/combined/"}, "GoKart found 6 potentially vulnerable functions"},
		{[]string{"scan", "test/testdata/vulnerablemodule/combined/serverTest.go"}, "GoKart found 6 potentially vulnerable functions"},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			
			//reset to base dir for each test
			os.Chdir(testBaseDir)
			if err != nil {
				t.Fatalf("Failed! %s",err)
			}

			// fetch last line of output from scan command
			output := ExecuteCommand(goKartCmd, tt.args)
			// fmt.Println(output)
			lastline := output[len(output)-2]
			if lastline != tt.expect {
				t.Fatalf("Failed! Expected: %s\nGot: %s\n",tt.expect,lastline,)
			} 
		})
	}
	// delete the temp testing directory
	util.CleanupDir(baseDir + "/.tmp_test")
	os.Chdir(baseDir)
}

func TestRemoteModScanCommand(t *testing.T) {
	// Tests the Scan command.
	curDir, err := os.Getwd()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	var tests = []struct {
		args []string
		expected_lastline string
		moduledir string
	}{
		{[]string{"scan"},"GoKart found 0 potentially vulnerable functions", ""},
		{[]string{"scan","-r", "github.com/Contrast-Security-OSS/go-test-bench"}, "GoKart found 8 potentially vulnerable functions", curDir+"/go-test-bench"},
		{[]string{"scan","-r", "github.com/praetorian-inc/gokart"}, "GoKart found 0 potentially vulnerable functions", curDir+"/gokart"},
		{[]string{"scan", "--help"}, "  -v, --verbose               outputs full trace of taint analysis", ""},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			
			os.Chdir(curDir)
			if err != nil {
				t.Fatalf("Failed! %s",err)
			}

			// fetch last line of output from scan command
			output := ExecuteCommand(goKartCmd, tt.args)
			lastline := output[len(output)-2]
			//if we tested with a remote module clean it up.
			if len(tt.moduledir) != 0 {
				err := util.CleanupDir(tt.moduledir)
				if err != nil {
					fmt.Print(err)
				}
			}
			if lastline != tt.expected_lastline {
				t.Fatalf("Failed! Expected: %s\nGot: %s\n",tt.expected_lastline,lastline,)
			} 
		})
	}
	os.Chdir(curDir)
}

func TestSpecifyDirScanCommand(t *testing.T) {
	// This test clones the gokart repo in a number of locations and then verifys that scanning from a variety
	// of paths works identically for all of them.

	baseDir, err := os.Getwd()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	gokartUrl := "https://github.com/praetorian-inc/gokart.git"
	os.MkdirAll(baseDir + "/.tmp_test/start/", 0755)
	os.Chdir(baseDir + "/.tmp_test/start/")
	
	//pause stdout to keep messages out of tests
	stdout := PauseStdout()
	util.CloneModule("gokart",gokartUrl)
	ResumeStdout(stdout)
	
	os.Chdir(baseDir + "/.tmp_test/start/gokart/")
	output := ExecuteCommand(goKartCmd, []string{"scan"})
	
	numFiles, _ := strconv.Atoi(strings.Split(output[len(output)-3], " ")[6])

	testBaseDir := baseDir + "/.tmp_test/start/"
	os.Chdir(testBaseDir)
	util.CleanupDir(baseDir + "/.tmp_test/start/gokart")

	var tests = []struct {
		args []string
		numFiles int
		dirPath string
	}{
		{[]string{"scan", "gokart/"},numFiles, "./gokart"},
		{[]string{"scan", "../gokart/"},numFiles, "../gokart"},
		{[]string{"scan", "../gokart"},numFiles, "../gokart"},
		{[]string{"scan", ".././././gokart/"},numFiles, "../gokart"},
		{[]string{"scan", "../1/2/3/4/5/gokart/"},numFiles, "../1/2/3/4/5/gokart"},
		{[]string{"scan", "./1/2/3/4/gokart/"},numFiles, "./1/2/3/4/gokart"},
		// {[]string{"scan", "test path to scan"},numFiles, "./path/to/clone/repo/to"},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			
			//reset to base dir for each test
			os.Chdir(testBaseDir)

			//pause stdout to keep messages out of tests
			stdout := PauseStdout()
			err := util.CloneModule(tt.dirPath, gokartUrl)
			ResumeStdout(stdout)
			if err != nil {
				fmt.Println(err)
				t.Fatalf("Failed to clone module.")
			}
			tout := ExecuteCommand(goKartCmd, tt.args)
			tfiles, _ := strconv.Atoi(strings.Split(tout[len(tout)-3], " ")[6])

			// Whenever running gokart - the number of files it is ran against varies slightly
			// from run to run. I'm not sure why, but this lets us know if we are in the same ballpark 
			if tfiles <= tt.numFiles-10 || tfiles >= tt.numFiles + 10{
				err = util.CleanupDir(tt.dirPath)
				t.Fatalf("Failed!\nExpected close to: %d files scanned\nGot %d files scanned",tt.numFiles,tfiles)
			}
			err = util.CleanupDir(tt.dirPath)
			// fmt.Printf("Passed: expect %d got %d\n",tt.numFiles,tfiles)

		})
	}

	// delete the temp testing directory
	util.CleanupDir(baseDir + "/.tmp_test")
	os.Chdir(baseDir)
}

func PauseStdout() *os.File {
	old := os.Stdout
	null, _ := os.Open(os.DevNull)
	os.Stdout = null
	return old
}

func ResumeStdout(stdout *os.File) {
	os.Stdout = stdout
}

func ExecuteCommand(cmd *cobra.Command,args []string) ([]string) {

	// change stdout to something we can read from to capture command out
	// Not sure if this could potentially cause issues if buffer gets too full
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	cmd.SetArgs(args)
	Execute()

	// reset stdout to normal stdout and read output from cmd
	w.Close()
	stdoutres, _ := ioutil.ReadAll(r)
	os.Stdout = old

	//get the last line of output for comparison with our tests
	stdoutresslice := strings.Split(strings.ReplaceAll(string(stdoutres), "\r\n", "\n"), "\n")
	return stdoutresslice


}