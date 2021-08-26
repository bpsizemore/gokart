// Copyright 2021 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package util

import (
	"github.com/go-git/go-git/v5"
	"fmt"
	"log"
	"strings"
	"os"
	"errors"
	"path/filepath"
)

// CloneModule clones a remote git repository over HTTP.
func CloneModule(dir string, url string) error {
	// fmt.Printf("git clone %s\n", url)
	fmt.Printf("Loading new racetrack: %s\n",url)

	_, err := git.PlainClone(dir, false, &git.CloneOptions{
		URL: url,
		//Progress: os.Stdout,
	})
	if err != nil {
		return err
	}

	return nil
}

//CleanupModule attempts to delete a directory.
func CleanupDir(dir string) error {
	
	err := os.RemoveAll(dir)
	if err != nil{
		return err
	}
	return nil
}

// ParseModuleName returns a directory from a module path 
func ParseModuleName(mn string) (string, error) {

	cur_dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	if len(mn) == 0 {
		return "", errors.New("No module name provided")
	}

	modSlice := strings.Split(mn, "/")
	if len(modSlice) <= 1 {
		return "", errors.New("Invalid remote module name!\nMust be in format of: github.com/praetorian/gokart")
	}

	dirName := cur_dir + "/" + modSlice[len(modSlice)-1:][0]
	return dirName, nil
}

func PathIsFile(path string) (bool, error) {
	//if not an absolute path, make it one
	if path[0] != '/' {
		basePath, err := os.Getwd()
		if err != nil {
			return false, err
		}
		path = filepath.Join(basePath, path)
	}

	file, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	switch mode := file.Mode(); {

	case mode.IsDir():
		return false, nil

	case mode.IsRegular():
		return true, nil
	default:
		err_str := fmt.Sprintf("File is of wrong mode: %s\n",mode)
		return false, errors.New(err_str)
	}
}

func GetPathBase(args ...string) string {
	path := filepath.Join(args[0])
	return filepath.Base(path)
}

func ChangeToModuleDir(args ...string) {
	fmt.Println(args)
	path := filepath.Join(args[0])
	fmt.Println(path)
	isFile, err := PathIsFile(path)
	if err != nil {
		//Something messed up with identifying the file type, maybe it doesn't exist
		log.Fatal(err)
	}
	fmt.Println(path)

	if !isFile {
		os.Chdir(path)
	}
}

func ChangeToFileDir(args ...string) {
	path := filepath.Join(args[0])
	isFile, err := PathIsFile(path)
	if err != nil {
		fmt.Printf("Something is wrong with your path. Exiting...")
		os.Exit(1)
	}
	if isFile {
		dir := filepath.Dir(path)
		os.Chdir(dir)
	}

}