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

/*
Package cmd implements a simple command line interface using cobra
*/
package cmd

import (
	"os"
	"fmt"

	"github.com/praetorian-inc/gokart/analyzers"
	"github.com/praetorian-inc/gokart/util"
	"github.com/spf13/cobra"

)

var yml string
var gomodname string

func init() {
	goKartCmd.AddCommand(scanCmd)
	scanCmd.Flags().BoolP("sarif", "s", false, "outputs findings in SARIF form")
	scanCmd.Flags().BoolP("globalsTainted", "g", false, "marks global variables as dangerous")
	scanCmd.Flags().BoolP("verbose", "v", false, "outputs full trace of taint analysis")
	scanCmd.Flags().BoolP("debug", "d", false, "outputs debug logs")
	scanCmd.Flags().StringVarP(&yml, "input", "i", "", "input path to custom yml file")
	scanCmd.Flags().StringVarP(&gomodname, "remoteModule", "r", "", "Remote gomodule to scan")
	goKartCmd.MarkFlagRequired("scan")
}

var scanCmd = &cobra.Command{
	Use:   "scan [flags] [directory]",
	Short: "Scans a Go module directory",
	Long: `
Scans a Go module directory. To scan the current directory recursively, use gokart scan. To scan a specific directory, use gokart scan <directory>.`,
	Run: func(cmd *cobra.Command, args []string) {
		sarif, _ := cmd.Flags().GetBool("sarif")
		globals, _ := cmd.Flags().GetBool("globalsTainted")
		verbose, _ := cmd.Flags().GetBool("verbose")
		debug, _ := cmd.Flags().GetBool("debug")
		util.InitConfig(globals, sarif, verbose, debug, yml)
		
		//if a non-flag arg was passed in, it should be a filepath/modulepath
		if len(args) != 0 {
			//if we change to the module dir, then we want to Change our args to just the base (last section)
			isFile, err := util.PathIsFile(args[0])
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			//if the path is a file we set the current working dir to the directory where it's located
			// then we set the argument to ./filename
			if isFile{
				util.ChangeToFileDir(args[0])
				basepath := util.GetPathBase(args[0])
				args = append([]string{}, basepath)
			} else {
			//if path is dir, we change the working dir to it and set args to blank
				util.ChangeToModuleDir(args[0])
				args = []string{}
			}
		}

		// If gomodname flag is set to a non-empty value then clone the repo and scan it
		if len(gomodname) != 0 {
			moddirname, err := util.ParseModuleName(gomodname)
			if err != nil {
				fmt.Printf("CRASH! gokart couldn't parse your module.\n")
				os.Exit(1)
			}
			err = util.CloneModule(moddirname, "https://"+gomodname)
			if err != nil {
				fmt.Printf("CRASH! gokart failed to fetch remote module.\n")
				fmt.Print(err)
				os.Exit(1)
			}

			// when passing a module, we need to set the current directory to the newly cloned repo
			// and wipe out other arguments with a recurisve call to the new dir.
			err = os.Chdir(moddirname)
			if err != nil {
				fmt.Print(err)
				os.Exit(1)
			}

			args = append([]string{}, moddirname+"/...")
		}

		// recursively scan the current directory if no arguments are passed in
		if len(args) == 0 {
			args = append(args, "./...")
		}
		
		analyzers.Scan(args)
	},
}
