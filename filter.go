package main

import (
	//"fmt"
	"log"

	//"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/httpx/runner"
)

func main() {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose) // increase the verbosity (optional)

	options := runner.Options{
		Methods:            "GET",
		InputFile:          "subfinder_output",
		FollowRedirects:    true,
		TechDetect:         true,
		VHost:              true,
		ProbeAllIPS:        true,
		Output:             "httpx_file",
		StatusCode:         true,
		RandomAgent:        true,
		ExtractTitle:       true,
		OutputIP:           true,
		OutputServerHeader: true,
	}

	if err := options.ValidateOptions(); err != nil {
		log.Fatal(err)
	}

	httpxRunner, err := runner.New(&options)
	if err != nil {
		log.Fatal(err)
	}
	defer httpxRunner.Close()

	httpxRunner.RunEnumeration()
}
