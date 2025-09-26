package main

import (
	"embed"
	"encoding/xml"
	"flag"
	"fmt"
	"html/template"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
)

func GenerateTableData(nmapFiles []string, serviceName string) [][]string {
	versionMap := make(map[string][]string)

	for _, filePath := range nmapFiles {
		fileData, err := os.ReadFile(filePath)
		if err != nil {
			fmt.Printf("Error reading file %s: %v\n", filePath, err)
			continue
		}

		var nmapRun Nmaprun
		err = xml.Unmarshal(fileData, &nmapRun)
		if err != nil {
			fmt.Printf("Failed to unmarshal xml data in %s\nError: %v\n", filePath, err)
			continue
		}

		for _, port := range nmapRun.Host.Ports.Port {
			if port.State.State == "filtered" {
				continue
			}
			if port.Service.Name == serviceName {
				var hostIP string
				if len(nmapRun.Host.Address) > 0 {
					hostIP = nmapRun.Host.Address[0].Addr
				}
				portID := port.Portid
				serviceVersion := fmt.Sprintf("%s %s", port.Service.Product, port.Service.Version)

				hostPort := hostIP + ":" + portID
				versionMap[serviceVersion] = append(versionMap[serviceVersion], hostPort)
			}
		}
	}

	var data [][]string
	for version, hosts := range versionMap {
		sort.Strings(hosts)
		hostsJoined := strings.Join(hosts, "<br>")
		data = append(data, []string{hostsJoined, serviceName, version})
	}

	// Sort the data slice by version
	sort.Slice(data, func(i, j int) bool {
		return data[i][2] < data[j][2]
	})

	return data
}

// FilePathWalkDir walks through the directory specified by dirPath and returns a slice of file paths
// that match the given file extension.
func FilePathWalkDir(dirPath, extension string) ([]string, error) {
	var files []string
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err // Return the error to stop the walk.
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), extension) {
			absPath, err := filepath.Abs(path)
			if err != nil {
				return err // Return the error to stop the walk.
			}
			files = append(files, absPath)
		}
		return nil
	})
	return files, err
}

// resolveAbsPath ...
func resolveAbsPath(path string) (string, error) {
	usr, err := user.Current()
	if err != nil {
		return path, err
	}

	dir := usr.HomeDir
	if path == "~" {
		path = dir
	} else if strings.HasPrefix(path, "~/") {
		path = filepath.Join(dir, path[2:])
	}

	path, err = filepath.Abs(path)
	if err != nil {
		return path, err
	}

	return path, nil
}

//go:embed template.html
var templateFS embed.FS

func main() {
	// Define command-line flags
	serviceName := flag.String("service", "ms-sql-s", "The service name to filter by")
	nmapDir := flag.String("nmap-dir", "", "The directory containing Nmap XML files")
	flag.Parse()

	// Check if nmap-dir is provided
	if *nmapDir == "" {
		log.Fatal("Please provide the Nmap directory using the -nmap-dir flag")
	}

	absNmapDir, err := resolveAbsPath(*nmapDir)
	if err != nil {
		log.Fatalf("invalid path: %s", err.Error())
	}

	nmapFiles, err := FilePathWalkDir(absNmapDir, ".xml")
	if err != nil {
		log.Fatalf("Error getting files\nError: %+v\n", err)
	}
	// ms-sql-s
	tableData := GenerateTableData(nmapFiles, *serviceName)

	tmpl, err := template.New("template.html").Funcs(template.FuncMap{
		"safe": func(s string) template.HTML {
			return template.HTML(s)
		},
	}).ParseFS(templateFS, "template.html")
	if err != nil {
		log.Fatalf("Error parsing template: %v", err)
	}

	outputFilename := fmt.Sprintf("%s.html", *serviceName)
	outputFile, err := os.Create(outputFilename)
	if err != nil {
		fmt.Println("Error creating output file:", err)
		return
	}
	defer outputFile.Close()

	err = tmpl.Execute(outputFile, tableData)
	if err != nil {
		fmt.Println("Error executing template:", err)
		return
	}

	fmt.Printf("HTML table written to %s\n", outputFilename)
}

type Nmaprun struct {
	XMLName          xml.Name `xml:"nmaprun"`
	Text             string   `xml:",chardata"`
	Scanner          string   `xml:"scanner,attr"`
	Args             string   `xml:"args,attr"`
	Start            string   `xml:"start,attr"`
	Startstr         string   `xml:"startstr,attr"`
	Version          string   `xml:"version,attr"`
	Xmloutputversion string   `xml:"xmloutputversion,attr"`
	Scaninfo         struct {
		Text        string `xml:",chardata"`
		Type        string `xml:"type,attr"`
		Protocol    string `xml:"protocol,attr"`
		Numservices string `xml:"numservices,attr"`
		Services    string `xml:"services,attr"`
	} `xml:"scaninfo"`
	Verbose struct {
		Text  string `xml:",chardata"`
		Level string `xml:"level,attr"`
	} `xml:"verbose"`
	Debugging struct {
		Text  string `xml:",chardata"`
		Level string `xml:"level,attr"`
	} `xml:"debugging"`
	Taskbegin []struct {
		Text string `xml:",chardata"`
		Task string `xml:"task,attr"`
		Time string `xml:"time,attr"`
	} `xml:"taskbegin"`
	Taskend []struct {
		Text      string `xml:",chardata"`
		Task      string `xml:"task,attr"`
		Time      string `xml:"time,attr"`
		Extrainfo string `xml:"extrainfo,attr"`
	} `xml:"taskend"`
	Hosthint struct {
		Text   string `xml:",chardata"`
		Status struct {
			Text      string `xml:",chardata"`
			State     string `xml:"state,attr"`
			Reason    string `xml:"reason,attr"`
			ReasonTtl string `xml:"reason_ttl,attr"`
		} `xml:"status"`
		Address []struct {
			Text     string `xml:",chardata"`
			Addr     string `xml:"addr,attr"`
			Addrtype string `xml:"addrtype,attr"`
			Vendor   string `xml:"vendor,attr"`
		} `xml:"address"`
		Hostnames string `xml:"hostnames"`
	} `xml:"hosthint"`
	Taskprogress []struct {
		Text      string `xml:",chardata"`
		Task      string `xml:"task,attr"`
		Time      string `xml:"time,attr"`
		Percent   string `xml:"percent,attr"`
		Remaining string `xml:"remaining,attr"`
		Etc       string `xml:"etc,attr"`
	} `xml:"taskprogress"`
	Host struct {
		Text      string `xml:",chardata"`
		Starttime string `xml:"starttime,attr"`
		Endtime   string `xml:"endtime,attr"`
		Status    struct {
			Text      string `xml:",chardata"`
			State     string `xml:"state,attr"`
			Reason    string `xml:"reason,attr"`
			ReasonTtl string `xml:"reason_ttl,attr"`
		} `xml:"status"`
		Address []struct {
			Text     string `xml:",chardata"`
			Addr     string `xml:"addr,attr"`
			Addrtype string `xml:"addrtype,attr"`
			Vendor   string `xml:"vendor,attr"`
		} `xml:"address"`
		Hostnames string `xml:"hostnames"`
		Ports     struct {
			Text string `xml:",chardata"`
			Port []struct {
				Text     string `xml:",chardata"`
				Protocol string `xml:"protocol,attr"`
				Portid   string `xml:"portid,attr"`
				State    struct {
					Text      string `xml:",chardata"`
					State     string `xml:"state,attr"`
					Reason    string `xml:"reason,attr"`
					ReasonTtl string `xml:"reason_ttl,attr"`
				} `xml:"state"`
				Service struct {
					Text      string `xml:",chardata"`
					Name      string `xml:"name,attr"`
					Product   string `xml:"product,attr"`
					Ostype    string `xml:"ostype,attr"`
					Method    string `xml:"method,attr"`
					Conf      string `xml:"conf,attr"`
					Version   string `xml:"version,attr"`
					Extrainfo string `xml:"extrainfo,attr"`
					Cpe       string `xml:"cpe"`
				} `xml:"service"`
				Script []struct {
					Text   string `xml:",chardata"`
					ID     string `xml:"id,attr"`
					Output string `xml:"output,attr"`
					Elem   []struct {
						Text string `xml:",chardata"`
						Key  string `xml:"key,attr"`
					} `xml:"elem"`
					Table []struct {
						Text string `xml:",chardata"`
						Key  string `xml:"key,attr"`
						Elem []struct {
							Text string `xml:",chardata"`
							Key  string `xml:"key,attr"`
						} `xml:"elem"`
						Table []struct {
							Text string `xml:",chardata"`
							Elem []struct {
								Text string `xml:",chardata"`
								Key  string `xml:"key,attr"`
							} `xml:"elem"`
						} `xml:"table"`
					} `xml:"table"`
				} `xml:"script"`
			} `xml:"port"`
		} `xml:"ports"`
		Hostscript struct {
			Text   string `xml:",chardata"`
			Script []struct {
				Text   string `xml:",chardata"`
				ID     string `xml:"id,attr"`
				Output string `xml:"output,attr"`
				Elem   []struct {
					Text string `xml:",chardata"`
					Key  string `xml:"key,attr"`
				} `xml:"elem"`
				Table struct {
					Text string `xml:",chardata"`
					Key  string `xml:"key,attr"`
					Elem string `xml:"elem"`
				} `xml:"table"`
			} `xml:"script"`
		} `xml:"hostscript"`
		Times struct {
			Text   string `xml:",chardata"`
			Srtt   string `xml:"srtt,attr"`
			Rttvar string `xml:"rttvar,attr"`
			To     string `xml:"to,attr"`
		} `xml:"times"`
	} `xml:"host"`
	Runstats struct {
		Text     string `xml:",chardata"`
		Finished struct {
			Text    string `xml:",chardata"`
			Time    string `xml:"time,attr"`
			Timestr string `xml:"timestr,attr"`
			Summary string `xml:"summary,attr"`
			Elapsed string `xml:"elapsed,attr"`
			Exit    string `xml:"exit,attr"`
		} `xml:"finished"`
		Hosts struct {
			Text  string `xml:",chardata"`
			Up    string `xml:"up,attr"`
			Down  string `xml:"down,attr"`
			Total string `xml:"total,attr"`
		} `xml:"hosts"`
	} `xml:"runstats"`
}
