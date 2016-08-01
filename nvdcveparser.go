package main

import (
	"compress/gzip"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"gopkg.in/olivere/elastic.v3"

	"github.com/beevik/etree"
)

var (
	Client        = &http.Client{}
	fakeUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36"
)

type CVE struct {
	CveId              string            `json:"cve_id"`
	Product            []string          `json:"product"`
	DiscoveredDate     string            `json:"discovered_datetime"`
	DisclosureDate     string            `json:"disclosure_datetime"`
	ExploitPubDate     string            `json:"exploit_publish_datetime"`
	PublishedDate      string            `json:"published_datetime"`
	LastModifiedDate   string            `json:"last_modified_datetime"`
	CVSS               CVSS_Base_Metrics `json:"cvss"`
	SecurityProtection string            `json:"security_protection"`
	CweId              string            `json:"cwe_id"`
	References         []Reference       `json:"references"`
	Summary            string            `json:"summary"`
}

type CVSS_Base_Metrics struct {
	Score                float64 `json:"score"`
	AccessVector         string  `json:"access_vector"`
	AccessComplexity     string  `json:"access_complexity"`
	Authentication       string  `json:"authentication"`
	ConfidentiallyImpact string  `json:"confidentiality_impact"`
	IntegrityImpact      string  `json:"integrity_impact"`
	AvailabilityImpact   string  `json:"availability_impact"`
	Source               string  `json:"source"`
	GeneratedDate        string  `json:"generated_on_datetime"`
}

type Reference struct {
	ReferenceType string `json:"reference_type"`
	Source        string `json:"reference_source"`
	URL           string `json:"reference_url"`
}

func main() {
	xmlUrl := [17]string{"https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-Recent.xml.gz",
		"https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-Modified.xml.gz",
		"https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2016.xml.gz",
		"https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2015.xml.gz",
		"https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2014.xml.gz",
		"https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2013.xml.gz",
		"https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2012.xml.gz",
		"https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2011.xml.gz",
		"https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2010.xml.gz",
		"https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2009.xml.gz",
		"https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2008.xml.gz",
		"https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2007.xml.gz",
		"https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2006.xml.gz",
		"https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2005.xml.gz",
		"https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2004.xml.gz",
		"https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2003.xml.gz",
		"https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2002.xml.gz"}

	for _, url := range xmlUrl {
		localPath := strings.Replace(url, "https://static.nvd.nist.gov/feeds/xml/cve", "/tmp", -1)
		//Get CVE xml files
		err := getCveXmlFiles(url, localPath)
		if err != nil {
			log.Println("Get CVE xml file failed.", err)
		}

		//Process xml and bulk import CVE xml files
		filename := strings.TrimSuffix(localPath, ".gz")
		err = xmlBulkImport(filename)
		if err != nil {
			log.Println("CVE xml bulk import failed. error info:", err)
		}
	}
}

func getCveXmlFiles(fileUrl string, fileLocalPath string) (err error) {
	//Get xml file
	resp, err := fetchUrl(fileUrl)
	if err != nil {
		log.Println(err)
	}
	defer resp.Body.Close()

	//Save file to /tmp folder
	out, err := os.Create(fileLocalPath)
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		log.Println(err)
	}

	//Check if file exists and ungzip it
	if _, err := os.Stat(fileLocalPath); err != nil {
		log.Println("***", fileLocalPath, "does not exists. ***")
		return err
	} else {
		log.Println("***", fileLocalPath, "exists. ***")

		// if file exists then ungzip it.
		err = ungzip(fileLocalPath, "/tmp")
		if err != nil {
			log.Println("CVE file", fileLocalPath, "ungzip failed. \nerror info:", err)
		}
	}

	return err
}

func fetchUrl(url string) (resp *http.Response, err error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", fakeUserAgent)

	return Client.Do(req)
}

func ungzip(source, target string) error {
	gzipfile, err := os.Open(source)
	if err != nil {
		log.Println(err)
		return err
	}
	defer gzipfile.Close()

	reader, err := gzip.NewReader(gzipfile)
	if err != nil {
		log.Println(err)
		return err
	}
	defer reader.Close()

	newFileName := strings.TrimSuffix(source, ".gz")
	writer, err := os.Create(newFileName)
	if err != nil {
		log.Println(err)
		return err
	}
	defer writer.Close()

	if _, err = io.Copy(writer, reader); err == nil {
		log.Println("*** ugzip cve file", source, "success.")
	} else {
		log.Println(err)
	}

	return err
}

func xmlBulkImport(filePath string) (err error) {

	var cves []CVE

	//Check if file exists
	if _, err := os.Stat(filePath); err != nil {
		log.Println("***", filePath, "does not exists. ***")
		return err
	} else {
		log.Println("***", filePath, "exists. ***")
	}

	//Read file
	dat, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	//
	//Begin to process CVE xml file
	//
	doc := etree.NewDocument()
	err = doc.ReadFromBytes(dat)

	if err != nil {
		log.Println(err, string(dat))
	}

	root := doc.SelectElement("nvd")

	for _, entry := range root.SelectElements("entry") {
		c := CVE{}

		//entryId := entry.SelectAttr("id").Value
		//log.Println("entryId is:", entryId)

		//vuln:cve-id
		cveId := entry.SelectElement("vuln:cve-id")
		if cveId != nil {
			//log.Println("cve-id is:", cveId.Text())
			c.CveId = cveId.Text()
		} else {
			continue
		}

		//vuln:vulnerable-software-list
		vsl := entry.SelectElement("vuln:vulnerable-software-list")
		var prdlist []string
		if vsl != nil {
			products := vsl.SelectElements("vuln:product")
			for _, prodname := range products {
				//log.Println("vulnerable-software-list is:", prodname.Text())
				prdlist = append(prdlist, prodname.Text())
			}
		}

		c.Product = prdlist

		//<vuln:discovered-datetime>2005-06-02T00:00:00.000-04:00</vuln:discovered-datetime>
		discoveredDate := entry.SelectElement("vuln:discovered-datetime")
		if discoveredDate != nil {
			//log.Println("discovered-datetime:", discoveredDate.Text())
			c.DiscoveredDate = discoveredDate.Text()
		}

		//vuln:disclosure-datetime
		disclosureDate := entry.SelectElement("vuln:disclosure-datetime")
		if disclosureDate != nil {
			//log.Println("disclosure-datetime:", disclosureDate.Text())
			c.DisclosureDate = disclosureDate.Text()
		}

		//vuln:exploit-publish-datetime
		exploitpublishDate := entry.SelectElement("vuln:exploit-publish-datetime")
		if exploitpublishDate != nil {
			//log.Println("exploit-publish-datetime:", exploitpublishDate.Text())
			c.ExploitPubDate = exploitpublishDate.Text()
		}

		//vuln:published-datetime
		pubDate := entry.SelectElement("vuln:published-datetime")
		if pubDate != nil {
			//log.Println("pubDate is:", pubDate.Text())
			c.PublishedDate = pubDate.Text()
		}

		//vuln:last-modified-datetime
		lastModDate := entry.SelectElement("vuln:last-modified-datetime")
		if lastModDate != nil {
			//log.Println("last modified datetime is:", lastModDate.Text())
			c.LastModifiedDate = lastModDate.Text()
		}

		//<vuln:cvss>
		//<cvss:base_metrics>
		//<cvss:score>7.6</cvss:score>
		//<cvss:access-vector>NETWORK</cvss:access-vector>
		//<cvss:access-complexity>HIGH</cvss:access-complexity>
		//<cvss:authentication>NONE</cvss:authentication>
		//<cvss:confidentiality-impact>COMPLETE</cvss:confidentiality-impact>
		//<cvss:integrity-impact>COMPLETE</cvss:integrity-impact>
		//<cvss:availability-impact>COMPLETE</cvss:availability-impact>
		//<cvss:source>http://nvd.nist.gov</cvss:source>
		//<cvss:generated-on-datetime>2016-03-09T09:38:02.973-05:00</cvss:generated-on-datetime>
		//</cvss:base_metrics>
		//</vuln:cvss>
		cvss := entry.SelectElement("vuln:cvss")
		cvssobj := CVSS_Base_Metrics{}
		if cvss != nil {
			base_metrics := cvss.SelectElement("cvss:base_metrics")
			score := base_metrics.SelectElement("cvss:score")
			if score != nil {
				//log.Println("score is:", score.Text())
				if s, err := strconv.ParseFloat(score.Text(), 64); err == nil {
					cvssobj.Score = s
				}

			}
			access_vector := base_metrics.SelectElement("cvss:access-vector")
			if access_vector != nil {
				//log.Println("access_vector:", access_vector.Text())
				cvssobj.AccessVector = access_vector.Text()
			}
			access_complexity := base_metrics.SelectElement("cvss:access-complexity")
			if access_complexity != nil {
				//log.Println("access_complexity:", access_complexity.Text())
				cvssobj.AccessComplexity = access_complexity.Text()
			}
			authentication := base_metrics.SelectElement("cvss:authentication")
			if authentication != nil {
				//log.Println("authentication:", authentication.Text())
				cvssobj.Authentication = authentication.Text()
			}
			confidentiality_impact := base_metrics.SelectElement("cvss:confidentiality-impact")
			if confidentiality_impact != nil {
				//log.Println("confidentiality_impact:", confidentiality_impact.Text())
				cvssobj.ConfidentiallyImpact = confidentiality_impact.Text()
			}
			integrity_impact := base_metrics.SelectElement("cvss:integrity-impact")
			if integrity_impact != nil {
				//log.Println("integrity_impact:", integrity_impact.Text())
				cvssobj.IntegrityImpact = integrity_impact.Text()
			}
			availability_impact := base_metrics.SelectElement("cvss:availability-impact")
			if availability_impact != nil {
				//log.Println("availability_impact:", availability_impact.Text())
				cvssobj.AvailabilityImpact = availability_impact.Text()
			}
			cvss_source := base_metrics.SelectElement("cvss:source")
			if cvss_source != nil {
				//log.Println("cvss_source:", cvss_source.Text())
				cvssobj.Source = cvss_source.Text()
			}
			generated_on_datetime := base_metrics.SelectElement("cvss:generated-on-datetime")
			if generated_on_datetime != nil {
				//log.Println("generated_on_datetime:", generated_on_datetime.Text())
				cvssobj.GeneratedDate = generated_on_datetime.Text()
			}
		}

		c.CVSS = cvssobj

		//<vuln:security-protection>ALLOWS_ADMIN_ACCESS</vuln:security-protection>
		security_protection := entry.SelectElement("vuln:security-protection")
		if security_protection != nil {
			//log.Println("security_protection:", security_protection.Text())
			c.SecurityProtection = security_protection.Text()
		}

		//<vuln:cwe id="CWE-119"/>
		cweId := entry.SelectElement("vuln:cwe")
		if cweId != nil {
			cwevalue := cweId.SelectAttr("id").Value
			//log.Println("cwe value:", cwevalue)
			c.CweId = cwevalue
		}

		//<vuln:references xml:lang="en" reference_type="VENDOR_ADVISORY">
		//<vuln:source>MS</vuln:source>
		//<vuln:reference href="http://technet.microsoft.com/security/bulletin/MS16-001" xml:lang="en">MS16-001</vuln:reference>
		//</vuln:references>
		//<vuln:references xml:lang="en" reference_type="VENDOR_ADVISORY">
		//<vuln:source>MS</vuln:source>
		//<vuln:reference href="http://technet.microsoft.com/security/bulletin/MS16-003" xml:lang="en">MS16-003</vuln:reference>
		//</vuln:references>
		var refs = []Reference{}
		references := entry.SelectElements("vuln:references")
		if references != nil {
			r := Reference{}
			for _, ref := range references {
				ref_type := ref.SelectAttr("reference_type").Value
				//log.Println("ref_type:", ref_type)
				r.ReferenceType = ref_type

				ref_source := ref.SelectElement("vuln:source").Text()
				//log.Println("ref_source:", ref_source)
				r.Source = ref_source

				ref_url := ref.SelectElement("vuln:reference").SelectAttr("href").Value
				//log.Println("ref_url:", ref_url)
				r.URL = ref_url

				refs = append(refs, r)
			}

		}

		c.References = refs

		//<vuln:summary>The Microsoft (1) VBScript 5.7 and 5.8 and (2) JScript 5.7 and 5.8 engines, as used in Internet Explorer 8 through 11 and other products, allow remote attackers to execute arbitrary code via a crafted web site, aka "Scripting Engine Memory Corruption Vulnerability."</vuln:summary>
		summary := entry.SelectElement("vuln:summary")
		if summary != nil {
			//log.Println("summary is:", summary.Text())
			c.Summary = summary.Text()
		}

		cves = append(cves, c)

		//log.Println("")
		//log.Println("*******")
		//log.Println("")
	}

	elk := "http://localhost:9200"
	//setup elastic client for bulk update
	client, err := elastic.NewClient(
		elastic.SetSniff(false),
		elastic.SetURL(elk),
	)
	if err != nil {
		log.Println("Elasticsearch Server is dead.")
		panic(err)
	}

	//initialize bulk update service
	bulkUpdateRequest := client.Bulk()

	for _, v := range cves {

		updateRequest := elastic.NewBulkUpdateRequest().
			Index("nvdcve").
			Type("cve").
			Id(v.CveId).
			Doc(v).
			DocAsUpsert(true).
			RetryOnConflict(3)

		bulkUpdateRequest = bulkUpdateRequest.Add(updateRequest)
	}

	log.Println("")
	log.Println("Number of actions:", bulkUpdateRequest.NumberOfActions())
	log.Println("")

	//execute Bulk Update
	_, err = bulkUpdateRequest.Do()
	if err != nil {
		log.Println("Bulk Update to ELK failed.", err)
	}

	return err
}
