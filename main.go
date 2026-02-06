package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/mrvcoder/V2rayCollector/collector"

	"github.com/PuerkitoBio/goquery"
	"github.com/jszwec/csvutil"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

var (
	client       = &http.Client{}
	maxMessages  = 100
	configs      = map[string]string{
		"ss":     "",
		"vmess":  "",
		"trojan": "",
		"vless":  "",
		"mixed":  "",
	}
	ConfigFileIds = map[string]int32{
		"ss":     0,
		"vmess":  0,
		"trojan": 0,
		"vless":  0,
		"mixed":  0,
	}
	myregex = map[string]string{
		"ss":     `(?m)(...ss:|^ss:)\/\/.+?(%3A%40|#|$)`,
		"vmess":  `(?m)vmess:\/\/.+`,
		"trojan": `(?m)trojan:\/\/.+?(%3A%40|#|$)`,
		"vless":  `(?m)vless:\/\/.+?(%3A%40|#|$)`,
	}
	sort         = flag.Bool("sort", false, "sort from latest to oldest (default : false)")
	npvtFiles    = []NPVTFile{}
	npvtFileMap  = make(map[string]NPVTFile) // For deduplication by hash
	npvtCounter  = 0
)

type ChannelsType struct {
	URL             string `csv:"URL"`
	AllMessagesFlag bool   `csv:"AllMessagesFlag"`
}

type NPVTFile struct {
	URL         string
	FileName    string
	ChannelName string
	LocalPath   string
	Hash        string // SHA256 hash for deduplication
}

func main() {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	flag.Parse()

	// Clean up old NPVT files before starting
	gologger.Info().Msg("Cleaning up old NPVT files...")
	CleanupNPVTDirectory()

	// Create npvt directory if it doesn't exist
	if err := os.MkdirAll("npvt_files", 0755); err != nil {
		gologger.Fatal().Msg("Failed to create npvt_files directory: " + err.Error())
	}

	fileData, err := collector.ReadFileContent("channels.csv")
	var channels []ChannelsType
	if err = csvutil.Unmarshal([]byte(fileData), &channels); err != nil {
		gologger.Fatal().Msg("error: " + err.Error())
	}

	for _, channel := range channels {
		// Extract channel name from URL for labeling
		uParts := strings.Split(strings.TrimSuffix(channel.URL, "/"), "/")
		channelName := uParts[len(uParts)-1]

		channel.URL = collector.ChangeUrlToTelegramWebUrl(channel.URL)
		resp := HttpRequest(channel.URL)
		doc, err := goquery.NewDocumentFromReader(resp.Body)
		err = resp.Body.Close()

		if err != nil {
			gologger.Error().Msg(err.Error())
		}

		fmt.Printf("\n\n---------------------------------------\n")
		gologger.Info().Msg("Crawling " + channel.URL)
		CrawlForV2ray(doc, channel.URL, channel.AllMessagesFlag, channelName)
		gologger.Info().Msg("Crawled " + channel.URL + " ! ")
		fmt.Printf("---------------------------------------\n\n")
	}

	gologger.Info().Msg("Creating output files !")

	for proto, configcontent := range configs {
		lines := collector.RemoveDuplicate(configcontent)
		lines = AddConfigNames(lines, proto)
		
		linesArr := strings.Split(lines, "\n")
		if *sort {
			linesArr = collector.Reverse(linesArr)
		} else {
			// Maintain order or apply custom logic
		}
		
		finalOutput := strings.Join(linesArr, "\n")
		finalOutput = strings.TrimSpace(finalOutput)
		collector.WriteToFile(finalOutput, proto+"_iran.txt")
	}

	// Create NPVT subscription file
	if len(npvtFiles) > 0 {
		gologger.Info().Msg(fmt.Sprintf("Creating NPVT subscription file with %d unique files", len(npvtFiles)))
		CreateNPVTSubscription()
	} else {
		gologger.Info().Msg("No NPVT files found")
		// Create empty files to avoid git errors
		collector.WriteToFile("", "npvt_iran.txt")
		collector.WriteToFile("[]", "npvt_subscription.json")
	}

	gologger.Info().Msg("All Done :D")
}

func CleanupNPVTDirectory() {
	npvtDir := "npvt_files"
	
	// Check if directory exists
	if _, err := os.Stat(npvtDir); os.IsNotExist(err) {
		gologger.Info().Msg("NPVT directory doesn't exist yet, skipping cleanup")
		return
	}

	// Read all files in the directory
	files, err := os.ReadDir(npvtDir)
	if err != nil {
		gologger.Error().Msg("Failed to read NPVT directory: " + err.Error())
		return
	}

	// Delete all .npvt files
	deletedCount := 0
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(strings.ToLower(file.Name()), ".npvt") {
			filePath := filepath.Join(npvtDir, file.Name())
			if err := os.Remove(filePath); err != nil {
				gologger.Error().Msg(fmt.Sprintf("Failed to delete %s: %v", filePath, err))
			} else {
				deletedCount++
			}
		}
	}

	if deletedCount > 0 {
		gologger.Info().Msg(fmt.Sprintf("Deleted %d old NPVT files", deletedCount))
	} else {
		gologger.Info().Msg("No old NPVT files to delete")
	}
}

func AddConfigNames(config string, configtype string) string {
	lines := strings.Split(config, "\n")
	newConfigs := ""
	
	for _, line := range lines {
		if line == "" { continue }
		
		// Split our temporary storage format (config|channelName)
		parts := strings.Split(line, "|SEP|")
		extractedConfig := parts[0]
		channelName := "Unknown"
		if len(parts) > 1 {
			channelName = parts[1]
		}

		// Handle Vmess specifically (JSON based)
		if strings.HasPrefix(extractedConfig, "vmess://") {
			formatted := EditVmessPs(extractedConfig, configtype, channelName)
			if formatted != "" {
				newConfigs += formatted + "\n"
			}
		} else {
			// Handle SS, Vless, Trojan (URL fragment based)
			ConfigFileIds[configtype]++
			// Remove existing fragments to avoid double naming
			cleanConfig := strings.Split(extractedConfig, "#")[0]
			newConfigs += fmt.Sprintf("%s#%s-%d\n", cleanConfig, channelName, ConfigFileIds[configtype])
		}
	}
	return newConfigs
}

func CrawlForV2ray(doc *goquery.Document, channelLink string, HasAllMessagesFlag bool, channelName string) {
	messages := doc.Find(".tgme_widget_message_wrap").Length()
	link, exist := doc.Find(".tgme_widget_message_wrap .js-widget_message").Last().Attr("data-post")

	if messages < maxMessages && exist {
		number := strings.Split(link, "/")[1]
		doc = GetMessages(maxMessages, doc, number, channelLink)
	}

	// Look for .npvt file attachments
	doc.Find(".tgme_widget_message_document").Each(func(i int, s *goquery.Selection) {
		// Find document link
		docLink, exists := s.Find(".tgme_widget_message_document_title").Attr("href")
		if !exists {
			return
		}

		// Find document name
		docName := s.Find(".tgme_widget_message_document_title").Text()
		
		// Check if it's a .npvt file
		if strings.HasSuffix(strings.ToLower(docName), ".npvt") {
			gologger.Info().Msg(fmt.Sprintf("Found .npvt file: %s from %s", docName, channelName))
			
			// Download the file
			if err := DownloadNPVTFile(docLink, docName, channelName); err != nil {
				gologger.Error().Msg(fmt.Sprintf("Failed to download %s: %v", docName, err))
			}
		}
	})

	selector := "code,pre"
	if HasAllMessagesFlag {
		selector = ".tgme_widget_message_text"
	}

	doc.Find(selector).Each(func(j int, s *goquery.Selection) {
		messageText, _ := s.Html()
		str := strings.ReplaceAll(messageText, "<br/>", "\n")
		doc, _ := goquery.NewDocumentFromReader(strings.NewReader(str))
		messageText = doc.Text()
		
		lines := strings.Split(messageText, "\n")
		for _, data := range lines {
			extracted := ExtractConfig(data, []string{})
			if extracted == "" { continue }
			
			configsForLine := strings.Split(strings.TrimSpace(extracted), "\n")
			for _, conf := range configsForLine {
				if conf == "" { continue }
				
				proto := "mixed"
				if !HasAllMessagesFlag {
					for p, reg := range myregex {
						if regexp.MustCompile(reg).MatchString(conf) {
							proto = p
							break
						}
					}
				}
				// Store with temporary separator to process in AddConfigNames
				configs[proto] += strings.TrimSpace(conf) + "|SEP|" + channelName + "\n"
			}
		}
	})
}

func DownloadNPVTFile(url, fileName, channelName string) error {
	// Download the file to memory first
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	// Read file content
	fileContent, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Calculate hash for deduplication
	hash := fmt.Sprintf("%x", sha256.Sum256(fileContent))

	// Check if we already have this exact file
	if existingFile, exists := npvtFileMap[hash]; exists {
		gologger.Info().Msg(fmt.Sprintf("Skipping duplicate file: %s (same as %s)", fileName, existingFile.FileName))
		return nil
	}

	// Create a unique filename
	npvtCounter++
	safeChannelName := strings.ReplaceAll(channelName, "/", "_")
	safeFileName := fmt.Sprintf("%s_%d_%s", safeChannelName, npvtCounter, filepath.Base(fileName))
	localPath := filepath.Join("npvt_files", safeFileName)

	// Write the file
	if err := os.WriteFile(localPath, fileContent, 0644); err != nil {
		return err
	}

	// Store file info
	npvtFile := NPVTFile{
		URL:         url,
		FileName:    fileName,
		ChannelName: channelName,
		LocalPath:   localPath,
		Hash:        hash,
	}
	
	npvtFiles = append(npvtFiles, npvtFile)
	npvtFileMap[hash] = npvtFile

	gologger.Info().Msg(fmt.Sprintf("Downloaded: %s -> %s", fileName, localPath))
	return nil
}

func CreateNPVTSubscription() {
	var subscriptionData []map[string]string
	
	for _, npvt := range npvtFiles {
		
		subscriptionData = append(subscriptionData, map[string]string{
			"name":    fmt.Sprintf("%s - %s", npvt.ChannelName, npvt.FileName),
			"url":     fmt.Sprintf("https://raw.githubusercontent.com/Farid-Karimi/Config-Collector/main/%s", npvt.LocalPath),
			"channel": npvt.ChannelName,
			"file":    npvt.FileName,
		})
	}

	// Create JSON subscription
	jsonData, err := json.MarshalIndent(subscriptionData, "", "  ")
	if err != nil {
		gologger.Error().Msg("Failed to create NPVT subscription JSON: " + err.Error())
		return
	}

	collector.WriteToFile(string(jsonData), "npvt_subscription.json")

	// Also create a simple text list of URLs
	var urlList strings.Builder
	for _, npvt := range npvtFiles {
		urlList.WriteString(fmt.Sprintf("https://raw.githubusercontent.com/Farid-Karimi/Config-Collector/main/%s\n", npvt.LocalPath))
	}
	
	collector.WriteToFile(urlList.String(), "npvt_iran.txt")
	
	gologger.Info().Msg("NPVT subscription files created!")
}

func ExtractConfig(Txt string, Tempconfigs []string) string {
	for _, regexValue := range myregex {
		re := regexp.MustCompile(regexValue)
		matches := re.FindStringSubmatch(Txt)
		if len(matches) > 0 {
			config := matches[0]
			Tempconfigs = append(Tempconfigs, config)
			Txt = strings.ReplaceAll(Txt, config, "")
			return ExtractConfig(Txt, Tempconfigs)
		}
	}
	return strings.Join(Tempconfigs, "\n")
}

func EditVmessPs(config string, fileName string, channelName string) string {
	slice := strings.Split(config, "vmess://")
	if len(slice) < 2 { return "" }
	
	decodedBytes, err := base64.StdEncoding.DecodeString(slice[1])
	if err != nil { return "" }

	var data map[string]interface{}
	if err := json.Unmarshal(decodedBytes, &data); err != nil { return "" }

	ConfigFileIds[fileName]++
	data["ps"] = fmt.Sprintf("%s-%d", channelName, ConfigFileIds[fileName])

	jsonData, _ := json.Marshal(data)
	return "vmess://" + base64.StdEncoding.EncodeToString(jsonData)
}

func loadMore(link string) *goquery.Document {
	req, _ := http.NewRequest("GET", link, nil)
	resp, _ := client.Do(req)
	doc, _ := goquery.NewDocumentFromReader(resp.Body)
	return doc
}

func HttpRequest(url string) *http.Response {
	req, _ := http.NewRequest("GET", url, nil)
	resp, err := client.Do(req)
	if err != nil { gologger.Fatal().Msg(err.Error()) }
	return resp
}

func GetMessages(length int, doc *goquery.Document, number string, channel string) *goquery.Document {
	x := loadMore(channel + "?before=" + number)
	doc.Find("body").AppendSelection(x.Find("body").Children())
	newDoc := goquery.NewDocumentFromNode(doc.Selection.Nodes[0])
	if newDoc.Find(".js-widget_message_wrap").Length() > length {
		return newDoc
	}
	num, _ := strconv.Atoi(number)
	if n := num - 21; n > 0 {
		return GetMessages(length, newDoc, strconv.Itoa(n), channel)
	}
	return newDoc
}
